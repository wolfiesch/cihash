# CIHash GitHub App setup

## App permissions and events

Create a GitHub App with these repository permissions:

- Checks: read and write
- Contents: read
- Actions: read and write
- Pull requests: read
- Metadata: read

Installation tokens are narrowed to the configured pilot repository and inherit the permissions accepted for that installation. Keep the App itself limited to the list above; CIHash does not request a broader token permission set.

Subscribe the App webhook to:

- Pull request
- Workflow run

Use a randomly generated webhook secret with at least 32 bytes. Install the App only on pilot repositories during shadow validation.

The App private key, webhook secret, and receipt-signing key are separate credentials. The submitted workload receives none of them.

## Hosted configuration

`cihash serve` reads a non-secret JSON configuration:

```json
{
  "listen": "127.0.0.1:8080",
  "webhookPath": "/webhooks/github",
  "repository": "owner/project",
  "checkName": "cihash/verify",
  "policyFile": "./policy.json",
  "receiptPublicKeyFile": "./receipt-signing.pub.pem",
  "receiptStore": "./var/receipts",
  "stateDirectory": "./var/state",
  "mode": "shadow",
  "shadowWorkflow": "CI",
  "shadowJob": "tooling",
  "buildMode": "production",
  "fallbackWorkflow": "cihash-fallback.yml",
  "detailsUrl": "https://cihash.example/checks",
  "githubApiBaseUrl": "https://api.github.com"
}
```

Relative paths resolve from the configuration file's directory. Keep secrets out of this file. Provision `stateDirectory` before starting the service; run-grant durability treats that directory as an existing administrator-owned boundary.

Supply credentials through the service environment:

```text
CIHASH_GITHUB_CLIENT_ID
CIHASH_GITHUB_PRIVATE_KEY_PATH
CIHASH_GITHUB_WEBHOOK_SECRET
CIHASH_PRODUCER_TOKEN
```

GitHub recommends the App client ID as the JWT `iss` claim. CIHash signs RS256 JWTs with `iat` 60 seconds in the past and `exp` nine minutes in the future, then exchanges them for one-hour installation tokens scoped to the configured repository and the `checks:write` and `actions:write` permissions.

Validate configuration and credential parsing without opening a listener:

```bash
cihash serve --config ./hosted.json --check-config
```

Run the service:

```bash
cihash serve --config ./hosted.json
```

Expose only the configured webhook path through the deployment proxy. GitHub sends `X-Hub-Signature-256`; CIHash verifies the HMAC before parsing or recording the delivery.

## Run grant boundary

The v0.1 control-plane protocol exposes authenticated endpoints for one
server-authorized run:

- `POST /api/v1/runs` accepts an installation ID and pull-request number,
  resolves the current same-repository head, base, and GitHub merge-tree identity,
  persists a grant, and returns it;
- `POST /api/v1/runs/{run-id}/receipt` verifies the signed receipt and uploaded
  log against that exact grant before binding and storing the evidence.

The grant includes the approved command and structured immutable execution
environment, so the producer does not read verification authority from the
submitted tree. A distinct server nonce binds the resulting receipt to the
grant. The run ID and nonce remain proof bindings rather than credentials; both
endpoints require the separately configured producer bearer token.

Grant state moves only from `issued` to `submitted` to `consumed`. Initial
submission and consumption must both occur before expiry. Expired grants,
replacement receipt digests, and out-of-order transitions fail closed.
Repeating the same verified receipt submission or consumption is idempotent only
while the grant remains valid.

## Pull-request decision flow

For `opened`, `reopened`, `synchronize`, `ready_for_review`, and `edited` events:

1. read the current PR and its `merge_commit_sha` instead of trusting revision fields in the webhook body, fetch that GitHub test-merge commit, then require its two parents to equal the current base and head before accepting its tree;
2. reject fork PRs, which are outside the v0.1 trust boundary;
3. derive the expected proof identity from the exact current head and base SHAs plus the approved server-side policy;
4. load only evidence bound to an immutable server-issued run and matching submitted receipt digest;
5. verify the receipt against the grant's nonce, timing, architecture, policy, and the current GitHub merge tree;
6. atomically consume the valid run before publishing an App-owned `cihash/verify` success check;
7. publish `neutral` in shadow mode when proof reuse is rejected;
8. create a queued check and dispatch the trusted fallback workflow in enforcement mode.

Webhook delivery IDs are persisted. Completed or concurrent duplicate deliveries do not create another check.

### Evidence timing

Evaluation happens at supported pull-request events and, for verified
successful receipts, immediately at submission. `POST
/api/v1/runs/{run-id}/receipt` verifies and stores the evidence, then
re-evaluates the granted pull request: the service re-resolves the current
head, base, and merge tree through GitHub and acts only when they still equal
the granted revisions. Anything else is logged and left to the event-driven
path, which stays authoritative.

- In shadow mode, an accepted late proof publishes a new completed App check
  and records a shadow decision.
- In enforcement mode, an accepted late proof performs three separate ordered
  operations: it consumes the run through the store's locked monotonic
  lifecycle, updates this pull request's own pending queued check to
  `success`, and only after a successful update marks the dispatched fallback
  `superseded` so its later `workflow_run` completion is ignored. If the check
  update fails, the fallback state is untouched and the fallback remains
  authoritative. If the state transition fails after a successful update, the
  fallback later overwrites the check with its real conclusion, which errs
  closed. If the fallback already completed the check, the late proof changes
  nothing.
- Rejected and diagnostic receipts never publish a check and never dispatch
  fallback from the submission path.

Fallback state is indexed by repository, installation, pull request, and the
App check's external identity, so pull requests that share a head commit
cannot supersede each other's checks.

Because grant issuance resolves an existing pull request, the first evaluation
of a freshly pushed head still records `proof_missing` and, in enforcement
mode, dispatches fallback. The receipt-triggered path exists so evidence that
completes minutes later still concludes that check without waiting for the
fallback workflow. Superseding removes only the fallback's authority, not its
compute: the dispatched run finishes harmlessly.

### Shadow parity evidence

In shadow mode, `shadowWorkflow` and `shadowJob` select the ordinary Actions
job used for parity evidence. CIHash accepts only first-attempt `pull_request`
runs whose webhook identifies exactly one pull request with the recorded head
and base. It then fetches the selected job through the installation-scoped
GitHub API and binds that immutable run to every CIHash evaluation of the same
pull request, head, and base. A push, manual dispatch, rerun, different base, or
second conflicting run cannot replace the evidence. CIHash records the proof
decision, rejection code, ordinary job conclusion, proof verification latency,
App decision latency, ordinary job duration, service source revision, service
binary digest, build mode, policy timeout, and observation timestamps in the
administrator-owned state directory. Aggregate workflow conclusions are not
used as a substitute for the selected job.

## Trusted fallback contract

The fallback workflow must live on the protected base branch and declare these `workflow_dispatch` inputs:

- `cihash_fallback_id`
- `cihash_head_sha`
- `cihash_base_sha`
- `cihash_external_id`
- `cihash_policy_digest`

The committed `.github/workflows/cihash-fallback.yml` is the CIHash repository's reference implementation. It checks out the exact base SHA, fetches the exact head SHA, prepares their merge tree, and runs the same formatting, vet, and test gates as the repository's ordinary CI workflow. `actions/checkout` and `actions/setup-go` are pinned to release commits.

CIHash records the workflow run ID returned by GitHub's dispatch endpoint. A signed `workflow_run: completed` webhook can finish the queued check only when:

- its run ID matches the recorded dispatch;
- repository and App installation match;
- event is `workflow_dispatch`;
- workflow head branch equals the recorded base branch;
- workflow head SHA equals the recorded base SHA;
- the fallback authorization has not expired.

Every mismatch finishes fail-closed as `stale` or `failure`. The fallback workload never receives authority to update the App-owned check.

## Rollout

1. Install in a sandbox repository with `mode: shadow`.
2. Confirm accepted proofs and ordinary CI agree.
3. Confirm every mismatch produces a neutral explanation without affecting merges.
4. Switch to `mode: enforce` while leaving existing required CI intact.
5. Configure the ruleset to require branches to be up to date before merging. This prevents a success check attached to a head SHA from surviving a later base-branch change.
6. Exercise missing, expired, stale-base, failed, cancelled, and timed-out fallback cases.
7. Require `cihash/verify` from the CIHash App only after the shadow evidence has zero unexplained mismatches.
