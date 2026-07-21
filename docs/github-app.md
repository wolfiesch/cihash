# CIHash GitHub App setup

## App permissions and events

Create a GitHub App with these repository permissions:

- Checks: read and write
- Actions: read and write
- Pull requests: read
- Metadata: read

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
  "policyFile": "./policy.json",
  "receiptPublicKeyFile": "./receipt-signing.pub.pem",
  "receiptStore": "./var/receipts",
  "stateDirectory": "./var/state",
  "mode": "shadow",
  "fallbackWorkflow": "cihash-fallback.yml",
  "detailsUrl": "https://cihash.example/checks",
  "githubApiBaseUrl": "https://api.github.com"
}
```

Relative paths resolve from the configuration file's directory. Keep secrets out of this file.

Supply credentials through the service environment:

```text
CIHASH_GITHUB_CLIENT_ID
CIHASH_GITHUB_PRIVATE_KEY_PATH
CIHASH_GITHUB_WEBHOOK_SECRET
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

## Pull-request decision flow

For `opened`, `reopened`, `synchronize`, and `ready_for_review` events:

1. read the current PR from GitHub instead of trusting revision fields in the webhook body;
2. reject fork PRs, which are outside the v0.1 trust boundary;
3. derive the expected proof identity from the exact current head and base SHAs plus the approved server-side policy;
4. evaluate the local receipt store using the trusted receipt public key;
5. create an App-owned `cihash/verify` check on the PR head;
6. finish immediately when the exact proof is accepted;
7. publish `neutral` in shadow mode when proof reuse is rejected;
8. create a queued check and dispatch the trusted fallback workflow in enforcement mode.

Webhook delivery IDs are persisted. Completed or concurrent duplicate deliveries do not create another check.

## Trusted fallback contract

The fallback workflow must live on the protected base branch and declare these `workflow_dispatch` inputs:

- `cihash_fallback_id`
- `cihash_head_sha`
- `cihash_base_sha`
- `cihash_external_id`
- `cihash_policy_digest`

The committed `.github/workflows/cihash-fallback.yml` is the CIHash repository's reference implementation. It checks out the exact base SHA, fetches the exact head SHA, prepares their merge tree, and runs the repository verification command. `actions/checkout` is pinned to the v5.0.0 release commit.

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
