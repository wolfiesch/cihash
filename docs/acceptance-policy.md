# CIHash acceptance policy

## Policy ownership

The repository administrator approves a policy snapshot through the CIHash control plane. Submitted code may reference a profile, but it cannot approve a new command, environment, required-job set, signer, or expiry window.

The v0.1 local policy is JSON:

```json
{
  "version": "0.1",
  "repository": "github.com/acme/project",
  "profile": "verify",
  "command": ["go", "test", "./..."],
  "environment": {
    "image": "registry.example/cihash/go@sha256:<digest>",
    "platform": "linux/amd64",
    "network": "none",
    "memory": "8g",
    "cpus": "6",
    "pidsLimit": 1024,
    "maxOutputBytes": 16777216
  },
  "maxAgeSeconds": 3600,
  "timeoutSeconds": 900
}
```

The policy digest is SHA-256 over its canonical JSON representation. The
workflow digest separately commits to the profile and command. The environment
digest commits to canonical JSON for the pinned image, Linux platform, disabled
network, resource limits, and output bound. Every environment field is explicit;
the producer cannot override one at execution time.

`maxAgeSeconds` is limited to 24 hours. `timeoutSeconds` is limited to two hours.
The trusted runner enforces the timeout and signs only a bounded execution log.

## Decision order

The verifier evaluates in this order and stops at the first rejection:

1. receipt exists for the expected lookup identity;
2. evidence is immutably bound to a submitted, unexpired server-issued run;
3. submitted receipt digest matches the stored evidence;
4. signer key is trusted and signature is valid;
5. subject and predicate are internally consistent;
6. repository, head, base, GitHub merge tree, profile, policy, workflow, environment, architecture, and nonce match;
7. issuance and expiry are valid for the run grant;
8. required jobs are complete and unique;
9. every job and the overall receipt succeeded;
10. run consumption succeeds before a success check is published.

## Stable rejection codes

- `proof_missing`
- `malformed_receipt`
- `unsupported_version`
- `untrusted_signer`
- `invalid_signature`
- `subject_mismatch`
- `repository_mismatch`
- `head_mismatch`
- `base_mismatch`
- `tree_mismatch`
- `profile_mismatch`
- `policy_mismatch`
- `workflow_mismatch`
- `environment_mismatch`
- `architecture_mismatch`
- `not_yet_valid`
- `expired`
- `issued_at_mismatch`
- `expiry_mismatch`
- `nonce_invalid`
- `run_unbound`
- `run_unsubmitted`
- `run_state_invalid`
- `receipt_digest_mismatch`
- `job_set_mismatch`
- `job_failed`
- `proof_failed`

Rejection messages must name the mismatched category without exposing secrets or signed log contents.

## GitHub check behavior

In shadow mode:

- accepted proof: completed `success`;
- rejected or missing proof: completed `neutral`, with the rejection reason;
- ordinary CI remains authoritative.

In enforcement mode:

- accepted proof: completed `success`;
- rejected or missing proof: `queued` with fallback required;
- the CIHash App dispatches or observes the approved fallback workflow for the same head and policy;
- only the CIHash App publishes the final required `cihash/verify` conclusion.

No unsupported state is converted to success.

## Experimental GitHub-state applicability

`cihash lab applicability` separates two proof-reuse policies without changing
the hosted decision path:

- `strict_commits` requires the repository, pull-request or merge-group context,
  head, base, merge tree, policy, workflow, and environment to match exactly;
- `merge_tree` explores reuse after a base or context change only when the
  repository, tested tree, policy, workflow, and environment remain exact.

`merge_tree` is not safe for the current runner. The workload runs inside a Git
clone and can observe commit, base, and merge metadata, so equal tree hashes do
not establish equivalent execution inputs. A future tree-equivalent policy
requires an administrator-approved tree-only execution mode that excludes
repository metadata from the workload. Until that boundary exists and is
measured, moved bases and merge-group changes continue to fail closed.
