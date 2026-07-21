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
  "environment": "oci://registry.example/cihash/go@sha256:<digest>",
  "maxAgeSeconds": 3600,
  "timeoutSeconds": 900
}
```

The policy digest is SHA-256 over its canonical JSON representation. The workflow digest separately commits to the profile and command. The environment digest commits to the immutable environment identity.

`maxAgeSeconds` is limited to 24 hours. `timeoutSeconds` is limited to two hours. The local runner enforces the timeout and records a signed failure when the command exceeds it.

## Decision order

The verifier evaluates in this order and stops at the first rejection:

1. receipt exists for the expected lookup identity;
2. envelope and statement decode under supported versions;
3. signer key is trusted and signature is valid;
4. subject and predicate are internally consistent;
5. repository, head, base, profile, policy, workflow, and environment match;
6. issuance and expiry are valid;
7. required jobs are complete and unique;
8. every job and the overall receipt succeeded.

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
- `profile_mismatch`
- `policy_mismatch`
- `workflow_mismatch`
- `environment_mismatch`
- `not_yet_valid`
- `expired`
- `nonce_invalid`
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
