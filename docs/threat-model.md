# CIHash threat model

## Security objective

A CIHash success check means a trusted signer observed every required job succeed for the exact repository, head, base, policy, workflow, and environment accepted by the repository administrator.

A signature proves who made a claim. Isolation and policy determine whether that claim deserves trust.

## Protected assets

- authority to create the required GitHub check;
- signing keys and key-revocation state;
- repository verification policies;
- receipt integrity and lookup indexes;
- job logs and output artifacts;
- GitHub App credentials and webhook secret.

## Trust boundaries

1. **Submitted repository:** attacker-controlled input. Code, scripts, configuration, dependencies, and tests may be malicious.
2. **Job workload:** untrusted execution. It must not access signing keys, App credentials, control-plane storage, or policy administration.
3. **Runner supervisor:** trusted to fetch the exact tree, enforce isolation, capture the result, and report complete job state.
4. **Signer:** trusted and separate from the workload. It signs only validated runner results tied to a server-issued nonce.
5. **Verifier:** trusted, deterministic, and fail-closed. It evaluates signatures and the repository's approved policy snapshot.
6. **GitHub App:** trusted to attach the verifier's decision to the exact head commit and to invoke fallback when required.

## Threats and required controls

| Threat | Required control |
|---|---|
| Workload signs a fabricated pass | Keep signing material outside the job sandbox; signer accepts only authenticated supervisor results. |
| Receipt replayed for different code | Bind repository, head, base, merge tree, policy, workflow, environment, nonce, and expiry into the signed predicate. |
| Repository weakens its own test command | Store or approve policy outside the submitted tree; bind the approved policy digest. |
| Base changes after verification | Bind the exact base SHA and reject when the pull request base differs. |
| Repository-local Git replacement metadata changes resolved objects | Disable Git replacement and process-level object/config overrides for every trusted Git command, then compare the signed tree to the merge-commit tree independently resolved through GitHub. |
| Required matrix job omitted | Bind the complete approved job set and require every job to succeed. |
| Mutable dependency or fixture changes | Pin or digest every accepted input; otherwise reject reuse and run fallback CI. |
| Another actor spoofs the status name | Require the check from the CIHash GitHub App as its source. |
| Forged GitHub webhook | Verify `X-Hub-Signature-256`, delivery freshness, and expected event/repository. |
| Signing key compromised | Support key IDs, revocation, rotation, short receipt expiry, and audit logs. |
| Stale or duplicated delivery | Use idempotency keys and a server-issued nonce; make check publication monotonic. |
| Repository requests a weaker run | Issue grants only from administrator-owned policy and server-resolved GitHub revisions; repository input supplies no command, environment, expiry, or nonce. |
| Grant ID or nonce leaks | Treat both as proof bindings rather than credentials; require a separately authenticated producer channel for issuance and submission. |
| Receipt races or replaces another receipt | Persist the grant before execution and bind the first verified receipt digest through a locked, monotonic lifecycle. |
| Logs altered after execution | Sign log and artifact digests; verify content before display or download. |
| Invalid proof accidentally authorizes merge | Invalid, missing, ambiguous, or unsupported evidence always enters fallback. |

## Development runner limitation

The trusted runner independently resolves the granted head and base, computes
their merge tree, and materializes only that exact tree without `.git`, refs,
hooks, remotes, or untracked host files. It runs the administrator-approved
command in the policy-pinned Linux container with no network, a read-only root,
dropped capabilities, no Docker socket, bounded resources, and only the
metadata-free tree mounted read-only. The signing key is loaded only after the
workload exits.

This development arrangement still shares the host kernel and Docker daemon
with the supervisor. Production enforcement requires an ephemeral VM or
hardened container host with the signing service outside the workload host
boundary.

## Unsupported trust claims

CIHash does not claim that passing tests make code secure, that a hash establishes trustworthy execution, or that signatures compensate for a compromised signer. It proves only the execution claim described by the accepted policy and receipt.
