# CIHash

CIHash is a proof-carrying CI prototype. A trusted runner executes an approved verification profile for an exact committed tree, emits a signed DSSE/in-toto receipt, and lets a GitHub App decide whether to accept that proof or invoke fallback CI.

## Product boundary

The initial path is intentionally narrow: one repository, one profile, same-repository pull requests, exact head and base commits, and a pinned Linux environment. Prefer a small trustworthy vertical slice over broad GitHub Actions compatibility.

`docs/product-brief.md`, `docs/threat-model.md`, and `docs/attestation-v0.1.md` define the current product and security contracts. Keep them aligned with observable behavior when those contracts change.

## Security invariants

- Treat submitted repositories, commands, dependencies, and test workloads as untrusted.
- Never expose signing keys, GitHub App credentials, webhook secrets, policy administration, or receipt storage to the workload.
- Bind acceptance to the repository, head, base, tested tree, policy, workflow, environment, complete job set, nonce, signer, and expiry.
- Repository code cannot approve or weaken its own required verification policy.
- Missing, invalid, stale, ambiguous, or unsupported evidence fails closed and requires fallback CI. It must never produce a success check.
- Failed executions may produce signed diagnostic receipts, but only a complete successful receipt can authorize a green check.
- Use established DSSE and in-toto formats and standard cryptographic primitives. Do not invent signature schemes or ambiguous canonicalization rules.

The development runner may share a host with its child process for local proof mechanics. Never describe that arrangement as production isolation; enforcement requires a hardened container or ephemeral VM with the signer outside the workload boundary.

## Implementation shape

As implementation lands, keep responsibilities separated:

```text
cmd/cihash/              local CLI
cmd/cihashd/             verifier and control plane
internal/attestation/    receipt schema, DSSE signing, verification
internal/runner/         exact-checkout execution and result capture
internal/signing/        signer boundary and key identity
internal/githubapp/      webhook validation, check decisions, fallback
```

Prefer Go standard-library components until a dependency materially reduces security or maintenance risk. Keep the verifier deterministic and usable independently from the runner and GitHub integration.

## Development workflow

Once the Go module exists, use:

```bash
gofmt -w <changed-go-files>
go test ./...
go vet ./...
```

Exercise the actual proof round trip after behavioral changes: run an exact committed tree, sign the result, verify it, and evaluate the check decision. Also confirm that changing the head, base, policy, environment, expiry, signature, or required job set causes a specific rejection.

Tests should defend observable trust contracts and fail on plausible authorization mistakes. Keep unit tests offline and deterministic; isolate live GitHub App checks to an explicit sandbox integration path.

## Repository hygiene

- Do not commit private keys, App credentials, webhook secrets, generated receipts, or raw job logs.
- Keep policy examples non-secret and clearly distinguish committed examples from administrator-approved policy state.
- Avoid compatibility shims while the format is pre-release. Update every caller and the schema together.
- Preserve actionable rejection codes and messages; proof acceptance must be explainable to both developers and automation.
