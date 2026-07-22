# High-leverage experiment milestones

This document records what CIHash has demonstrated, what remains a prototype, and which result should change the roadmap. A passing lab experiment is evidence for one contract only; it is not evidence of production isolation, market demand, or economic viability.

## Current status

| Priority | Experiment | Status | What the result establishes | Remaining gate |
|---|---|---|---|---|
| 1 | Live enforcement fallback | Passed in a private GitHub sandbox | One App-owned check accepted a matching off-host-signed proof; missing and stale proofs queued the fallback workflow; fallback completion updated the same check to success. | Repeat under production-grade workload isolation and observe real users. |
| 2 | Key lifecycle and crash recovery | Partial pass | Planned key windows accept receipts by issuance time; revoked, unknown, duplicate, and out-of-window keys fail closed. Issued, submitted, consumed, fallback-dispatched, and fallback-completed state survives process restart; corrupt state fails closed. | Exercise live rotation, revocation, crash, restore, and operator recovery against a deployed verifier. |
| 3 | Complete policy-owned job set | Evaluator prototype passed | A receipt can bind distinct named jobs to distinct argv commands. Missing, duplicate, unapproved, changed-command, and failed jobs receive stable rejection codes. | Extend the policy and runner from one command to independently scheduled jobs with resource limits and separate logs. |
| 4 | External producer conformance | Contract spike passed; ecosystem fit unproven | CIHash now has a strict normalized unsigned-result conformance check. Complete successful and failed diagnostic results conform; missing tree, nonce, job, or exact command fail closed. | No surveyed adjacent artifact conforms without added capture fields. Maintainer willingness has not been tested. |
| 5 | Economic pilot | Not run | Nothing yet establishes avoided critical-path latency, developer demand, or favorable unit economics. | Run shadow pilots on repositories with repeated deterministic CI and collect eligible-proof rate, p50/p95 saved latency, compute avoided, fallback rate, and operating cost. |
| 6 | Tree-equivalent merge-queue reuse | Local sandbox passed | A metadata-only base advance produced a new base and merge-group commit with the same merge tree. Tree-only materialization hid Git metadata, tree mode accepted the equivalent merge group, and content or policy changes were rejected. | Exercise a real GitHub merge queue and keep this mode disabled until the hosted workload consumes only the tree archive under an administrator-approved policy. |

## Experiment evidence

### Live enforcement fallback

Observed in the private `wolfiesch/cihash-enforce-sandbox` repository:

- missing proof created a queued CIHash check and dispatched the fallback workflow;
- the completed fallback workflow changed that same check to `success`;
- a moved base rejected the stale proof and dispatched fallback;
- a fresh proof for the authoritative head, base, and merge tree was signed on a separate host and accepted;
- the workload container had no signing key, producer token, Docker socket, writable repository root, network access, or Linux capabilities.

This establishes the end-to-end decision path. The prototype still used a long-lived container host and operator-managed services; it does not establish hardened production isolation or operability.

### Key lifecycle and crash recovery

Implemented contracts:

- `internal/acceptance/keyring.go` selects trusted keys by receipt issuance time and fails closed on revocation or ambiguous windows;
- `internal/rungrant/store.go` persists lifecycle transitions atomically;
- `internal/hosted/state.go` persists fallback dispatch and completion, including workflow-run recovery after process restart;
- invalid or corrupt persisted state returns an error rather than authorizing work.

The tests simulate process reconstruction from disk. They do not yet simulate a deployed host failure, backup restore, concurrent operator rotation, or compromised-key incident.

### Complete job-set contract

`cihash lab job-set` exercises a two-job contract with separate commands:

```text
unit -> go test ./...
lint -> go vet ./...
```

The verifier now consumes `[]verifier.ExpectedJob` rather than one shared command plus a list of names. The current policy and runner still emit one job, so this result supports the receipt and verifier design while leaving scheduling as a separate implementation decision.

### Producer conformance

The normalized contract is `attestation.TestResult` checked against a server-issued `rungrant.Grant` by `internal/conformance`. The check is deliberately unsigned and cannot authorize GitHub; a trusted signer and normal receipt verification remain mandatory.

Surveyed public artifacts at pinned revisions:

| Producer | Useful native evidence | Blocking gaps for CIHash |
|---|---|---|
| Agent CI `0.17.1` | repository, head SHA, named job results, run bounds, conclusion, log paths | base and executed tree, policy/environment identities, architecture, exact argv and numeric exits, nonce/expiry, signature |
| BootProof `0.4.1` | commit and dirty flag, architecture, step commands/exits/timestamps, local Ed25519 signature | base, dirty-tree content identity, policy/workflow, complete CI job set, log digests, nonce/expiry, CIHash-trusted signer identity |
| CosaCI `0.5.0` | signed commit/result/environment hash, pipeline hash, quorum bundle, captured-output hashes | base, exposed executed tree, distinct policy identity, architecture, recoverable named jobs/exits/timestamps, signed log binding, nonce/expiry |
| Occasio `0.12.1` | head, policy hash, audit-chain timestamps/exits, Sigstore DSSE identity | repository/base, full tree identity, workflow/environment/architecture, declared jobs and argv, log digests, expiry, overall CI conclusion |

No artifact can be safely post-processed into a complete CIHash result because several missing values describe facts that must be captured during execution. CosaCI is the nearest execution-and-attestation substrate; Agent CI is the nearest local developer workflow. BootProof and Occasio provide reusable evidence patterns but target different proof subjects.

No maintainer outreach occurred in this experiment. Repository licenses and machine-readable CLI or bundle surfaces make adapters technically plausible, except Agent CI's FSL terms require review before commercial or potentially competing use.

### Tree-equivalent merge-queue reuse

`cihash lab tree-reuse` creates real Git objects locally:

1. a pull-request head over an initial base;
2. a metadata-only base commit with the same base tree;
3. a synthetic merge-group commit whose merge tree equals the original tested merge tree;
4. a content-changing base commit whose merge tree differs.

Strict commit mode rejects the new merge-group context. Lab-only merge-tree mode accepts the equal tree as `tree_equivalent`, then rejects the changed tree and changed policy. `treesource.Materialize` supplies only the tested tree and confirms `.git` metadata is absent.

## Decisions from the current evidence

1. Keep strict head/base/tree matching as the hosted default.
2. Keep merge-tree reuse lab-only until real merge-queue evidence and production tree-only isolation exist.
3. Preserve per-job commands in the verifier; do not treat a wrapper script as the long-term job-set model.
4. Use the normalized conformance command for partner discussions, but do not build four adapters speculatively.
5. Prioritize the economic pilot next. Technical feasibility now exceeds evidence of demand and saved developer time.

## Reproduction

```bash
go run ./cmd/cihash lab job-set
go run ./cmd/cihash lab tree-reuse
go run ./cmd/cihash lab producer-conformance
go test ./...
go vet ./...
```

To check an external normalized producer result against its grant:

```bash
go run ./cmd/cihash lab producer-conformance \
  --grant ./grant.json \
  --result ./result.json \
  --now 2026-07-21T12:00:04Z
```

`signingEligible: true` means the producer result is complete enough to send to a trusted signer. `resultSucceeded: true` distinguishes a successful result from signable diagnostic failure evidence. Neither field authorizes a green check; authorization still requires a trusted signature and the normal receipt-verification path.
