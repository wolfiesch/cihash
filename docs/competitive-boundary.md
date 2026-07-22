# CIHash competitive boundary

## Product boundary

CIHash owns the decision that converts a trusted pre-push run into an immediate GitHub required check, including policy matching, rejection explanations, and fallback orchestration.

The product should reuse standard or existing execution and attestation components where they satisfy the trust contract.

The decisive adoption constraint is ownership of the execution moment. Only a
system that already runs the agent's final verification can turn that run into
evidence at zero marginal compute; everyone else re-executes the workload on
trusted infrastructure and competes with ordinary CI on cost. CIHash therefore
integrates into agent execution platforms rather than operating a competing
runner mesh.

## Adjacent systems

| System | Existing strength | CIHash boundary |
|---|---|---|
| CosaCI | Distributed attested runners, quorum, sandboxing, signed bundles, Merkle log, GitHub payload contracts | Evaluate its execution and attestation components; focus CIHash on single-run agent UX, live GitHub App publication, policy matching, and fallback. |
| Occasio | Signed behavioral evidence for agent activity and GitHub checks | CIHash proves required test execution and reuses that result to authorize a merge check. |
| GitHub artifact attestations | Sigstore-backed artifact provenance rooted in GitHub Actions identity | CIHash accepts evidence produced before push by a separately trusted runner. |
| Bazel, Nx, and Turborepo caches | Reuse content-addressed build and task outputs | CIHash produces portable merge authorization independent of a specific build graph. |
| Managed runner vendors | Faster or cheaper execution of CI jobs | CIHash removes equivalent post-push execution when a valid proof already exists. |
| CI evidence bundles | Compliance and audit artifacts for completed runs | CIHash makes an online fail-closed authorization decision for an exact pull-request state. |

## Build-versus-integrate gate

Before implementing a production runner mesh, test whether CosaCI can provide:

1. one approved job submission without requiring a quorum deployment;
2. a receipt containing CIHash's required head, base, policy, workflow, environment, and log bindings;
3. verifier behavior that can be embedded behind the CIHash acceptance API;
4. workload isolation that keeps CIHash signing and GitHub credentials out of reach;
5. stable programmatic interfaces suitable for a hosted product.

Use it when those conditions hold without importing unnecessary distributed-system complexity. Otherwise retain standard DSSE/in-toto receipt compatibility and implement the smallest single-run trusted executor.

## Durable differentiation

- agent-native pre-push invocation;
- exact explanation for every accepted or rejected proof;
- one App-owned required check across proof and fallback paths;
- measured proof eligibility and avoided critical-path latency;
- open receipt verification;
- managed and customer-controlled trusted runners under one policy model.

## Executable product-research workbench

CIHash keeps product experiments behind `cihash lab` so protocol questions are
answered with executable, adversarial scenarios before they affect the hosted
required check:

- `trust-quorum` proves distinct trusted Ed25519 keys can enforce a threshold
  over one exact receipt while duplicate signatures, spoofed key IDs, stale
  bases, tampering, and ordinary claim mismatches still fail closed;
- `applicability` maps exact-commit, moving-base, and merge-group reuse against
  immutable tree identities;
- `confirmer` proves two receipts with different clocks and nonces can be
  compared honestly through a 2-of-2 agreement bound to approved receipt keys,
  domain names, and both canonical evidence-envelope digests;
- `tree-isolation` materializes a metadata-free Git tree and verifies every
  tracked path, blob identity, byte size, and executable mode against
  `git ls-tree`; a trusted attribute override prevents `git archive` export,
  filter, encoding, and line-ending rules from changing or omitting blobs. It
  rejects commit IDs, `.git` paths, escaping symlinks, resource limit
  violations, gitlinks, and any remaining archive mismatch.

These experiments establish representational and source-materialization
feasibility, not hosted authorization, workload isolation, or market demand.
The tree-only source is connected to the runner; repositories that need
submodules deliberately fall back.
Hosted authorization still uses strict commit identity until the merge-queue sandbox
proves that every execution input remains tree-equivalent. The remaining
product questions are independent trust-domain execution, evidence lifecycle,
producer conformance, and measurable avoided CI latency.
