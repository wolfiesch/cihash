# CIHash competitive boundary

## Product boundary

CIHash owns the decision that converts a trusted pre-push run into an immediate GitHub required check, including policy matching, rejection explanations, and fallback orchestration.

The product should reuse standard or existing execution and attestation components where they satisfy the trust contract.

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
