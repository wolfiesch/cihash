# CIHash product brief

## Thesis

Coding agents already run verification while producing a change. CIHash turns a trusted run for an exact committed tree into signed evidence that a GitHub App can evaluate without repeating equivalent work.

## Product promise

> Test once in an isolated, policy-approved environment. Reuse the signed result for the exact code, base, workflow, and environment.

CIHash is the gatekeeper for a required check. It accepts an exact proof immediately or routes the change to normal CI when any input differs.

## Initial customer

The first customer is a private software team with:

- frequent agent-generated pushes;
- deterministic Linux verification;
- material pull-request critical-path latency;
- verification already run before push;
- willingness to install a GitHub App that owns a required check.

## First supported case

- one repository and one verification profile;
- same-repository pull-request branches;
- an exact head commit and current base commit;
- a pinned Linux execution environment;
- commands approved outside the submitted workload;
- no privileged secrets in the workload;
- fail-closed proof validation with normal CI fallback.

Forks, merge queues, arbitrary GitHub Actions interpretation, macOS, mutable external fixtures, and secret-bearing jobs follow only after the constrained path proves useful.

## Success measures

- proof eligibility: pushes with a proof for the exact required inputs;
- proof acceptance: eligible proofs accepted by policy;
- critical-path minutes avoided;
- duplicate runner-minutes avoided;
- proof decision latency;
- fallback completion rate;
- false-green count;
- unexplained result mismatch count.

False greens and unexplained mismatches must remain zero before enforcement.

## Product gates

Continue beyond a private shadow pilot only when:

1. multiple external teams share CI data and agree to install a pilot App;
2. target repositories have enough eligible duplicate work to matter;
3. shadow runs show exact agreement with ordinary CI;
4. key isolation, replay protection, fallback, and revocation work end to end;
5. avoided latency or compute cost exceeds CIHash operating cost and adoption friction.

## Continuation decision

An adversarial architecture review concluded that a standalone vendor-operated
trusted runner cannot win its own economics: it relocates the verification run
to more expensive isolated infrastructure instead of eliminating it, and the
eligibility constraints select for the cheapest CI jobs. The decisive
constraint is ownership of the execution moment: only a system that already
runs the agent's final verification can turn that run into evidence at zero
marginal compute.

Direction: position CIHash as an embedded attestation bridge for platforms
that already execute a coding agent's final verification in an isolated
workcell. The platform signs its existing run under its own key custody;
CIHash supplies the receipt schema, the deterministic verifier, and the
receipt-driven GitHub App with fallback orchestration. Vendor-operated
execution at scale, generic GitHub Actions interpretation, and speculative
compatibility layers are out of scope. The product gates above now test that
wedge, and the pilot metrics that decide continuation are unchanged.
