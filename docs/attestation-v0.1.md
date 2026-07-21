# CIHash test-result attestation v0.1

## Envelope

Receipts use a DSSE envelope:

```json
{
  "payloadType": "application/vnd.in-toto+json",
  "payload": "<base64 in-toto statement>",
  "signatures": [
    { "keyid": "sha256:<public-key-digest>", "sig": "<base64 signature>" }
  ]
}
```

The signature covers DSSE pre-authentication encoding of the exact payload type and payload bytes. v0.1 permits exactly one Ed25519 signature.

### Experimental threshold verification

The hosted v0.1 decision path continues to require one configured signer. The
`cihash lab trust-quorum` workbench separately exercises DSSE threshold
verification over the same payload:

- only cryptographically valid signatures from distinct trusted public keys
  count toward the threshold;
- repeated signatures from one key count once;
- DSSE `keyid` values are unauthenticated lookup hints and never grant trust;
- satisfying the signature threshold does not weaken repository, revision,
  policy, workflow, environment, expiry, nonce, or job checks.

This proves that the receipt and acceptance layers can represent quorum trust.
It does not prove independent execution: the `trust-quorum` workbench generates
both signers in one process.

### Experimental independent confirmation

`cihash lab confirmer` exercises a separate in-toto agreement predicate for two
v0.1 receipts under distinct administrator-approved signer-to-domain bindings.
Each receipt keeps its own nonce, timestamps, expiry, and signature. The
confirmer projects only the deterministic execution claim, compares those
claims, and binds an agreement statement to the SHA-256 digest of the canonical
stored serialization of each DSSE envelope. Both receipt keys then sign the
exact agreement payload, producing a 2-of-2 agreement.

The deterministic projection retains repository, head, base, tree, profile,
policy, workflow, environment, architecture, job names, commands, exit codes,
conclusions, log digests, and the overall conclusion. It excludes per-run clocks
and nonces, so separately timed observations do not falsely claim identical
runtime metadata.

An agreement conclusion means only that the projected claims match. It is not a
success authorization and is not accepted by the hosted v0.1 verifier. Any
future authorization path must retrieve and fully validate both referenced
receipts for freshness, nonce and replay state, exact policy and job set,
success, signer independence, and evidence availability.

## Run authorization

Before trusted execution, the control plane creates a
`https://cihash.dev/run-grant/v0.1` grant from administrator-controlled policy
and GitHub state resolved by the server. Submitted repository code does not
choose the command, environment, policy, base, expiry, or nonce.

The grant records:

- an unpredictable 32-byte run ID and a distinct 32-byte nonce;
- the exact head and base Git object IDs;
- the complete approved policy plus its policy, workflow, and environment
  digests;
- the explicit Linux execution architecture; and
- server issuance and expiry times, with the validity window fixed by the
  approved policy.

The server persists the grant before returning it. Its lifecycle is monotonic:
`issued` becomes `submitted` after a verified receipt is bound to the run, then
becomes `consumed` after the GitHub decision uses that receipt. Submission and
consumption must both occur before expiry. One receipt digest may be submitted
idempotently while valid; a different digest, an early timestamp, a late
transition, or consumption before submission is rejected.

The run ID and nonce are proof bindings, not client authentication credentials.
Receipt submission requires a separate authenticated producer channel. The
grant JSON is not itself signed; the server-owned stored record is authoritative,
and receipt acceptance compares the signed predicate to that record.

## Statement

The decoded payload is an in-toto Statement v1:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "<repository>",
      "digest": { "gitCommit": "<head SHA>" }
    }
  ],
  "predicateType": "https://cihash.dev/attestation/test-result/v0.1",
  "predicate": {}
}
```

The predicate contains:

| Field | Meaning |
|---|---|
| `schemaVersion` | Receipt schema version, currently `0.1`. |
| `repository` | Canonical repository identity. |
| `headSha` | Exact committed change under test. |
| `baseSha` | Exact target-branch commit used by the run. |
| `treeSha` | Git tree object executed by the runner. |
| `profile` | Administrator-approved verification profile. |
| `policyDigest` | SHA-256 of the approved policy document. |
| `workflowDigest` | SHA-256 of the approved profile and command. |
| `environmentDigest` | SHA-256 of the immutable execution-environment identity. |
| `architecture` | Runner OS and architecture. |
| `jobs` | Complete required job results and signed log digests. |
| `conclusion` | `success` or `failure`. |
| `nonce` | Server-issued, single-use job nonce. |
| `issuedAt` | UTC issuance time. |
| `expiresAt` | UTC time after which reuse is forbidden. |

Each job records its approved name, command argument vector, exit code, conclusion, start and completion times, and SHA-256 log digest.

## Acceptance invariants

A receipt authorizes success only when:

1. the DSSE signature is valid under a currently trusted, non-revoked key;
2. the statement and predicate types are supported exactly;
3. subject repository and Git commit agree with the predicate;
4. repository, head, base, profile, policy, workflow, and environment match expected values exactly;
5. the receipt is issued within the permitted clock window and has not expired;
6. the nonce is valid for the submitted job and has not been replayed;
7. every required job is present exactly once and succeeded;
8. the overall conclusion is `success`.

A signed failure is authentic evidence but never authorization.
