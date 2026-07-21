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
It does not prove independent execution: the current workbench generates both
signers in one process. A later confirmer experiment must place signers in
separate trust domains and require agreement on one exact statement payload.

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
