package acceptance

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/wolfiesch/cihash/internal/attestation"
	"github.com/wolfiesch/cihash/internal/verifier"
)

func TestKeyringPlannedRotationUsesReceiptIssuanceTime(t *testing.T) {
	oldPublic, oldPrivate := keyPair(t)
	newPublic, newPrivate := keyPair(t)
	cutover := time.Date(2026, time.July, 21, 14, 0, 0, 0, time.UTC)
	evaluator := Ed25519KeyringEvaluator{
		Keys: []Ed25519Key{
			{PublicKey: oldPublic, ValidUntil: cutover},
			{PublicKey: newPublic, ValidFrom: cutover},
		},
		Threshold: 1,
	}

	beforeEnvelope, beforeExpected := signedResult(t, oldPrivate, cutover.Add(-time.Second))
	beforeExpected.Now = cutover.Add(time.Minute)
	if decision := evaluator.Verify(beforeEnvelope, beforeExpected); !decision.Accepted {
		t.Fatalf("old key before cutover = %+v, want accepted", decision)
	}

	atCutoverEnvelope, atCutoverExpected := signedResult(t, oldPrivate, cutover)
	atCutoverExpected.Now = cutover.Add(time.Minute)
	if decision := evaluator.Verify(atCutoverEnvelope, atCutoverExpected); decision.Accepted || decision.Code != "untrusted_signer" {
		t.Fatalf("old key at cutover = %+v, want untrusted_signer", decision)
	}

	newEnvelope, newExpected := signedResult(t, newPrivate, cutover)
	newExpected.Now = cutover.Add(time.Minute)
	if decision := evaluator.Verify(newEnvelope, newExpected); !decision.Accepted {
		t.Fatalf("new key at cutover = %+v, want accepted", decision)
	}
}

func TestKeyringEmergencyRevocationInvalidatesEarlierReceipts(t *testing.T) {
	publicKey, privateKey := keyPair(t)
	issuedAt := time.Date(2026, time.July, 21, 14, 0, 0, 0, time.UTC)
	revokedAt := issuedAt.Add(time.Minute)
	envelope, expected := signedResult(t, privateKey, issuedAt)
	evaluator := Ed25519KeyringEvaluator{
		Keys:      []Ed25519Key{{PublicKey: publicKey, RevokedAt: revokedAt}},
		Threshold: 1,
	}

	expected.Now = revokedAt.Add(-time.Nanosecond)
	if decision := evaluator.Verify(envelope, expected); !decision.Accepted {
		t.Fatalf("before revocation = %+v, want accepted", decision)
	}
	expected.Now = revokedAt
	if decision := evaluator.Verify(envelope, expected); decision.Accepted || decision.Code != "untrusted_signer" {
		t.Fatalf("at revocation = %+v, want untrusted_signer", decision)
	}
}

func TestKeyringInvalidConfigurationFailsClosed(t *testing.T) {
	publicKey, privateKey := keyPair(t)
	now := time.Date(2026, time.July, 21, 14, 0, 0, 0, time.UTC)
	envelope, expected := signedResult(t, privateKey, now)
	evaluator := Ed25519KeyringEvaluator{
		Keys: []Ed25519Key{
			{PublicKey: publicKey},
			{PublicKey: append(ed25519.PublicKey(nil), publicKey...)},
		},
		Threshold: 1,
	}
	if decision := evaluator.Verify(envelope, expected); decision.Accepted || decision.Code != "keyring_invalid" {
		t.Fatalf("decision = %+v, want keyring_invalid", decision)
	}
}

func keyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return publicKey, privateKey
}

func signedResult(t *testing.T, privateKey ed25519.PrivateKey, issuedAt time.Time) (attestation.Envelope, verifier.Expected) {
	t.Helper()
	command := []string{"go", "test", "./..."}
	result := attestation.TestResult{
		SchemaVersion:     attestation.SchemaVersion,
		Repository:        "github.com/example/project",
		HeadSHA:           strings.Repeat("a", 40),
		BaseSHA:           strings.Repeat("b", 40),
		TreeSHA:           strings.Repeat("c", 40),
		Profile:           "verify",
		PolicyDigest:      attestation.Digest([]byte("policy")),
		WorkflowDigest:    attestation.Digest([]byte("workflow")),
		EnvironmentDigest: attestation.Digest([]byte("environment")),
		Architecture:      "linux/amd64",
		Jobs: []attestation.JobResult{{
			Name:        "verify",
			Command:     command,
			Conclusion:  "success",
			StartedAt:   issuedAt.Add(-time.Minute),
			CompletedAt: issuedAt.Add(-time.Second),
			LogDigest:   attestation.Digest([]byte("log")),
		}},
		Conclusion: "success",
		Nonce:      "expected-nonce",
		IssuedAt:   issuedAt,
		ExpiresAt:  issuedAt.Add(time.Hour),
	}
	envelope, err := attestation.Sign(attestation.NewStatement(result), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return envelope, verifier.Expected{
		Repository:        result.Repository,
		HeadSHA:           result.HeadSHA,
		BaseSHA:           result.BaseSHA,
		TreeSHA:           result.TreeSHA,
		Profile:           result.Profile,
		PolicyDigest:      result.PolicyDigest,
		WorkflowDigest:    result.WorkflowDigest,
		EnvironmentDigest: result.EnvironmentDigest,
		Architecture:      result.Architecture,
		Jobs:              []verifier.ExpectedJob{{Name: "verify", Command: command}},
		Nonce:             result.Nonce,
		MaxAge:            time.Hour,
		Now:               issuedAt.Add(time.Minute),
	}
}
