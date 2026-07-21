package verifier

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/wolfiesch/cihash/internal/attestation"
)

func TestVerifyAcceptsExactSuccessfulProof(t *testing.T) {
	envelope, publicKey, expected := signedFixture(t, "success")
	decision := Verify(envelope, publicKey, expected)
	if !decision.Accepted || decision.Code != "accepted" {
		t.Fatalf("decision = %+v, want accepted", decision)
	}
}

func TestVerifyRejectsChangedBase(t *testing.T) {
	envelope, publicKey, expected := signedFixture(t, "success")
	expected.BaseSHA = strings.Repeat("d", 40)
	decision := Verify(envelope, publicKey, expected)
	if decision.Accepted || decision.Code != "base_mismatch" {
		t.Fatalf("decision = %+v, want base_mismatch", decision)
	}
}

func TestVerifyRejectsSignedFailure(t *testing.T) {
	envelope, publicKey, expected := signedFixture(t, "failure")
	decision := Verify(envelope, publicKey, expected)
	if decision.Accepted || decision.Code != "job_failed" {
		t.Fatalf("decision = %+v, want job_failed", decision)
	}
}

func TestVerifyRejectsExpiredProof(t *testing.T) {
	envelope, publicKey, expected := signedFixture(t, "success")
	expected.Now = expected.Now.Add(time.Hour)
	decision := Verify(envelope, publicKey, expected)
	if decision.Accepted || decision.Code != "expired" {
		t.Fatalf("decision = %+v, want expired", decision)
	}
}

func signedFixture(t *testing.T, conclusion string) (attestation.Envelope, ed25519.PublicKey, Expected) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.July, 20, 12, 0, 0, 0, time.UTC)
	exitCode := 0
	if conclusion != "success" {
		exitCode = 1
	}
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
		Architecture:      "linux/arm64",
		Jobs: []attestation.JobResult{{
			Name:        "verify",
			Command:     command,
			ExitCode:    exitCode,
			Conclusion:  conclusion,
			StartedAt:   now.Add(-time.Minute),
			CompletedAt: now.Add(-time.Second),
			LogDigest:   attestation.Digest([]byte("log")),
		}},
		Conclusion: conclusion,
		Nonce:      "expected-nonce",
		IssuedAt:   now,
		ExpiresAt:  now.Add(time.Hour),
	}
	envelope, err := attestation.Sign(attestation.NewStatement(result), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return envelope, publicKey, Expected{
		Repository:        result.Repository,
		HeadSHA:           result.HeadSHA,
		BaseSHA:           result.BaseSHA,
		Profile:           result.Profile,
		PolicyDigest:      result.PolicyDigest,
		WorkflowDigest:    result.WorkflowDigest,
		EnvironmentDigest: result.EnvironmentDigest,
		Command:           command,
		RequiredJobs:      []string{"verify"},
		Nonce:             result.Nonce,
		MaxAge:            time.Hour,
		Now:               now,
	}
}
