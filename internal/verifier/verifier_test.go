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

func TestVerifyThresholdRequiresQuorumBeforeClaimValidation(t *testing.T) {
	envelope, publicKeyA, expected := signedFixture(t, "success")
	publicKeyB, privateKeyB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	singleSignature := envelope
	envelope, err = attestation.AddSignature(envelope, privateKeyB)
	if err != nil {
		t.Fatal(err)
	}
	decision := VerifyThreshold(envelope, []ed25519.PublicKey{publicKeyA, publicKeyB}, 2, expected)
	if !decision.Accepted || decision.Code != "accepted" {
		t.Fatalf("decision = %+v, want accepted quorum", decision)
	}
	expected.BaseSHA = strings.Repeat("d", 40)
	decision = VerifyThreshold(envelope, []ed25519.PublicKey{publicKeyA, publicKeyB}, 2, expected)
	if decision.Accepted || decision.Code != "base_mismatch" {
		t.Fatalf("decision = %+v, want base_mismatch after quorum", decision)
	}
	decision = VerifyThreshold(singleSignature, []ed25519.PublicKey{publicKeyA, publicKeyB}, 2, expected)
	if decision.Accepted || decision.Code != "untrusted_signer" {
		t.Fatalf("decision = %+v, want untrusted_signer without quorum", decision)
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
func TestVerifyRejectsChangedTree(t *testing.T) {
	envelope, publicKey, expected := signedFixture(t, "success")
	expected.TreeSHA = strings.Repeat("d", 40)
	decision := Verify(envelope, publicKey, expected)
	if decision.Accepted || decision.Code != "tree_mismatch" {
		t.Fatalf("decision = %+v, want tree_mismatch", decision)
	}
}

func TestVerifyRejectsChangedArchitecture(t *testing.T) {
	envelope, publicKey, expected := signedFixture(t, "success")
	expected.Architecture = "linux/amd64"
	decision := Verify(envelope, publicKey, expected)
	if decision.Accepted || decision.Code != "architecture_mismatch" {
		t.Fatalf("decision = %+v, want architecture_mismatch", decision)
	}
}

func TestVerifyRejectsSignedFailure(t *testing.T) {
	envelope, publicKey, expected := signedFixture(t, "failure")
	decision := Verify(envelope, publicKey, expected)
	if decision.Accepted || decision.Code != "job_failed" {
		t.Fatalf("decision = %+v, want job_failed", decision)
	}
}
func TestVerifyRejectsContradictoryAggregateConclusion(t *testing.T) {
	for _, test := range []struct {
		name              string
		jobConclusion     string
		overallConclusion string
	}{
		{name: "failed job successful run", jobConclusion: "failure", overallConclusion: "success"},
		{name: "successful job failed run", jobConclusion: "success", overallConclusion: "failure"},
	} {
		t.Run(test.name, func(t *testing.T) {
			envelope, publicKey, expected := signedConclusionsFixture(t, test.jobConclusion, test.overallConclusion)
			decision := Verify(envelope, publicKey, expected)
			if decision.Accepted || decision.Code != "malformed_receipt" {
				t.Fatalf("decision = %+v, want malformed_receipt", decision)
			}
		})
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
	return signedConclusionsFixture(t, conclusion, conclusion)
}

func signedConclusionsFixture(t *testing.T, jobConclusion, overallConclusion string) (attestation.Envelope, ed25519.PublicKey, Expected) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.July, 20, 12, 0, 0, 0, time.UTC)
	exitCode := 0
	if jobConclusion != "success" {
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
			Conclusion:  jobConclusion,
			StartedAt:   now.Add(-time.Minute),
			CompletedAt: now.Add(-time.Second),
			LogDigest:   attestation.Digest([]byte("log")),
		}},
		Conclusion: overallConclusion,
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
		TreeSHA:           result.TreeSHA,
		Profile:           result.Profile,
		PolicyDigest:      result.PolicyDigest,
		WorkflowDigest:    result.WorkflowDigest,
		EnvironmentDigest: result.EnvironmentDigest,
		Architecture:      result.Architecture,
		Jobs:              []ExpectedJob{{Name: "verify", Command: command}},
		Nonce:             result.Nonce,
		MaxAge:            time.Hour,
		Now:               now,
	}
}
