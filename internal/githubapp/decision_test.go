package githubapp_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/wolfiesch/cihash/internal/attestation"
	"github.com/wolfiesch/cihash/internal/githubapp"
	"github.com/wolfiesch/cihash/internal/store"
	"github.com/wolfiesch/cihash/internal/verifier"
)

func TestEvaluatePublishesSuccessForExactProof(t *testing.T) {
	receiptStore, publicKey, expected := storedProof(t)
	result := githubapp.Evaluate(receiptStore, publicKey, expected, githubapp.EnforceMode)
	if !result.Accepted || result.FallbackRequired {
		t.Fatalf("result = %+v, want accepted without fallback", result)
	}
	if result.CheckRun.Status != "completed" || result.CheckRun.Conclusion != "success" {
		t.Fatalf("check run = %+v, want completed success", result.CheckRun)
	}
}

func TestEvaluateRequiresFallbackWhenExactProofIsMissing(t *testing.T) {
	receiptStore, publicKey, expected := storedProof(t)
	expected.BaseSHA = strings.Repeat("d", 40)
	result := githubapp.Evaluate(receiptStore, publicKey, expected, githubapp.EnforceMode)
	if result.Accepted || !result.FallbackRequired || result.Code != "proof_missing" {
		t.Fatalf("result = %+v, want proof_missing fallback", result)
	}
	if result.CheckRun.Status != "queued" || result.CheckRun.Conclusion != "" {
		t.Fatalf("check run = %+v, want queued without conclusion", result.CheckRun)
	}
}

func storedProof(t *testing.T) (store.Store, ed25519.PublicKey, verifier.Expected) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.July, 20, 12, 0, 0, 0, time.UTC)
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
			Conclusion:  "success",
			StartedAt:   now.Add(-time.Minute),
			CompletedAt: now.Add(-time.Second),
			LogDigest:   attestation.Digest([]byte("verified")),
		}},
		Conclusion: "success",
		Nonce:      "expected-nonce",
		IssuedAt:   now,
		ExpiresAt:  now.Add(time.Hour),
	}
	envelope, err := attestation.Sign(attestation.NewStatement(result), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	receiptStore := store.New(t.TempDir())
	if _, _, err := receiptStore.Save(store.IdentityFromResult(result), envelope, []byte("verified")); err != nil {
		t.Fatal(err)
	}
	return receiptStore, publicKey, verifier.Expected{
		Repository:        result.Repository,
		HeadSHA:           result.HeadSHA,
		BaseSHA:           result.BaseSHA,
		Profile:           result.Profile,
		PolicyDigest:      result.PolicyDigest,
		WorkflowDigest:    result.WorkflowDigest,
		EnvironmentDigest: result.EnvironmentDigest,
		Architecture:      result.Architecture,
		Jobs:              []verifier.ExpectedJob{{Name: "verify", Command: command}},
		Nonce:             result.Nonce,
		MaxAge:            time.Hour,
		Now:               now,
	}
}
