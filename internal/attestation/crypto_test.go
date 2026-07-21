package attestation

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSignAndVerifyExactStatement(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	statement := NewStatement(testResult("success"))
	envelope, err := Sign(statement, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifySignature(envelope, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Predicate.HeadSHA != statement.Predicate.HeadSHA {
		t.Fatalf("verified head %q, want %q", verified.Predicate.HeadSHA, statement.Predicate.HeadSHA)
	}
}

func TestVerifyThresholdSignaturesCountsDistinctTrustedKeys(t *testing.T) {
	publicKeyA, privateKeyA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKeyB, privateKeyB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	statement := NewStatement(testResult("success"))
	envelope, err := Sign(statement, privateKeyA)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err = AddSignature(envelope, privateKeyB)
	if err != nil {
		t.Fatal(err)
	}
	envelope.Signatures[0].KeyID = KeyID(publicKeyB)
	envelope.Signatures[1].KeyID = "unauthenticated-hint"
	verified, err := VerifyThresholdSignatures(envelope, []ed25519.PublicKey{publicKeyA, publicKeyB}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Predicate.HeadSHA != statement.Predicate.HeadSHA {
		t.Fatalf("verified head %q, want %q", verified.Predicate.HeadSHA, statement.Predicate.HeadSHA)
	}
}

func TestVerifyThresholdSignaturesRejectsDuplicateSigner(t *testing.T) {
	publicKeyA, privateKeyA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKeyB, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := Sign(NewStatement(testResult("success")), privateKeyA)
	if err != nil {
		t.Fatal(err)
	}
	envelope.Signatures = append(envelope.Signatures, envelope.Signatures[0])
	if _, err := VerifyThresholdSignatures(envelope, []ed25519.PublicKey{publicKeyA, publicKeyB}, 2); !errors.Is(err, ErrUntrustedSigner) {
		t.Fatalf("VerifyThresholdSignatures error = %v, want ErrUntrustedSigner", err)
	}
	if _, err := AddSignature(envelope, privateKeyA); !errors.Is(err, ErrMalformedReceipt) {
		t.Fatalf("AddSignature error = %v, want ErrMalformedReceipt", err)
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := Sign(NewStatement(testResult("success")), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	payload[len(payload)/2] ^= 1
	envelope.Payload = base64.StdEncoding.EncodeToString(payload)
	if _, err := VerifySignature(envelope, publicKey); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("VerifySignature error = %v, want ErrInvalidSignature", err)
	}
}

func TestUnmarshalEnvelopeRejectsTrailingDocument(t *testing.T) {
	data := []byte(`{"payloadType":"application/vnd.in-toto+json","payload":"","signatures":[]} {}`)
	if _, err := UnmarshalEnvelope(data); !errors.Is(err, ErrMalformedReceipt) {
		t.Fatalf("UnmarshalEnvelope error = %v, want ErrMalformedReceipt", err)
	}
}

func testResult(conclusion string) TestResult {
	now := time.Date(2026, time.July, 20, 12, 0, 0, 0, time.UTC)
	exitCode := 0
	if conclusion != "success" {
		exitCode = 1
	}
	return TestResult{
		SchemaVersion:     SchemaVersion,
		Repository:        "github.com/example/project",
		HeadSHA:           strings.Repeat("a", 40),
		BaseSHA:           strings.Repeat("b", 40),
		TreeSHA:           strings.Repeat("c", 40),
		Profile:           "verify",
		PolicyDigest:      Digest([]byte("policy")),
		WorkflowDigest:    Digest([]byte("workflow")),
		EnvironmentDigest: Digest([]byte("environment")),
		Architecture:      "linux/arm64",
		Jobs: []JobResult{{
			Name:        "verify",
			Command:     []string{"go", "test", "./..."},
			ExitCode:    exitCode,
			Conclusion:  conclusion,
			StartedAt:   now.Add(-time.Minute),
			CompletedAt: now.Add(-time.Second),
			LogDigest:   Digest([]byte("log")),
		}},
		Conclusion: conclusion,
		Nonce:      "server-issued-nonce",
		IssuedAt:   now,
		ExpiresAt:  now.Add(time.Hour),
	}
}
