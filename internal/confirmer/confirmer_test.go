package confirmer

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/wolfiesch/cihash/internal/attestation"
)

func TestIndependentObservationsAgreeAndSignThresholdAgreement(t *testing.T) {
	publicKeyA, privateKeyA := testKey(t)
	publicKeyB, privateKeyB := testKey(t)
	resultA := testResult()
	resultB := testResult()
	resultB.Nonce = "independent-nonce"
	resultB.IssuedAt = resultB.IssuedAt.Add(17 * time.Minute)
	resultB.ExpiresAt = resultB.ExpiresAt.Add(17 * time.Minute)
	resultB.Jobs[0].StartedAt = resultB.Jobs[0].StartedAt.Add(17 * time.Minute)
	resultB.Jobs[0].CompletedAt = resultB.Jobs[0].CompletedAt.Add(17 * time.Minute)
	observationA := testObservation(t, "runner-a", resultA, privateKeyA, publicKeyA)
	observationB := testObservation(t, "runner-b", resultB, privateKeyB, publicKeyB)
	comparison, err := CompareObservations(observationA, observationB)
	if err != nil {
		t.Fatal(err)
	}
	if !comparison.Agrees || comparison.Divergence != DivergenceNone || comparison.Fingerprint == "" {
		t.Fatalf("comparison = %#v, want deterministic agreement", comparison)
	}
	agreement, err := SignAgreement(observationA, observationB, privateKeyA)
	if err != nil {
		t.Fatal(err)
	}
	agreement, err = AddAgreementSignature(agreement, observationA, observationB, privateKeyB)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyAgreement(agreement, testDomains(publicKeyA, publicKeyB))
	if err != nil {
		t.Fatal(err)
	}
	if verified.Predicate.Conclusion != AgreementConclusion || verified.Predicate.Claim.Conclusion != "success" {
		t.Fatalf("agreement conclusions = %q/%q, want agreement/success", verified.Predicate.Conclusion, verified.Predicate.Claim.Conclusion)
	}
}

func TestProjectClaimNormalizesJobOrder(t *testing.T) {
	first := testResult()
	first.Jobs = append(first.Jobs, attestation.JobResult{
		Name: "lint", Command: []string{"go", "vet", "./..."}, ExitCode: 0, Conclusion: "success", LogDigest: attestation.Digest([]byte("lint")),
	})
	second := first
	second.Jobs = append([]attestation.JobResult(nil), first.Jobs...)
	second.Jobs[0], second.Jobs[1] = second.Jobs[1], second.Jobs[0]
	firstFingerprint, err := ClaimFingerprint(ProjectClaim(first))
	if err != nil {
		t.Fatal(err)
	}
	secondFingerprint, err := ClaimFingerprint(ProjectClaim(second))
	if err != nil {
		t.Fatal(err)
	}
	if firstFingerprint != secondFingerprint {
		t.Fatalf("claim fingerprints differ: %q != %q", firstFingerprint, secondFingerprint)
	}
}

func TestCompareObservationsDivergencePrecedence(t *testing.T) {
	publicKeyA, privateKeyA := testKey(t)
	publicKeyB, privateKeyB := testKey(t)
	cases := []struct {
		name   string
		want   Divergence
		mutate func(*attestation.TestResult)
	}{
		{
			name: "identity", want: DivergenceIdentity,
			mutate: func(result *attestation.TestResult) { result.HeadSHA = strings.Repeat("d", 40) },
		},
		{
			name: "policy workflow", want: DivergencePolicyWorkflow,
			mutate: func(result *attestation.TestResult) {
				result.PolicyDigest = attestation.Digest([]byte("different-policy"))
			},
		},
		{
			name: "environment architecture", want: DivergenceEnvironmentArchitecture,
			mutate: func(result *attestation.TestResult) { result.Architecture = "linux/arm64" },
		},
		{
			name: "job set command", want: DivergenceJobSetCommand,
			mutate: func(result *attestation.TestResult) {
				result.Jobs[0].Command = []string{"go", "test", "./internal/..."}
			},
		},
		{
			name: "job set", want: DivergenceJobSetCommand,
			mutate: func(result *attestation.TestResult) {
				result.Jobs = append(result.Jobs, attestation.JobResult{Name: "lint", Command: []string{"go", "vet", "./..."}, ExitCode: 0, Conclusion: "success", LogDigest: attestation.Digest([]byte("lint-log"))})
			},
		},
		{
			name: "result", want: DivergenceResult,
			mutate: func(result *attestation.TestResult) { result.Jobs[0].ExitCode = 1 },
		},
		{
			name: "log", want: DivergenceLog,
			mutate: func(result *attestation.TestResult) {
				result.Jobs[0].LogDigest = attestation.Digest([]byte("different-log"))
			},
		},
	}
	for _, candidate := range cases {
		t.Run(candidate.name, func(t *testing.T) {
			left := testResult()
			right := testResult()
			candidate.mutate(&right)
			leftObservation := testObservation(t, "runner-a", left, privateKeyA, publicKeyA)
			rightObservation := testObservation(t, "runner-b", right, privateKeyB, publicKeyB)
			comparison, err := CompareObservations(leftObservation, rightObservation)
			if err != nil {
				t.Fatal(err)
			}
			if comparison.Agrees || comparison.Divergence != candidate.want {
				t.Fatalf("comparison = %#v, want divergence %q", comparison, candidate.want)
			}
		})
	}
}

func TestBuildAgreementRejectsDuplicateTrustDomain(t *testing.T) {
	publicKeyA, privateKeyA := testKey(t)
	publicKeyB, privateKeyB := testKey(t)
	left := testObservation(t, "shared-domain", testResult(), privateKeyA, publicKeyA)
	right := testObservation(t, "shared-domain", testResult(), privateKeyB, publicKeyB)
	if _, err := BuildAgreement(left, right); !errors.Is(err, ErrInvalidAgreement) {
		t.Fatalf("BuildAgreement error = %v, want ErrInvalidAgreement", err)
	}
}

func TestBuildAgreementRejectsOneReceiptSignerAcrossDomains(t *testing.T) {
	publicKey, privateKey := testKey(t)
	leftResult := testResult()
	rightResult := testResult()
	rightResult.Nonce = "second-nonce"
	rightResult.IssuedAt = rightResult.IssuedAt.Add(time.Minute)
	rightResult.ExpiresAt = rightResult.ExpiresAt.Add(time.Minute)
	rightResult.Jobs[0].StartedAt = rightResult.Jobs[0].StartedAt.Add(time.Minute)
	rightResult.Jobs[0].CompletedAt = rightResult.Jobs[0].CompletedAt.Add(time.Minute)
	left := testObservation(t, "runner-a", leftResult, privateKey, publicKey)
	right := testObservation(t, "runner-b", rightResult, privateKey, publicKey)
	if _, err := BuildAgreement(left, right); !errors.Is(err, ErrInvalidAgreement) {
		t.Fatalf("BuildAgreement error = %v, want ErrInvalidAgreement", err)
	}
}

func TestAgreementConstructionRejectsUnboundSigner(t *testing.T) {
	publicKeyA, privateKeyA := testKey(t)
	publicKeyB, privateKeyB := testKey(t)
	_, unboundPrivateKey := testKey(t)
	left := testObservation(t, "runner-a", testResult(), privateKeyA, publicKeyA)
	right := testObservation(t, "runner-b", testResult(), privateKeyB, publicKeyB)
	if _, err := SignAgreement(left, right, unboundPrivateKey); !errors.Is(err, ErrInvalidAgreement) {
		t.Fatalf("SignAgreement error = %v, want ErrInvalidAgreement", err)
	}
	agreement, err := SignAgreement(left, right, privateKeyA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AddAgreementSignature(agreement, left, right, unboundPrivateKey); !errors.Is(err, ErrInvalidAgreement) {
		t.Fatalf("AddAgreementSignature error = %v, want ErrInvalidAgreement", err)
	}
	payload, err := agreementPayload(left, right)
	if err != nil {
		t.Fatal(err)
	}
	rogueAgreement, err := attestation.SignPayload(attestation.PayloadType, payload, unboundPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AddAgreementSignature(rogueAgreement, left, right, privateKeyB); !errors.Is(err, ErrInvalidAgreement) {
		t.Fatalf("rogue existing signer error = %v, want ErrInvalidAgreement", err)
	}
}

func TestVerifyObservationRejectsInconsistentSubjectAndDuplicateJobs(t *testing.T) {
	publicKey, privateKey := testKey(t)
	domain := TrustDomain{Name: "runner-a", ReceiptKey: publicKey}

	statement := attestation.NewStatement(testResult())
	statement.Subject[0].Name = "github.com/other/project"
	envelope, err := attestation.Sign(statement, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyObservation(domain, envelope); !errors.Is(err, ErrInvalidObservation) {
		t.Fatalf("subject mismatch error = %v, want ErrInvalidObservation", err)
	}

	duplicateJobs := testResult()
	duplicateJobs.Jobs = append(duplicateJobs.Jobs, duplicateJobs.Jobs[0])
	envelope, err = attestation.Sign(attestation.NewStatement(duplicateJobs), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyObservation(domain, envelope); !errors.Is(err, ErrInvalidObservation) {
		t.Fatalf("duplicate jobs error = %v, want ErrInvalidObservation", err)
	}
}

func TestVerifyAgreementRejectsMissingQuorumAndDuplicateSigner(t *testing.T) {
	publicKeyA, privateKeyA := testKey(t)
	publicKeyB, privateKeyB := testKey(t)
	left := testObservation(t, "runner-a", testResult(), privateKeyA, publicKeyA)
	right := testObservation(t, "runner-b", testResult(), privateKeyB, publicKeyB)
	agreement, err := SignAgreement(left, right, privateKeyA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAgreement(agreement, testDomains(publicKeyA, publicKeyB)); !errors.Is(err, ErrInvalidAgreement) {
		t.Fatalf("missing quorum error = %v, want ErrInvalidAgreement", err)
	}
	duplicate := agreement
	duplicate.Signatures = append(duplicate.Signatures, duplicate.Signatures[0])
	if _, err := VerifyAgreement(duplicate, testDomains(publicKeyA, publicKeyB)); !errors.Is(err, ErrInvalidAgreement) {
		t.Fatalf("duplicate signer error = %v, want ErrInvalidAgreement", err)
	}
}

func TestVerifyAgreementRejectsTamperingAndMalformedStatements(t *testing.T) {
	publicKeyA, privateKeyA := testKey(t)
	publicKeyB, privateKeyB := testKey(t)
	left := testObservation(t, "runner-a", testResult(), privateKeyA, publicKeyA)
	right := testObservation(t, "runner-b", testResult(), privateKeyB, publicKeyB)
	agreement, err := SignAgreement(left, right, privateKeyA)
	if err != nil {
		t.Fatal(err)
	}
	agreement, err = AddAgreementSignature(agreement, left, right, privateKeyB)
	if err != nil {
		t.Fatal(err)
	}
	tampered := agreement
	payload, err := base64.StdEncoding.DecodeString(tampered.Payload)
	if err != nil {
		t.Fatal(err)
	}
	payload[len(payload)/2] ^= 1
	tampered.Payload = base64.StdEncoding.EncodeToString(payload)
	if _, err := VerifyAgreement(tampered, testDomains(publicKeyA, publicKeyB)); !errors.Is(err, ErrInvalidAgreement) {
		t.Fatalf("tampered agreement error = %v, want ErrInvalidAgreement", err)
	}
	malformed, err := attestation.SignPayload(attestation.PayloadType, []byte(`{"_type":"wrong"}`), privateKeyA)
	if err != nil {
		t.Fatal(err)
	}
	malformed, err = attestation.AddSignature(malformed, privateKeyB)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAgreement(malformed, testDomains(publicKeyA, publicKeyB)); !errors.Is(err, ErrInvalidAgreement) {
		t.Fatalf("malformed agreement error = %v, want ErrInvalidAgreement", err)
	}
}

func TestVerifyAgreementRejectsUnapprovedTrustBinding(t *testing.T) {
	publicKeyA, privateKeyA := testKey(t)
	publicKeyB, privateKeyB := testKey(t)
	left := testObservation(t, "runner-a", testResult(), privateKeyA, publicKeyA)
	right := testObservation(t, "runner-b", testResult(), privateKeyB, publicKeyB)
	agreement, err := SignAgreement(left, right, privateKeyA)
	if err != nil {
		t.Fatal(err)
	}
	agreement, err = AddAgreementSignature(agreement, left, right, privateKeyB)
	if err != nil {
		t.Fatal(err)
	}
	unapproved := []TrustDomain{
		{Name: "renamed-runner", ReceiptKey: publicKeyA},
		{Name: "runner-b", ReceiptKey: publicKeyB},
	}
	if _, err := VerifyAgreement(agreement, unapproved); !errors.Is(err, ErrInvalidAgreement) {
		t.Fatalf("unapproved binding error = %v, want ErrInvalidAgreement", err)
	}
}

func TestFailureAgreementRetainsFailureWithoutClaimingSuccess(t *testing.T) {
	publicKeyA, privateKeyA := testKey(t)
	publicKeyB, privateKeyB := testKey(t)
	failureA := testResult()
	failureA.Conclusion = "failure"
	failureA.Jobs[0].Conclusion = "failure"
	failureA.Jobs[0].ExitCode = 1
	failureB := failureA
	left := testObservation(t, "runner-a", failureA, privateKeyA, publicKeyA)
	right := testObservation(t, "runner-b", failureB, privateKeyB, publicKeyB)
	statement, err := BuildAgreement(left, right)
	if err != nil {
		t.Fatal(err)
	}
	if statement.Predicate.Conclusion != AgreementConclusion || statement.Predicate.Claim.Conclusion != "failure" {
		t.Fatalf("agreement conclusions = %q/%q, want agreement/failure", statement.Predicate.Conclusion, statement.Predicate.Claim.Conclusion)
	}
}

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return publicKey, privateKey
}

func testObservation(t *testing.T, domain string, result attestation.TestResult, privateKey ed25519.PrivateKey, publicKey ed25519.PublicKey) Observation {
	t.Helper()
	envelope, err := attestation.Sign(attestation.NewStatement(result), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := VerifyObservation(TrustDomain{Name: domain, ReceiptKey: publicKey}, envelope)
	if err != nil {
		t.Fatal(err)
	}
	return observation
}

func testDomains(publicKeyA, publicKeyB ed25519.PublicKey) []TrustDomain {
	return []TrustDomain{
		{Name: "runner-a", ReceiptKey: publicKeyA},
		{Name: "runner-b", ReceiptKey: publicKeyB},
	}
}

func testResult() attestation.TestResult {
	now := time.Date(2026, time.July, 20, 12, 0, 0, 0, time.UTC)
	return attestation.TestResult{
		SchemaVersion:     attestation.SchemaVersion,
		Repository:        "github.com/cihash/lab",
		HeadSHA:           strings.Repeat("a", 40),
		BaseSHA:           strings.Repeat("b", 40),
		TreeSHA:           strings.Repeat("c", 40),
		Profile:           "verify",
		PolicyDigest:      attestation.Digest([]byte("policy")),
		WorkflowDigest:    attestation.Digest([]byte("workflow")),
		EnvironmentDigest: attestation.Digest([]byte("environment")),
		Architecture:      "linux/amd64",
		Jobs: []attestation.JobResult{{
			Name: "verify", Command: []string{"go", "test", "./..."}, ExitCode: 0, Conclusion: "success", StartedAt: now.Add(-time.Minute), CompletedAt: now.Add(-time.Second), LogDigest: attestation.Digest([]byte("log")),
		}},
		Conclusion: "success", Nonce: "first-nonce", IssuedAt: now, ExpiresAt: now.Add(time.Hour),
	}
}

func TestObservationRetainsCanonicalEnvelopeDigest(t *testing.T) {
	publicKey, privateKey := testKey(t)
	envelope, err := attestation.Sign(attestation.NewStatement(testResult()), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := VerifyObservation(TrustDomain{Name: "runner-a", ReceiptKey: publicKey}, envelope)
	if err != nil {
		t.Fatal(err)
	}
	data, err := attestation.MarshalEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if observation.EnvelopeDigest() != attestation.Digest(data) {
		t.Fatalf("envelope digest = %q, want %q", observation.EnvelopeDigest(), attestation.Digest(data))
	}
}
