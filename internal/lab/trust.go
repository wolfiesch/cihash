package lab

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/wolfiesch/cihash/internal/acceptance"
	"github.com/wolfiesch/cihash/internal/attestation"
	"github.com/wolfiesch/cihash/internal/store"
	"github.com/wolfiesch/cihash/internal/verifier"
)

const ReportSchema = "https://cihash.dev/lab/report/v0.1"

type ScenarioResult struct {
	Name         string `json:"name"`
	Accepted     bool   `json:"accepted"`
	Code         string `json:"code"`
	ExpectedCode string `json:"expectedCode"`
	Passed       bool   `json:"passed"`
}

type Report struct {
	SchemaVersion string           `json:"schemaVersion"`
	Experiment    string           `json:"experiment"`
	Passed        bool             `json:"passed"`
	Scenarios     []ScenarioResult `json:"scenarios"`
}

type proofSource struct {
	envelope attestation.Envelope
	found    bool
	err      error
}

func (source proofSource) Lookup(store.Identity) (attestation.Envelope, string, bool, error) {
	return source.envelope, "lab://receipt", source.found, source.err
}

type scenario struct {
	name         string
	source       proofSource
	evaluator    acceptance.TrustEvaluator
	expected     verifier.Expected
	expectedCode string
}

func RunTrustQuorum() (Report, error) {
	publicKeyA, privateKeyA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Report{}, fmt.Errorf("generate first lab signer: %w", err)
	}
	publicKeyB, privateKeyB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Report{}, fmt.Errorf("generate second lab signer: %w", err)
	}
	now := time.Date(2026, time.July, 20, 12, 0, 0, 0, time.UTC)
	command := []string{"go", "test", "./..."}
	result := attestation.TestResult{
		SchemaVersion:     attestation.SchemaVersion,
		Repository:        "github.com/cihash/lab",
		HeadSHA:           strings.Repeat("a", 40),
		BaseSHA:           strings.Repeat("b", 40),
		TreeSHA:           strings.Repeat("c", 40),
		Profile:           "verify",
		PolicyDigest:      attestation.Digest([]byte("lab-policy")),
		WorkflowDigest:    attestation.Digest([]byte("lab-workflow")),
		EnvironmentDigest: attestation.Digest([]byte("lab-environment")),
		Architecture:      "linux/amd64",
		Jobs: []attestation.JobResult{{
			Name:        "verify",
			Command:     command,
			Conclusion:  "success",
			StartedAt:   now.Add(-time.Minute),
			CompletedAt: now.Add(-time.Second),
			LogDigest:   attestation.Digest([]byte("lab-log")),
		}},
		Conclusion: "success",
		Nonce:      "lab-nonce",
		IssuedAt:   now,
		ExpiresAt:  now.Add(time.Hour),
	}
	expected := verifier.Expected{
		Repository:        result.Repository,
		HeadSHA:           result.HeadSHA,
		BaseSHA:           result.BaseSHA,
		Profile:           result.Profile,
		PolicyDigest:      result.PolicyDigest,
		WorkflowDigest:    result.WorkflowDigest,
		EnvironmentDigest: result.EnvironmentDigest,
		Architecture:      result.Architecture,
		Command:           command,
		RequiredJobs:      []string{"verify"},
		Nonce:             result.Nonce,
		MaxAge:            time.Hour,
		Now:               now,
	}
	singleSignature, err := attestation.Sign(attestation.NewStatement(result), privateKeyA)
	if err != nil {
		return Report{}, fmt.Errorf("sign lab receipt: %w", err)
	}
	quorumEnvelope, err := attestation.AddSignature(singleSignature, privateKeyB)
	if err != nil {
		return Report{}, fmt.Errorf("co-sign lab receipt: %w", err)
	}
	duplicateEnvelope := cloneEnvelope(singleSignature)
	duplicateEnvelope.Signatures = append(duplicateEnvelope.Signatures, duplicateEnvelope.Signatures[0])
	spoofedHints := cloneEnvelope(quorumEnvelope)
	for index := range spoofedHints.Signatures {
		spoofedHints.Signatures[index].KeyID = "untrusted-hint"
	}
	tamperedEnvelope := cloneEnvelope(quorumEnvelope)
	payload, err := base64.StdEncoding.DecodeString(tamperedEnvelope.Payload)
	if err != nil {
		return Report{}, fmt.Errorf("decode lab payload: %w", err)
	}
	payload[len(payload)/2] ^= 1
	tamperedEnvelope.Payload = base64.StdEncoding.EncodeToString(payload)
	staleBase := expected
	staleBase.BaseSHA = strings.Repeat("d", 40)
	threshold := acceptance.Ed25519ThresholdEvaluator{
		PublicKeys: []ed25519.PublicKey{publicKeyA, publicKeyB},
		Threshold:  2,
	}
	scenarios := []scenario{
		{
			name:         "single trusted signature",
			source:       proofSource{envelope: singleSignature, found: true},
			evaluator:    acceptance.Ed25519Evaluator{PublicKey: publicKeyA},
			expected:     expected,
			expectedCode: "accepted",
		},
		{
			name:         "missing proof",
			source:       proofSource{},
			evaluator:    threshold,
			expected:     expected,
			expectedCode: "proof_missing",
		},
		{
			name:         "proof lookup failure",
			source:       proofSource{err: errors.New("lab index failure")},
			evaluator:    threshold,
			expected:     expected,
			expectedCode: "malformed_receipt",
		},
		{
			name:         "one signer cannot satisfy quorum",
			source:       proofSource{envelope: singleSignature, found: true},
			evaluator:    threshold,
			expected:     expected,
			expectedCode: "untrusted_signer",
		},
		{
			name:         "duplicate signer cannot satisfy quorum",
			source:       proofSource{envelope: duplicateEnvelope, found: true},
			evaluator:    threshold,
			expected:     expected,
			expectedCode: "untrusted_signer",
		},
		{
			name:         "two independent signatures satisfy quorum",
			source:       proofSource{envelope: quorumEnvelope, found: true},
			evaluator:    threshold,
			expected:     expected,
			expectedCode: "accepted",
		},
		{
			name:         "key ID hints do not control trust",
			source:       proofSource{envelope: spoofedHints, found: true},
			evaluator:    threshold,
			expected:     expected,
			expectedCode: "accepted",
		},
		{
			name:         "quorum cannot authorize a stale base",
			source:       proofSource{envelope: quorumEnvelope, found: true},
			evaluator:    threshold,
			expected:     staleBase,
			expectedCode: "base_mismatch",
		},
		{
			name:         "tampered quorum payload",
			source:       proofSource{envelope: tamperedEnvelope, found: true},
			evaluator:    threshold,
			expected:     expected,
			expectedCode: "untrusted_signer",
		},
	}
	report := Report{
		SchemaVersion: ReportSchema,
		Experiment:    "ed25519-threshold-acceptance",
		Passed:        true,
		Scenarios:     make([]ScenarioResult, 0, len(scenarios)),
	}
	for _, candidate := range scenarios {
		decision := acceptance.Evaluate(candidate.source, candidate.evaluator, candidate.expected)
		result := ScenarioResult{
			Name:         candidate.name,
			Accepted:     decision.Accepted,
			Code:         decision.Code,
			ExpectedCode: candidate.expectedCode,
			Passed:       decision.Code == candidate.expectedCode && decision.Accepted == (candidate.expectedCode == "accepted"),
		}
		report.Passed = report.Passed && result.Passed
		report.Scenarios = append(report.Scenarios, result)
	}
	return report, nil
}

func cloneEnvelope(envelope attestation.Envelope) attestation.Envelope {
	envelope.Signatures = append([]attestation.Signature(nil), envelope.Signatures...)
	return envelope
}
