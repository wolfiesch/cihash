package lab

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/wolfiesch/cihash/internal/attestation"
	"github.com/wolfiesch/cihash/internal/confirmer"
)

func RunConfirmer() (Report, error) {
	publicKeyA, privateKeyA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Report{}, fmt.Errorf("generate first lab signer: %w", err)
	}
	publicKeyB, privateKeyB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Report{}, fmt.Errorf("generate second lab signer: %w", err)
	}
	domains := []confirmer.TrustDomain{
		{Name: "runner-a", ReceiptKey: publicKeyA},
		{Name: "runner-b", ReceiptKey: publicKeyB},
	}
	now := time.Date(2026, time.July, 20, 12, 0, 0, 0, time.UTC)
	resultA := confirmerResult(now)
	resultB := confirmerResult(now.Add(23 * time.Minute))
	resultB.Nonce = "independent-lab-nonce"
	observationA, err := confirmerObservation("runner-a", resultA, privateKeyA, publicKeyA)
	if err != nil {
		return Report{}, err
	}
	observationB, err := confirmerObservation("runner-b", resultB, privateKeyB, publicKeyB)
	if err != nil {
		return Report{}, err
	}
	agreement, err := confirmer.SignAgreement(observationA, observationB, privateKeyA)
	if err != nil {
		return Report{}, fmt.Errorf("sign lab agreement: %w", err)
	}
	quorumAgreement, err := confirmer.AddAgreementSignature(agreement, observationA, observationB, privateKeyB)
	if err != nil {
		return Report{}, fmt.Errorf("co-sign lab agreement: %w", err)
	}
	duplicateDomain, err := confirmerObservation("runner-a", resultB, privateKeyB, publicKeyB)
	if err != nil {
		return Report{}, err
	}
	sameSigner, err := confirmerObservation("runner-b", resultB, privateKeyA, publicKeyA)
	if err != nil {
		return Report{}, err
	}
	unapprovedDomains := []confirmer.TrustDomain{
		{Name: "renamed-runner", ReceiptKey: publicKeyA},
		{Name: "runner-b", ReceiptKey: publicKeyB},
	}
	commandResult := resultB
	commandResult.Jobs = append([]attestation.JobResult(nil), resultB.Jobs...)
	commandResult.Jobs[0].Command = []string{"go", "test", "./internal/..."}
	commandObservation, err := confirmerObservation("runner-b", commandResult, privateKeyB, publicKeyB)
	if err != nil {
		return Report{}, err
	}
	logResult := resultB
	logResult.Jobs = append([]attestation.JobResult(nil), resultB.Jobs...)
	logResult.Jobs[0].LogDigest = attestation.Digest([]byte("different-lab-log"))
	logObservation, err := confirmerObservation("runner-b", logResult, privateKeyB, publicKeyB)
	if err != nil {
		return Report{}, err
	}
	tamperedAgreement := cloneEnvelope(quorumAgreement)
	payload, err := base64.StdEncoding.DecodeString(tamperedAgreement.Payload)
	if err != nil {
		return Report{}, fmt.Errorf("decode lab agreement payload: %w", err)
	}
	payload[len(payload)/2] ^= 1
	tamperedAgreement.Payload = base64.StdEncoding.EncodeToString(payload)
	cases := []struct {
		name     string
		accepted bool
		run      func() error
	}{
		{
			name:     "independent timestamps agree with 2-of-2 confirmation",
			accepted: true,
			run: func() error {
				_, err := confirmer.VerifyAgreement(quorumAgreement, domains)
				return err
			},
		},
		{
			name:     "duplicate evidence trust domain rejects",
			accepted: false,
			run: func() error {
				_, err := confirmer.BuildAgreement(observationA, duplicateDomain)
				return err
			},
		},
		{
			name:     "one receipt signer across two domain labels rejects",
			accepted: false,
			run: func() error {
				_, err := confirmer.BuildAgreement(observationA, sameSigner)
				return err
			},
		},
		{
			name:     "unapproved trust-domain binding rejects",
			accepted: false,
			run: func() error {
				_, err := confirmer.VerifyAgreement(quorumAgreement, unapprovedDomains)
				return err
			},
		},
		{
			name:     "command divergence rejects",
			accepted: false,
			run: func() error {
				_, err := confirmer.BuildAgreement(observationA, commandObservation)
				return err
			},
		},
		{
			name:     "log divergence rejects",
			accepted: false,
			run: func() error {
				_, err := confirmer.BuildAgreement(observationA, logObservation)
				return err
			},
		},
		{
			name:     "missing agreement quorum rejects",
			accepted: false,
			run: func() error {
				_, err := confirmer.VerifyAgreement(agreement, domains)
				return err
			},
		},
		{
			name:     "tampered agreement rejects",
			accepted: false,
			run: func() error {
				_, err := confirmer.VerifyAgreement(tamperedAgreement, domains)
				return err
			},
		},
	}
	report := Report{
		SchemaVersion: ReportSchema,
		Experiment:    "independent-receipt-confirmer",
		Passed:        true,
		Scenarios:     make([]ScenarioResult, 0, len(cases)),
	}
	for _, candidate := range cases {
		err := candidate.run()
		accepted := err == nil
		code := "rejected"
		if accepted {
			code = "accepted"
		}
		expectedCode := "rejected"
		if candidate.accepted {
			expectedCode = "accepted"
		}
		result := ScenarioResult{
			Name:         candidate.name,
			Accepted:     accepted,
			Code:         code,
			ExpectedCode: expectedCode,
			Passed:       accepted == candidate.accepted,
		}
		report.Passed = report.Passed && result.Passed
		report.Scenarios = append(report.Scenarios, result)
	}
	return report, nil
}

func confirmerObservation(domain string, result attestation.TestResult, privateKey ed25519.PrivateKey, publicKey ed25519.PublicKey) (confirmer.Observation, error) {
	envelope, err := attestation.Sign(attestation.NewStatement(result), privateKey)
	if err != nil {
		return confirmer.Observation{}, fmt.Errorf("sign lab receipt: %w", err)
	}
	observation, err := confirmer.VerifyObservation(confirmer.TrustDomain{Name: domain, ReceiptKey: publicKey}, envelope)
	if err != nil {
		return confirmer.Observation{}, fmt.Errorf("verify lab receipt: %w", err)
	}
	return observation, nil
}

func confirmerResult(now time.Time) attestation.TestResult {
	return attestation.TestResult{
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
			Command:     []string{"go", "test", "./..."},
			ExitCode:    0,
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
}
