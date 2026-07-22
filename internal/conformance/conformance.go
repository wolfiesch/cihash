// Package conformance checks unsigned producer output against a server-issued
// CIHash run grant. Conformance never authorizes a GitHub check; acceptance
// still requires a trusted signer and the normal receipt verification path.
package conformance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/wolfiesch/cihash/internal/attestation"
	"github.com/wolfiesch/cihash/internal/rungrant"
	"github.com/wolfiesch/cihash/internal/verifier"
)

const SchemaVersion = "https://cihash.dev/producer-conformance/v0.2"

type Report struct {
	SchemaVersion   string `json:"schemaVersion"`
	Conformant      bool   `json:"conformant"`
	SigningEligible bool   `json:"signingEligible"`
	ResultSucceeded bool   `json:"resultSucceeded"`
	Code            string `json:"code"`
	Message         string `json:"message"`
}

func Check(grant rungrant.Grant, result attestation.TestResult, now time.Time) Report {
	if err := grant.Validate(); err != nil {
		return Report{SchemaVersion: SchemaVersion, Code: "invalid_grant", Message: err.Error()}
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	expected := verifier.Expected{
		Repository:        grant.Policy.Repository,
		HeadSHA:           grant.HeadSHA,
		BaseSHA:           grant.BaseSHA,
		TreeSHA:           grant.TreeSHA,
		Profile:           grant.Policy.Profile,
		PolicyDigest:      grant.PolicyDigest,
		WorkflowDigest:    grant.WorkflowDigest,
		EnvironmentDigest: grant.EnvironmentDigest,
		Architecture:      grant.Architecture,
		Jobs: []verifier.ExpectedJob{{
			Name:    grant.Policy.Profile,
			Command: append([]string(nil), grant.Policy.Command...),
		}},
		Nonce:     grant.Nonce,
		MaxAge:    grant.ExpiresAt.Sub(grant.IssuedAt),
		NotBefore: grant.IssuedAt,
		ExpiresAt: grant.ExpiresAt,
		Now:       now.UTC(),
	}
	decision := verifier.ValidateUnsignedResult(result, expected)
	conformant := decision.Accepted || decision.Code == "job_failed" || decision.Code == "proof_failed"
	code, message := decision.Code, decision.Message
	if decision.Accepted {
		code = "conformant"
		message = "producer result matches the server-issued grant"
	}
	return Report{
		SchemaVersion:   SchemaVersion,
		Conformant:      conformant,
		SigningEligible: conformant,
		ResultSucceeded: decision.Accepted,
		Code:            code,
		Message:         message,
	}
}

func Load(path string, destination any) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 1<<20+1))
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) > 1<<20 {
		return fmt.Errorf("read %s: file exceeds 1 MiB", path)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("decode %s: trailing data", path)
	}
	return nil
}
