package verifier

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/wolfiesch/cihash/internal/attestation"
)

type Expected struct {
	Repository        string
	HeadSHA           string
	BaseSHA           string
	Profile           string
	PolicyDigest      string
	WorkflowDigest    string
	EnvironmentDigest string
	Command           []string
	RequiredJobs      []string
	Nonce             string
	MaxAge            time.Duration
	Now               time.Time
	ClockSkew         time.Duration
}

type Decision struct {
	Accepted  bool                  `json:"accepted"`
	Code      string                `json:"code"`
	Message   string                `json:"message"`
	Statement attestation.Statement `json:"-"`
}

func Verify(envelope attestation.Envelope, publicKey ed25519.PublicKey, expected Expected) Decision {
	statement, err := attestation.VerifySignature(envelope, publicKey)
	if err != nil {
		return signatureDecision(err)
	}
	if decision := validateStatement(statement, expected); !decision.Accepted {
		return decision
	}
	return Decision{
		Accepted:  true,
		Code:      "accepted",
		Message:   "proof matches the required code, policy, workflow, and environment",
		Statement: statement,
	}
}

func validateStatement(statement attestation.Statement, expected Expected) Decision {
	if statement.Type != attestation.StatementType || statement.PredicateType != attestation.PredicateType || statement.Predicate.SchemaVersion != attestation.SchemaVersion {
		return reject("unsupported_version", "receipt uses an unsupported statement or predicate version")
	}
	predicate := statement.Predicate
	if len(statement.Subject) != 1 || statement.Subject[0].Name != predicate.Repository || statement.Subject[0].Digest["gitCommit"] != predicate.HeadSHA {
		return reject("subject_mismatch", "statement subject does not match its predicate")
	}
	if predicate.Repository != expected.Repository {
		return reject("repository_mismatch", "proof repository does not match the required repository")
	}
	if predicate.HeadSHA != expected.HeadSHA {
		return reject("head_mismatch", "proof head does not match the required commit")
	}
	if predicate.BaseSHA != expected.BaseSHA {
		return reject("base_mismatch", "proof base does not match the current base commit")
	}
	if predicate.Profile != expected.Profile {
		return reject("profile_mismatch", "proof profile does not match the approved profile")
	}
	if predicate.PolicyDigest != expected.PolicyDigest {
		return reject("policy_mismatch", "proof policy does not match the approved policy")
	}
	if predicate.WorkflowDigest != expected.WorkflowDigest {
		return reject("workflow_mismatch", "proof workflow does not match the approved workflow")
	}
	if predicate.EnvironmentDigest != expected.EnvironmentDigest {
		return reject("environment_mismatch", "proof environment does not match the approved environment")
	}
	if expected.Nonce != "" && predicate.Nonce != expected.Nonce {
		return reject("nonce_invalid", "proof nonce is not valid for this job")
	}
	if predicate.Nonce == "" {
		return reject("nonce_invalid", "proof nonce is missing")
	}
	if !validGitOID(predicate.HeadSHA) || !validGitOID(predicate.BaseSHA) || !validGitOID(predicate.TreeSHA) {
		return reject("malformed_receipt", "proof contains an invalid Git object identity")
	}
	for _, digest := range []string{predicate.PolicyDigest, predicate.WorkflowDigest, predicate.EnvironmentDigest} {
		if err := attestation.ValidateDigest(digest); err != nil {
			return reject("malformed_receipt", "proof contains an invalid SHA-256 digest")
		}
	}

	now := expected.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	skew := expected.ClockSkew
	if skew == 0 {
		skew = time.Minute
	}
	if predicate.IssuedAt.After(now.Add(skew)) {
		return reject("not_yet_valid", "proof issue time is in the future")
	}
	if !predicate.ExpiresAt.After(predicate.IssuedAt) {
		return reject("malformed_receipt", "proof expiry does not follow its issue time")
	}
	if !now.Before(predicate.ExpiresAt) {
		return reject("expired", "proof has expired")
	}
	if expected.MaxAge > 0 && predicate.ExpiresAt.Sub(predicate.IssuedAt) > expected.MaxAge {
		return reject("expired", "proof validity exceeds the approved maximum age")
	}

	if len(predicate.Jobs) != len(expected.RequiredJobs) {
		return reject("job_set_mismatch", "proof does not contain the complete required job set")
	}
	seen := make(map[string]struct{}, len(predicate.Jobs))
	for _, job := range predicate.Jobs {
		if _, duplicate := seen[job.Name]; duplicate {
			return reject("job_set_mismatch", "proof contains a duplicate job")
		}
		seen[job.Name] = struct{}{}
		if !slices.Contains(expected.RequiredJobs, job.Name) {
			return reject("job_set_mismatch", "proof contains an unapproved job")
		}
		if !slices.Equal(job.Command, expected.Command) {
			return reject("workflow_mismatch", "proof job command does not match the approved command")
		}
		if err := attestation.ValidateDigest(job.LogDigest); err != nil {
			return reject("malformed_receipt", "proof contains an invalid log digest")
		}
		if job.StartedAt.After(job.CompletedAt) || job.CompletedAt.After(predicate.IssuedAt.Add(skew)) {
			return reject("malformed_receipt", "proof contains invalid job timestamps")
		}
		if job.Conclusion != "success" || job.ExitCode != 0 {
			return reject("job_failed", fmt.Sprintf("required job %q did not succeed", job.Name))
		}
	}
	if predicate.Conclusion != "success" {
		return reject("proof_failed", "proof records an unsuccessful run")
	}
	return Decision{Accepted: true, Statement: statement}
}

func signatureDecision(err error) Decision {
	switch {
	case errors.Is(err, attestation.ErrUnsupportedVersion):
		return reject("unsupported_version", err.Error())
	case errors.Is(err, attestation.ErrUntrustedSigner):
		return reject("untrusted_signer", err.Error())
	case errors.Is(err, attestation.ErrInvalidSignature):
		return reject("invalid_signature", err.Error())
	default:
		return reject("malformed_receipt", err.Error())
	}
}

func reject(code, message string) Decision {
	return Decision{Code: code, Message: message}
}

func validGitOID(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
