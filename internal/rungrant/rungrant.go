// Package rungrant defines server-issued authorization for one CIHash execution.
package rungrant

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/wolfiesch/cihash/internal/attestation"
	"github.com/wolfiesch/cihash/internal/policy"
)

const SchemaVersion = "https://cihash.dev/run-grant/v0.1"

var ErrInvalidGrant = errors.New("invalid run grant")

type Grant struct {
	SchemaVersion     string        `json:"schemaVersion"`
	ID                string        `json:"id"`
	Policy            policy.Policy `json:"policy"`
	PolicyDigest      string        `json:"policyDigest"`
	WorkflowDigest    string        `json:"workflowDigest"`
	EnvironmentDigest string        `json:"environmentDigest"`
	Architecture      string        `json:"architecture"`
	HeadSHA           string        `json:"headSha"`
	BaseSHA           string        `json:"baseSha"`
	TreeSHA           string        `json:"treeSha"`
	Nonce             string        `json:"nonce"`
	IssuedAt          time.Time     `json:"issuedAt"`
	ExpiresAt         time.Time     `json:"expiresAt"`
}

func Issue(configuredPolicy policy.Policy, headSHA, baseSHA, treeSHA string, now time.Time) (Grant, error) {
	return issue(configuredPolicy, headSHA, baseSHA, treeSHA, now, rand.Reader)
}

func issue(configuredPolicy policy.Policy, headSHA, baseSHA, treeSHA string, now time.Time, entropy io.Reader) (Grant, error) {
	if err := configuredPolicy.Validate(); err != nil {
		return Grant{}, fmt.Errorf("%w: %v", ErrInvalidGrant, err)
	}
	policyDigest, err := configuredPolicy.Digest()
	if err != nil {
		return Grant{}, err
	}
	workflowDigest, err := configuredPolicy.WorkflowDigest()
	if err != nil {
		return Grant{}, err
	}
	id, err := randomValue(entropy)
	if err != nil {
		return Grant{}, fmt.Errorf("generate run ID: %w", err)
	}
	nonce, err := randomValue(entropy)
	if err != nil {
		return Grant{}, fmt.Errorf("generate run nonce: %w", err)
	}
	now = now.UTC()
	grant := Grant{
		SchemaVersion:     SchemaVersion,
		ID:                id,
		Policy:            clonePolicy(configuredPolicy),
		PolicyDigest:      policyDigest,
		WorkflowDigest:    workflowDigest,
		EnvironmentDigest: configuredPolicy.EnvironmentDigest(),
		Architecture:      configuredPolicy.Environment.Platform,
		HeadSHA:           headSHA,
		BaseSHA:           baseSHA,
		Nonce:             nonce,
		TreeSHA:           treeSHA,
		IssuedAt:          now,
		ExpiresAt:         now.Add(time.Duration(configuredPolicy.MaxAgeSeconds) * time.Second),
	}
	if err := grant.Validate(); err != nil {
		return Grant{}, err
	}
	return grant, nil
}

func (grant Grant) Validate() error {
	if grant.SchemaVersion != SchemaVersion {
		return invalid("unsupported schema version")
	}
	if !validRandomValue(grant.ID) || !validRandomValue(grant.Nonce) {
		return invalid("run ID and nonce must be 32-byte base64url values")
	}
	if grant.ID == grant.Nonce {
		return invalid("run ID and nonce must be distinct")
	}
	if err := grant.Policy.Validate(); err != nil {
		return invalid(err.Error())
	}
	if !validGitObjectID(grant.HeadSHA) ||
		!validGitObjectID(grant.BaseSHA) ||
		!validGitObjectID(grant.TreeSHA) ||
		len(grant.HeadSHA) != len(grant.BaseSHA) ||
		len(grant.HeadSHA) != len(grant.TreeSHA) {
		return invalid("head, base, and tree must use matching Git object IDs")
	}
	if grant.Architecture != grant.Policy.Environment.Platform {
		return invalid("architecture does not match the approved environment")
	}
	if grant.IssuedAt.IsZero() || !grant.ExpiresAt.After(grant.IssuedAt) {
		return invalid("grant validity window is invalid")
	}
	if grant.ExpiresAt.Sub(grant.IssuedAt) != time.Duration(grant.Policy.MaxAgeSeconds)*time.Second {
		return invalid("grant validity window does not match policy")
	}
	policyDigest, err := grant.Policy.Digest()
	if err != nil {
		return invalid(err.Error())
	}
	workflowDigest, err := grant.Policy.WorkflowDigest()
	if err != nil {
		return invalid(err.Error())
	}
	if grant.PolicyDigest != policyDigest || grant.WorkflowDigest != workflowDigest || grant.EnvironmentDigest != grant.Policy.EnvironmentDigest() {
		return invalid("grant digests do not match the approved policy")
	}
	for _, digest := range []string{grant.PolicyDigest, grant.WorkflowDigest, grant.EnvironmentDigest} {
		if err := attestation.ValidateDigest(digest); err != nil {
			return invalid(err.Error())
		}
	}
	return nil
}

func clonePolicy(configured policy.Policy) policy.Policy {
	configured.Command = append([]string(nil), configured.Command...)
	return configured
}

func randomValue(source io.Reader) (string, error) {
	value := make([]byte, 32)
	if _, err := io.ReadFull(source, value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func validRandomValue(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func validGitObjectID(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') && (character < 'A' || character > 'F') {
			return false
		}
	}
	return true
}

func invalid(message string) error {
	return fmt.Errorf("%w: %s", ErrInvalidGrant, message)
}
