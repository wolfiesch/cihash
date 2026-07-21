package attestation

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

const (
	PayloadType   = "application/vnd.in-toto+json"
	StatementType = "https://in-toto.io/Statement/v1"
	PredicateType = "https://cihash.dev/attestation/test-result/v0.1"
	SchemaVersion = "0.1"
)

type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}

type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

type Statement struct {
	Type          string     `json:"_type"`
	Subject       []Subject  `json:"subject"`
	PredicateType string     `json:"predicateType"`
	Predicate     TestResult `json:"predicate"`
}

type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type TestResult struct {
	SchemaVersion     string      `json:"schemaVersion"`
	Repository        string      `json:"repository"`
	HeadSHA           string      `json:"headSha"`
	BaseSHA           string      `json:"baseSha"`
	TreeSHA           string      `json:"treeSha"`
	Profile           string      `json:"profile"`
	PolicyDigest      string      `json:"policyDigest"`
	WorkflowDigest    string      `json:"workflowDigest"`
	EnvironmentDigest string      `json:"environmentDigest"`
	Architecture      string      `json:"architecture"`
	Jobs              []JobResult `json:"jobs"`
	Conclusion        string      `json:"conclusion"`
	Nonce             string      `json:"nonce"`
	IssuedAt          time.Time   `json:"issuedAt"`
	ExpiresAt         time.Time   `json:"expiresAt"`
}

type JobResult struct {
	Name        string    `json:"name"`
	Command     []string  `json:"command"`
	ExitCode    int       `json:"exitCode"`
	Conclusion  string    `json:"conclusion"`
	StartedAt   time.Time `json:"startedAt"`
	CompletedAt time.Time `json:"completedAt"`
	LogDigest   string    `json:"logDigest"`
}

func NewStatement(result TestResult) Statement {
	return Statement{
		Type: StatementType,
		Subject: []Subject{{
			Name:   result.Repository,
			Digest: map[string]string{"gitCommit": result.HeadSHA},
		}},
		PredicateType: PredicateType,
		Predicate:     result,
	}
}

func Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func ValidateDigest(value string) error {
	const prefix = "sha256:"
	if len(value) != len(prefix)+sha256.Size*2 || value[:len(prefix)] != prefix {
		return fmt.Errorf("expected sha256 digest")
	}
	if _, err := hex.DecodeString(value[len(prefix):]); err != nil {
		return fmt.Errorf("invalid sha256 digest: %w", err)
	}
	return nil
}
