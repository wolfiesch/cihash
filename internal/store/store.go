package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/wolfiesch/cihash/internal/attestation"
)

type Identity struct {
	Repository        string `json:"repository"`
	HeadSHA           string `json:"headSha"`
	BaseSHA           string `json:"baseSha"`
	Profile           string `json:"profile"`
	PolicyDigest      string `json:"policyDigest"`
	WorkflowDigest    string `json:"workflowDigest"`
	EnvironmentDigest string `json:"environmentDigest"`
}

type Store struct {
	root string
}

func New(root string) Store {
	return Store{root: root}
}

func (s Store) Save(identity Identity, envelope attestation.Envelope, log []byte) (receiptPath, logPath string, err error) {
	envelopeData, err := attestation.MarshalEnvelope(envelope)
	if err != nil {
		return "", "", err
	}
	key, err := identity.Key()
	if err != nil {
		return "", "", err
	}
	receiptID := digest(envelopeData)
	receiptsDir := filepath.Join(s.root, "receipts")
	logsDir := filepath.Join(s.root, "logs")
	if err := os.MkdirAll(receiptsDir, 0o700); err != nil {
		return "", "", fmt.Errorf("create receipt directory: %w", err)
	}
	if err := os.MkdirAll(logsDir, 0o700); err != nil {
		return "", "", fmt.Errorf("create log directory: %w", err)
	}
	receiptPath = filepath.Join(receiptsDir, key+".json")
	logPath = filepath.Join(logsDir, receiptID+".log")
	if err := atomicWrite(logPath, log, 0o600); err != nil {
		return "", "", err
	}
	if err := atomicWrite(receiptPath, envelopeData, 0o600); err != nil {
		return "", "", err
	}
	return receiptPath, logPath, nil
}

func (s Store) Lookup(identity Identity) (attestation.Envelope, string, bool, error) {
	key, err := identity.Key()
	if err != nil {
		return attestation.Envelope{}, "", false, err
	}
	path := filepath.Join(s.root, "receipts", key+".json")
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return attestation.Envelope{}, path, false, nil
	}
	if err != nil {
		return attestation.Envelope{}, path, false, fmt.Errorf("read receipt: %w", err)
	}
	envelope, err := attestation.UnmarshalEnvelope(data)
	if err != nil {
		return attestation.Envelope{}, path, false, err
	}
	return envelope, path, true, nil
}

func (identity Identity) Key() (string, error) {
	data, err := json.Marshal(identity)
	if err != nil {
		return "", fmt.Errorf("marshal receipt identity: %w", err)
	}
	return digest(data), nil
}

func IdentityFromResult(result attestation.TestResult) Identity {
	return Identity{
		Repository:        result.Repository,
		HeadSHA:           result.HeadSHA,
		BaseSHA:           result.BaseSHA,
		Profile:           result.Profile,
		PolicyDigest:      result.PolicyDigest,
		WorkflowDigest:    result.WorkflowDigest,
		EnvironmentDigest: result.EnvironmentDigest,
	}
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".cihash-*")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("set temporary file mode: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write temporary file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync temporary file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary file: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}
