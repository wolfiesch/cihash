package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/wolfiesch/cihash/internal/attestation"
)

var ErrConflict = errors.New("immutable evidence conflict")

type Identity struct {
	Repository        string `json:"repository"`
	HeadSHA           string `json:"headSha"`
	BaseSHA           string `json:"baseSha"`
	Profile           string `json:"profile"`
	PolicyDigest      string `json:"policyDigest"`
	WorkflowDigest    string `json:"workflowDigest"`
	EnvironmentDigest string `json:"environmentDigest"`
}

type runIndex struct {
	ReceiptDigest string `json:"receiptDigest"`
	IdentityKey   string `json:"identityKey"`
}

type identityIndex struct {
	ReceiptKey    string `json:"receiptKey"`
	ReceiptDigest string `json:"receiptDigest"`
	RunID         string `json:"runId,omitempty"`
}

type Evidence struct {
	Envelope      attestation.Envelope
	ReceiptPath   string
	ReceiptDigest string
	RunID         string
}

type Store struct {
	root string
}

func New(root string) Store {
	return Store{root: root}
}

// Save stores immutable receipt and log artifacts, then publishes the receipt
// as the current evidence for an exact lookup identity.
func (s Store) Save(identity Identity, envelope attestation.Envelope, log []byte) (receiptPath, logPath string, err error) {
	return s.save(identity, "", envelope, log)
}

// SaveForRun stores immutable artifacts and an immutable run binding before
// atomically publishing the receipt for lookup. A run ID may bind only one
// byte-for-byte receipt; a later authorized run may refresh the same identity.
func (s Store) SaveForRun(runID string, identity Identity, envelope attestation.Envelope, log []byte) (receiptPath, logPath string, err error) {
	if runID == "" {
		return "", "", fmt.Errorf("run ID is required")
	}
	return s.save(identity, runID, envelope, log)
}

func (s Store) save(identity Identity, runID string, envelope attestation.Envelope, log []byte) (receiptPath, logPath string, err error) {
	envelopeData, err := attestation.MarshalEnvelope(envelope)
	if err != nil {
		return "", "", err
	}
	identityKey, err := identity.Key()
	if err != nil {
		return "", "", err
	}
	receiptKey := digest(envelopeData)
	receiptDigest := attestation.Digest(envelopeData)
	receiptsDir := filepath.Join(s.root, "receipts")
	identitiesDir := filepath.Join(s.root, "identities")
	logsDir := filepath.Join(s.root, "logs")
	if err := os.MkdirAll(receiptsDir, 0o750); err != nil {
		return "", "", fmt.Errorf("create receipt directory: %w", err)
	}
	if err := os.Chmod(receiptsDir, 0o750|os.ModeSetgid); err != nil {
		return "", "", fmt.Errorf("set receipt directory mode: %w", err)
	}
	if err := os.MkdirAll(identitiesDir, 0o700); err != nil {
		return "", "", fmt.Errorf("create evidence identity directory: %w", err)
	}
	if err := os.MkdirAll(logsDir, 0o700); err != nil {
		return "", "", fmt.Errorf("create log directory: %w", err)
	}
	receiptPath = filepath.Join(receiptsDir, receiptKey+".json")
	logPath = filepath.Join(logsDir, receiptKey+".log")
	if err := writeImmutable(logPath, log, 0o600); err != nil {
		return "", "", err
	}
	if err := writeImmutable(receiptPath, envelopeData, 0o640); err != nil {
		return "", "", err
	}
	if runID != "" {
		runsDir := filepath.Join(s.root, "runs")
		if err := os.MkdirAll(runsDir, 0o700); err != nil {
			return "", "", fmt.Errorf("create run evidence directory: %w", err)
		}
		indexData, err := json.Marshal(runIndex{ReceiptDigest: receiptDigest, IdentityKey: identityKey})
		if err != nil {
			return "", "", fmt.Errorf("encode run evidence index: %w", err)
		}
		if err := writeImmutable(filepath.Join(runsDir, digest([]byte(runID))+".json"), indexData, 0o600); err != nil {
			return "", "", err
		}
	}
	indexData, err := json.Marshal(identityIndex{ReceiptKey: receiptKey, ReceiptDigest: receiptDigest, RunID: runID})
	if err != nil {
		return "", "", fmt.Errorf("encode evidence identity index: %w", err)
	}
	if err := writeAtomic(filepath.Join(identitiesDir, identityKey+".json"), indexData, 0o600); err != nil {
		return "", "", err
	}
	return receiptPath, logPath, nil
}

func (s Store) Lookup(identity Identity) (attestation.Envelope, string, bool, error) {
	evidence, found, err := s.LookupEvidence(identity)
	return evidence.Envelope, evidence.ReceiptPath, found, err
}

func (s Store) LookupEvidence(identity Identity) (Evidence, bool, error) {
	key, err := identity.Key()
	if err != nil {
		return Evidence{}, false, err
	}
	indexPath := filepath.Join(s.root, "identities", key+".json")
	indexData, err := os.ReadFile(indexPath)
	if errors.Is(err, os.ErrNotExist) {
		return Evidence{ReceiptPath: indexPath}, false, nil
	}
	if err != nil {
		return Evidence{ReceiptPath: indexPath}, false, fmt.Errorf("read evidence identity index: %w", err)
	}
	var index identityIndex
	if err := json.Unmarshal(indexData, &index); err != nil ||
		!validKey(index.ReceiptKey) ||
		index.ReceiptDigest != "sha256:"+index.ReceiptKey {
		return Evidence{ReceiptPath: indexPath}, false, fmt.Errorf("decode evidence identity index")
	}
	receiptPath := filepath.Join(s.root, "receipts", index.ReceiptKey+".json")
	data, err := os.ReadFile(receiptPath)
	if err != nil {
		return Evidence{ReceiptPath: receiptPath}, false, fmt.Errorf("read receipt: %w", err)
	}
	if attestation.Digest(data) != index.ReceiptDigest {
		return Evidence{ReceiptPath: receiptPath}, false, fmt.Errorf("receipt digest does not match evidence index")
	}
	envelope, err := attestation.UnmarshalEnvelope(data)
	if err != nil {
		return Evidence{ReceiptPath: receiptPath}, false, err
	}
	if index.RunID != "" {
		runData, err := os.ReadFile(filepath.Join(s.root, "runs", digest([]byte(index.RunID))+".json"))
		if err != nil {
			return Evidence{ReceiptPath: receiptPath}, false, fmt.Errorf("read run evidence index: %w", err)
		}
		var run runIndex
		if err := json.Unmarshal(runData, &run); err != nil ||
			run.IdentityKey != key ||
			run.ReceiptDigest != index.ReceiptDigest {
			return Evidence{ReceiptPath: receiptPath}, false, fmt.Errorf("run evidence binding does not match identity index")
		}
	}
	return Evidence{
		Envelope:      envelope,
		ReceiptPath:   receiptPath,
		ReceiptDigest: index.ReceiptDigest,
		RunID:         index.RunID,
	}, true, nil
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

func validKey(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, character := range value {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return false
		}
	}
	return true
}

func writeImmutable(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if errors.Is(err, os.ErrExist) {
		existing, readErr := os.ReadFile(path)
		if readErr != nil {
			return fmt.Errorf("read existing immutable evidence: %w", readErr)
		}
		if bytes.Equal(existing, data) {
			return nil
		}
		return ErrConflict
	}
	if err != nil {
		return fmt.Errorf("create immutable evidence: %w", err)
	}
	if err := file.Chmod(mode); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return fmt.Errorf("set immutable evidence mode: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return fmt.Errorf("write immutable evidence: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return fmt.Errorf("sync immutable evidence: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close immutable evidence: %w", err)
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	return nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".cihash-index-*")
	if err != nil {
		return fmt.Errorf("create temporary evidence index: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("set evidence index mode: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write evidence index: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync evidence index: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close evidence index: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace evidence index: %w", err)
	}
	return syncDirectory(filepath.Dir(path))
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open evidence directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync evidence directory: %w", err)
	}
	return nil
}
