package hosted

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

const deliveryLease = 15 * time.Minute

type StateStore struct {
	root string
}

type FallbackState struct {
	ID             string     `json:"id"`
	Repository     string     `json:"repository"`
	InstallationID int64      `json:"installationId"`
	CheckRunID     int64      `json:"checkRunId"`
	WorkflowRunID  int64      `json:"workflowRunId,omitempty"`
	HeadSHA        string     `json:"headSha"`
	BaseSHA        string     `json:"baseSha"`
	BaseRef        string     `json:"baseRef"`
	PolicyDigest   string     `json:"policyDigest"`
	ExternalID     string     `json:"externalId"`
	CreatedAt      time.Time  `json:"createdAt"`
	ExpiresAt      time.Time  `json:"expiresAt"`
	CompletedAt    *time.Time `json:"completedAt,omitempty"`
	Conclusion     string     `json:"conclusion,omitempty"`
}

func NewStateStore(root string) StateStore {
	return StateStore{root: root}
}

func (store StateStore) BeginDelivery(deliveryID string) (bool, error) {
	if deliveryID == "" {
		return false, fmt.Errorf("GitHub delivery ID is required")
	}
	directory := filepath.Join(store.root, "deliveries")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return false, fmt.Errorf("create delivery state directory: %w", err)
	}
	key := digestName(deliveryID)
	if _, err := os.Stat(filepath.Join(directory, key+".done")); err == nil {
		return false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("inspect completed delivery: %w", err)
	}
	inflightPath := filepath.Join(directory, key+".inflight")
	for {
		file, err := os.OpenFile(inflightPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, os.ErrExist) {
			info, statErr := os.Stat(inflightPath)
			if statErr != nil {
				return false, fmt.Errorf("inspect in-flight delivery: %w", statErr)
			}
			if time.Since(info.ModTime()) < deliveryLease {
				return false, nil
			}
			if err := os.Remove(inflightPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				return false, fmt.Errorf("reclaim stale delivery: %w", err)
			}
			continue
		}
		if err != nil {
			return false, fmt.Errorf("begin delivery: %w", err)
		}
		if _, err := file.WriteString(deliveryID + "\n"); err != nil {
			_ = file.Close()
			_ = os.Remove(inflightPath)
			return false, fmt.Errorf("record delivery: %w", err)
		}
		if err := file.Close(); err != nil {
			_ = os.Remove(inflightPath)
			return false, fmt.Errorf("close delivery state: %w", err)
		}
		return true, nil
	}
}

func (store StateStore) CompleteDelivery(deliveryID string) error {
	directory := filepath.Join(store.root, "deliveries")
	key := digestName(deliveryID)
	if err := os.Rename(filepath.Join(directory, key+".inflight"), filepath.Join(directory, key+".done")); err != nil {
		return fmt.Errorf("complete delivery: %w", err)
	}
	return nil
}

func (store StateStore) FailDelivery(deliveryID string) {
	_ = os.Remove(filepath.Join(store.root, "deliveries", digestName(deliveryID)+".inflight"))
}

func (store StateStore) CreateFallback(state FallbackState) error {
	if state.ID == "" || state.CheckRunID <= 0 || state.InstallationID <= 0 || state.ExpiresAt.IsZero() {
		return fmt.Errorf("fallback state is incomplete")
	}
	directory := filepath.Join(store.root, "fallbacks")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create fallback state directory: %w", err)
	}
	path := filepath.Join(directory, digestName(state.ID)+".json")
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("fallback state already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect fallback state: %w", err)
	}
	return writeJSONAtomic(path, state)
}

func (store StateStore) BindWorkflowRun(fallbackID string, workflowRunID int64) error {
	if workflowRunID <= 0 {
		return fmt.Errorf("workflow run ID is required")
	}
	state, path, err := store.loadFallback(fallbackID)
	if err != nil {
		return err
	}
	if state.WorkflowRunID != 0 && state.WorkflowRunID != workflowRunID {
		return fmt.Errorf("fallback is already bound to another workflow run")
	}
	state.WorkflowRunID = workflowRunID
	if err := writeJSONAtomic(path, state); err != nil {
		return err
	}
	indexDirectory := filepath.Join(store.root, "workflow-runs")
	if err := os.MkdirAll(indexDirectory, 0o700); err != nil {
		return fmt.Errorf("create workflow-run index: %w", err)
	}
	return writeBytesAtomic(filepath.Join(indexDirectory, strconv.FormatInt(workflowRunID, 10)), []byte(fallbackID+"\n"), 0o600)
}

func (store StateStore) LookupWorkflowRun(workflowRunID int64) (FallbackState, bool, error) {
	indexPath := filepath.Join(store.root, "workflow-runs", strconv.FormatInt(workflowRunID, 10))
	fallbackID, err := os.ReadFile(indexPath)
	if errors.Is(err, os.ErrNotExist) {
		return FallbackState{}, false, nil
	}
	if err != nil {
		return FallbackState{}, false, fmt.Errorf("read workflow-run index: %w", err)
	}
	state, _, err := store.loadFallback(stringTrimSpace(fallbackID))
	if err != nil {
		return FallbackState{}, false, err
	}
	return state, true, nil
}

func (store StateStore) CompleteFallback(fallbackID, conclusion string, completedAt time.Time) error {
	state, path, err := store.loadFallback(fallbackID)
	if err != nil {
		return err
	}
	if state.CompletedAt != nil {
		if state.Conclusion == conclusion {
			return nil
		}
		return fmt.Errorf("fallback already completed with %q", state.Conclusion)
	}
	completedAt = completedAt.UTC()
	state.CompletedAt = &completedAt
	state.Conclusion = conclusion
	return writeJSONAtomic(path, state)
}

func (store StateStore) loadFallback(fallbackID string) (FallbackState, string, error) {
	path := filepath.Join(store.root, "fallbacks", digestName(fallbackID)+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		return FallbackState{}, path, fmt.Errorf("read fallback state: %w", err)
	}
	var state FallbackState
	if err := json.Unmarshal(data, &state); err != nil {
		return FallbackState{}, path, fmt.Errorf("decode fallback state: %w", err)
	}
	if state.ID != fallbackID {
		return FallbackState{}, path, fmt.Errorf("fallback state identity mismatch")
	}
	return state, path, nil
}

func writeJSONAtomic(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	return writeBytesAtomic(path, append(data, '\n'), 0o600)
}

func writeBytesAtomic(path string, data []byte, mode os.FileMode) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".cihash-*")
	if err != nil {
		return fmt.Errorf("create temporary state: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("set state mode: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write state: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync state: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close state: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace state: %w", err)
	}
	return nil
}

func digestName(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func stringTrimSpace(value []byte) string {
	start := 0
	for start < len(value) && (value[start] == ' ' || value[start] == '\n' || value[start] == '\r' || value[start] == '\t') {
		start++
	}
	end := len(value)
	for end > start && (value[end-1] == ' ' || value[end-1] == '\n' || value[end-1] == '\r' || value[end-1] == '\t') {
		end--
	}
	return string(value[start:end])
}
