package rungrant

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/wolfiesch/cihash/internal/attestation"
)

var (
	ErrNotFound           = errors.New("run grant not found")
	ErrGrantExpired       = errors.New("run grant expired")
	ErrLifecycleConflict  = errors.New("run grant lifecycle conflict")
	ErrConcurrentMutation = errors.New("run grant is being updated")
)

type Status string

const (
	StatusIssued    Status = "issued"
	StatusSubmitted Status = "submitted"
	StatusConsumed  Status = "consumed"
	StatusExpired   Status = "expired"
)

type Record struct {
	Grant         Grant      `json:"grant"`
	Status        Status     `json:"status"`
	ReceiptDigest string     `json:"receiptDigest,omitempty"`
	SubmittedAt   *time.Time `json:"submittedAt,omitempty"`
	ConsumedAt    *time.Time `json:"consumedAt,omitempty"`
}

type Store struct {
	root string
}

func NewStore(root string) Store {
	return Store{root: root}
}

func (store Store) Create(grant Grant) (Record, error) {
	if err := grant.Validate(); err != nil {
		return Record{}, err
	}
	if err := store.ensureDirectory(); err != nil {
		return Record{}, err
	}
	record := Record{Grant: grant, Status: StatusIssued}
	data, err := marshalRecord(record)
	if err != nil {
		return Record{}, err
	}
	file, err := os.OpenFile(store.recordPath(grant.ID), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return Record{}, fmt.Errorf("%w: run ID already exists", ErrLifecycleConflict)
	}
	if err != nil {
		return Record{}, fmt.Errorf("create run grant: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		_ = os.Remove(store.recordPath(grant.ID))
		return Record{}, fmt.Errorf("write run grant: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(store.recordPath(grant.ID))
		return Record{}, fmt.Errorf("sync run grant: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(store.recordPath(grant.ID))
		return Record{}, fmt.Errorf("close run grant: %w", err)
	}
	if err := syncDirectory(store.directory()); err != nil {
		return Record{}, err
	}
	return record, nil
}

func (store Store) Lookup(id string, now time.Time) (Record, bool, error) {
	record, err := store.load(id)
	if errors.Is(err, ErrNotFound) {
		return Record{}, false, nil
	}
	if err != nil {
		return Record{}, false, err
	}
	return effectiveRecord(record, now), true, nil
}

func (store Store) MarkSubmitted(id, receiptDigest string, submittedAt time.Time) (Record, error) {
	if err := attestation.ValidateDigest(receiptDigest); err != nil {
		return Record{}, fmt.Errorf("invalid receipt digest: %w", err)
	}
	return store.mutate(id, func(record *Record) error {
		if !submittedAt.Before(record.Grant.ExpiresAt) {
			return ErrGrantExpired
		}
		switch record.Status {
		case StatusIssued:
			if submittedAt.Before(record.Grant.IssuedAt) {
				return fmt.Errorf("%w: submission predates issuance", ErrLifecycleConflict)
			}
			submittedAt = submittedAt.UTC()
			record.Status = StatusSubmitted
			record.ReceiptDigest = receiptDigest
			record.SubmittedAt = &submittedAt
			return nil
		case StatusSubmitted, StatusConsumed:
			if record.ReceiptDigest == receiptDigest {
				return nil
			}
			return fmt.Errorf("%w: run is bound to another receipt", ErrLifecycleConflict)
		default:
			return fmt.Errorf("%w: cannot submit a %s run", ErrLifecycleConflict, record.Status)
		}
	})
}

func (store Store) MarkConsumed(id string, consumedAt time.Time) (Record, error) {
	return store.mutate(id, func(record *Record) error {
		if !consumedAt.Before(record.Grant.ExpiresAt) {
			return ErrGrantExpired
		}
		switch record.Status {
		case StatusSubmitted:
			if consumedAt.Before(*record.SubmittedAt) {
				return fmt.Errorf("%w: consumption predates submission", ErrLifecycleConflict)
			}
			consumedAt = consumedAt.UTC()
			record.Status = StatusConsumed
			record.ConsumedAt = &consumedAt
			return nil
		case StatusConsumed:
			return nil
		default:
			return fmt.Errorf("%w: cannot consume a %s run", ErrLifecycleConflict, record.Status)
		}
	})
}

func (store Store) mutate(id string, update func(*Record) error) (Record, error) {
	if err := store.ensureDirectory(); err != nil {
		return Record{}, err
	}
	lock, err := os.OpenFile(store.lockPath(id), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return Record{}, fmt.Errorf("open run grant lock: %w", err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lock.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return Record{}, ErrConcurrentMutation
		}
		return Record{}, fmt.Errorf("lock run grant: %w", err)
	}
	defer func() {
		_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
		_ = lock.Close()
	}()

	record, err := store.load(id)
	if err != nil {
		return Record{}, err
	}
	if err := update(&record); err != nil {
		return Record{}, err
	}
	if err := writeAtomic(store.recordPath(id), record); err != nil {
		return Record{}, err
	}
	return record, nil
}

func (store Store) load(id string) (Record, error) {
	data, err := os.ReadFile(store.recordPath(id))
	if errors.Is(err, os.ErrNotExist) {
		return Record{}, ErrNotFound
	}
	if err != nil {
		return Record{}, fmt.Errorf("read run grant: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var record Record
	if err := decoder.Decode(&record); err != nil {
		return Record{}, fmt.Errorf("decode run grant: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return Record{}, fmt.Errorf("decode run grant: trailing data")
	}
	if record.Grant.ID != id {
		return Record{}, fmt.Errorf("run grant identity mismatch")
	}
	if err := validateRecord(record); err != nil {
		return Record{}, err
	}
	return record, nil
}

func validateRecord(record Record) error {
	if err := record.Grant.Validate(); err != nil {
		return err
	}
	switch record.Status {
	case StatusIssued:
		if record.ReceiptDigest != "" || record.SubmittedAt != nil || record.ConsumedAt != nil {
			return fmt.Errorf("invalid issued run state")
		}
	case StatusSubmitted:
		if record.SubmittedAt == nil || record.ConsumedAt != nil {
			return fmt.Errorf("invalid submitted run state")
		}
	case StatusConsumed:
		if record.SubmittedAt == nil || record.ConsumedAt == nil {
			return fmt.Errorf("invalid consumed run state")
		}
	default:
		return fmt.Errorf("invalid run status %q", record.Status)
	}
	if record.Status != StatusIssued {
		if err := attestation.ValidateDigest(record.ReceiptDigest); err != nil {
			return fmt.Errorf("invalid receipt digest: %w", err)
		}
		if record.SubmittedAt.Before(record.Grant.IssuedAt) || !record.SubmittedAt.Before(record.Grant.ExpiresAt) {
			return fmt.Errorf("invalid submission timestamp")
		}
	}
	if record.Status == StatusConsumed {
		if record.ConsumedAt.Before(*record.SubmittedAt) || !record.ConsumedAt.Before(record.Grant.ExpiresAt) {
			return fmt.Errorf("invalid consumption timestamp")
		}
	}
	return nil
}

func effectiveRecord(record Record, now time.Time) Record {
	if record.Status == StatusIssued && !now.Before(record.Grant.ExpiresAt) {
		record.Status = StatusExpired
	}
	return record
}

func (store Store) ensureDirectory() error {
	info, err := os.Stat(store.root)
	if err != nil {
		return fmt.Errorf("inspect run grant root: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("run grant root must be a provisioned directory")
	}
	if err := os.Mkdir(store.directory(), 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create run grant directory: %w", err)
	}
	return syncDirectory(store.root)
}

func (store Store) directory() string {
	return filepath.Join(store.root, "runs")
}

func (store Store) recordPath(id string) string {
	return filepath.Join(store.directory(), digestName(id)+".json")
}

func (store Store) lockPath(id string) string {
	return filepath.Join(store.directory(), digestName(id)+".lock")
}

func digestName(value string) string {
	sum := attestation.Digest([]byte(value))
	return sum[len("sha256:"):]
}

func marshalRecord(record Record) ([]byte, error) {
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode run grant: %w", err)
	}
	return append(data, '\n'), nil
}

func writeAtomic(path string, record Record) error {
	data, err := marshalRecord(record)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".cihash-run-*")
	if err != nil {
		return fmt.Errorf("create temporary run grant: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("set run grant mode: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write run grant: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync run grant: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close run grant: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace run grant: %w", err)
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open state directory for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync state directory: %w", err)
	}
	return nil
}
