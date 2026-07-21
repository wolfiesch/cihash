package store

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/wolfiesch/cihash/internal/attestation"
)

func TestSaveKeepsLogsPrivateAndReceiptsGroupReadable(t *testing.T) {
	for _, existingReceiptsDir := range []bool{false, true} {
		name := "fresh directory"
		if existingReceiptsDir {
			name = "existing private directory"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			if existingReceiptsDir {
				if err := os.Mkdir(filepath.Join(root, "receipts"), 0o700); err != nil {
					t.Fatal(err)
				}
			}

			previousUmask := syscall.Umask(0o077)
			defer syscall.Umask(previousUmask)
			receiptPath, logPath, err := New(root).Save(
				Identity{Repository: "github.com/example/project"},
				attestation.Envelope{PayloadType: attestation.PayloadType, Payload: "e30="},
				[]byte("job output"),
			)
			if err != nil {
				t.Fatalf("Save() error = %v", err)
			}

			assertMode(t, filepath.Dir(receiptPath), 0o750)
			assertSetgid(t, filepath.Dir(receiptPath))
			assertMode(t, receiptPath, 0o640)
			assertMode(t, filepath.Dir(logPath), 0o700)
			assertMode(t, logPath, 0o600)
		})
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("mode for %s = %04o, want %04o", path, got, want)
	}
}

func assertSetgid(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if info.Mode()&os.ModeSetgid == 0 {
		t.Fatalf("mode for %s does not include setgid: %v", path, info.Mode())
	}
}

func TestSaveForRunKeepsRunBindingsImmutableAndRefreshesIdentity(t *testing.T) {
	root := t.TempDir()
	evidence := New(root)
	identity := Identity{Repository: "github.com/example/project"}
	first := attestation.Envelope{PayloadType: attestation.PayloadType, Payload: "e30="}
	if _, _, err := evidence.SaveForRun("run-1", identity, first, []byte("first log")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := evidence.SaveForRun("run-1", identity, first, []byte("first log")); err != nil {
		t.Fatalf("same receipt retry = %v", err)
	}
	replacement := attestation.Envelope{PayloadType: attestation.PayloadType, Payload: "eyJkaWZmZXJlbnQiOnRydWV9"}
	if _, _, err := evidence.SaveForRun("run-1", identity, replacement, []byte("second log")); !errors.Is(err, ErrConflict) {
		t.Fatalf("same-run replacement error = %v, want ErrConflict", err)
	}
	stored, _, found, err := evidence.Lookup(identity)
	if err != nil || !found || stored.Payload != first.Payload {
		t.Fatalf("same-run conflict changed lookup evidence: found=%t err=%v envelope=%+v", found, err, stored)
	}

	if _, _, err := evidence.SaveForRun("run-2", identity, replacement, []byte("second log")); err != nil {
		t.Fatalf("new authorized run could not refresh identity: %v", err)
	}
	stored, _, found, err = evidence.Lookup(identity)
	if err != nil || !found || stored.Payload != replacement.Payload {
		t.Fatalf("refreshed lookup evidence: found=%t err=%v envelope=%+v", found, err, stored)
	}
	bound, found, err := evidence.LookupEvidence(identity)
	if err != nil || !found {
		t.Fatalf("bound evidence lookup: found=%t err=%v", found, err)
	}
	replacementData, err := attestation.MarshalEnvelope(replacement)
	if err != nil {
		t.Fatal(err)
	}
	if bound.RunID != "run-2" || bound.ReceiptDigest != attestation.Digest(replacementData) {
		t.Fatalf("bound evidence = %+v", bound)
	}
}
