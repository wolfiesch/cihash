package rungrant

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/wolfiesch/cihash/internal/attestation"
	"github.com/wolfiesch/cihash/internal/policy"
)

func TestIssueBindsAdministratorPolicyAndServerNonce(t *testing.T) {
	now := time.Date(2026, time.July, 21, 12, 0, 0, 0, time.UTC)
	configured := testPolicy()
	entropy := bytes.NewReader(append(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)...))
	grant, err := issue(configured, strings.Repeat("a", 40), strings.Repeat("b", 40), strings.Repeat("c", 40), now, entropy)
	if err != nil {
		t.Fatal(err)
	}
	if grant.Policy.Repository != configured.Repository || grant.Policy.Profile != configured.Profile {
		t.Fatalf("grant policy = %+v, want configured policy", grant.Policy)
	}
	if grant.ID == grant.Nonce || grant.ID == "" || grant.Nonce == "" {
		t.Fatalf("grant identity is not independently generated: %+v", grant)
	}
	if got, want := grant.ExpiresAt, now.Add(time.Hour); !got.Equal(want) {
		t.Fatalf("expiresAt = %v, want %v", got, want)
	}

	tamperedArchitecture := grant
	tamperedArchitecture.Architecture = "linux/arm64"
	if err := tamperedArchitecture.Validate(); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("tampered architecture error = %v, want ErrInvalidGrant", err)
	}

	grant.Policy.Command[0] = "unapproved"
	if err := grant.Validate(); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("tampered policy error = %v, want ErrInvalidGrant", err)
	}
}

func TestGrantRejectsEqualIDAndNonce(t *testing.T) {
	now := time.Date(2026, time.July, 21, 12, 0, 0, 0, time.UTC)
	entropy := bytes.NewReader(bytes.Repeat([]byte{1}, 64))
	if _, err := issue(testPolicy(), strings.Repeat("a", 40), strings.Repeat("b", 40), strings.Repeat("c", 40), now, entropy); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("equal ID and nonce error = %v, want ErrInvalidGrant", err)
	}
}

func TestIssueRejectsInvalidExecutionIdentity(t *testing.T) {
	now := time.Date(2026, time.July, 21, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name string
		head string
		base string
		tree string
	}{
		{name: "short head", head: "abc", base: strings.Repeat("b", 40), tree: strings.Repeat("c", 40)},
		{name: "mixed object formats", head: strings.Repeat("a", 40), base: strings.Repeat("b", 64), tree: strings.Repeat("c", 40)},
		{name: "mixed tree format", head: strings.Repeat("a", 40), base: strings.Repeat("b", 40), tree: strings.Repeat("c", 64)},
		{name: "missing tree", head: strings.Repeat("a", 40), base: strings.Repeat("b", 40)},
	} {
		t.Run(test.name, func(t *testing.T) {
			entropy := bytes.NewReader(bytes.Repeat([]byte{1}, 64))
			if _, err := issue(testPolicy(), test.head, test.base, test.tree, now, entropy); !errors.Is(err, ErrInvalidGrant) {
				t.Fatalf("issue error = %v, want ErrInvalidGrant", err)
			}
		})
	}
}

func TestStoreEnforcesRunLifecycle(t *testing.T) {
	now := time.Date(2026, time.July, 21, 12, 0, 0, 0, time.UTC)
	grant := testGrant(t, now)
	store := NewStore(t.TempDir())
	created, err := store.Create(grant, testRunContext())
	if err != nil {
		t.Fatal(err)
	}
	if created.Status != StatusIssued {
		t.Fatalf("created status = %q, want %q", created.Status, StatusIssued)
	}
	if _, err := store.Create(grant, testRunContext()); !errors.Is(err, ErrLifecycleConflict) {
		t.Fatalf("duplicate create error = %v, want ErrLifecycleConflict", err)
	}
	if _, err := store.MarkConsumed(grant.ID, now.Add(time.Minute)); !errors.Is(err, ErrLifecycleConflict) {
		t.Fatalf("early consume error = %v, want ErrLifecycleConflict", err)
	}

	receiptDigest := attestation.Digest([]byte("receipt-a"))
	submitted, err := store.MarkSubmitted(grant.ID, receiptDigest, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if submitted.Status != StatusSubmitted || submitted.ReceiptDigest != receiptDigest || submitted.SubmittedAt == nil {
		t.Fatalf("submitted record = %+v", submitted)
	}
	if _, err := store.MarkSubmitted(grant.ID, receiptDigest, now.Add(2*time.Minute)); err != nil {
		t.Fatalf("idempotent submission: %v", err)
	}
	if _, err := store.MarkSubmitted(grant.ID, attestation.Digest([]byte("receipt-b")), now.Add(2*time.Minute)); !errors.Is(err, ErrLifecycleConflict) {
		t.Fatalf("replacement submission error = %v, want ErrLifecycleConflict", err)
	}

	consumed, err := store.MarkConsumed(grant.ID, now.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if consumed.Status != StatusConsumed || consumed.ConsumedAt == nil {
		t.Fatalf("consumed record = %+v", consumed)
	}
	if _, err := store.MarkConsumed(grant.ID, now.Add(4*time.Minute)); err != nil {
		t.Fatalf("idempotent consumption: %v", err)
	}
}

func TestStoreRecoversEachPersistedLifecycleTransition(t *testing.T) {
	now := time.Date(2026, time.July, 21, 12, 0, 0, 0, time.UTC)
	grant := testGrant(t, now)
	root := t.TempDir()
	if _, err := NewStore(root).Create(grant, testRunContext()); err != nil {
		t.Fatal(err)
	}
	issued, found, err := NewStore(root).Lookup(grant.ID, now.Add(time.Second))
	if err != nil || !found || issued.Status != StatusIssued {
		t.Fatalf("issued after restart = %+v, %v, %v", issued, found, err)
	}
	receiptDigest := attestation.Digest([]byte("receipt"))
	if _, err := NewStore(root).MarkSubmitted(grant.ID, receiptDigest, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	submitted, found, err := NewStore(root).Lookup(grant.ID, now.Add(2*time.Minute))
	if err != nil || !found || submitted.Status != StatusSubmitted || submitted.ReceiptDigest != receiptDigest {
		t.Fatalf("submitted after restart = %+v, %v, %v", submitted, found, err)
	}
	if _, err := NewStore(root).MarkConsumed(grant.ID, now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	consumed, found, err := NewStore(root).Lookup(grant.ID, now.Add(4*time.Minute))
	if err != nil || !found || consumed.Status != StatusConsumed {
		t.Fatalf("consumed after restart = %+v, %v, %v", consumed, found, err)
	}
}

func TestStoreRejectsExpiredOrConflictingSubmission(t *testing.T) {
	now := time.Date(2026, time.July, 21, 12, 0, 0, 0, time.UTC)
	grant := testGrant(t, now)
	store := NewStore(t.TempDir())
	if _, err := store.Create(grant, testRunContext()); err != nil {
		t.Fatal(err)
	}

	expired, found, err := store.Lookup(grant.ID, grant.ExpiresAt)
	if err != nil || !found || expired.Status != StatusExpired {
		t.Fatalf("expired lookup = %+v, %v, %v", expired, found, err)
	}
	if _, err := store.MarkSubmitted(grant.ID, attestation.Digest([]byte("receipt")), grant.ExpiresAt); !errors.Is(err, ErrGrantExpired) {
		t.Fatalf("expired submission error = %v, want ErrGrantExpired", err)
	}
	grant2 := testGrantWithEntropy(t, now, 4)
	if _, err := store.Create(grant2, testRunContext()); err != nil {
		t.Fatal(err)
	}
	receiptDigest := attestation.Digest([]byte("accepted-receipt"))
	if _, err := store.MarkSubmitted(grant2.ID, receiptDigest, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkSubmitted(grant2.ID, receiptDigest, grant2.ExpiresAt); !errors.Is(err, ErrGrantExpired) {
		t.Fatalf("expired idempotent submission error = %v, want ErrGrantExpired", err)
	}
	if _, err := store.MarkConsumed(grant2.ID, grant2.ExpiresAt); !errors.Is(err, ErrGrantExpired) {
		t.Fatalf("expired consumption error = %v, want ErrGrantExpired", err)
	}
	if _, err := store.MarkSubmitted(grant.ID, attestation.Digest([]byte("early")), now.Add(-time.Second)); !errors.Is(err, ErrLifecycleConflict) {
		t.Fatalf("pre-issuance submission error = %v, want ErrLifecycleConflict", err)
	}
	if _, err := store.MarkSubmitted("missing", attestation.Digest([]byte("receipt")), now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing submission error = %v, want ErrNotFound", err)
	}
}

func TestStoreRequiresProvisionedRoot(t *testing.T) {
	now := time.Date(2026, time.July, 21, 12, 0, 0, 0, time.UTC)
	root := filepath.Join(t.TempDir(), "missing")
	if _, err := NewStore(root).Create(testGrant(t, now), testRunContext()); err == nil || !strings.Contains(err.Error(), "inspect run grant root") {
		t.Fatalf("unprovisioned root error = %v", err)
	}
}

func TestStoreRejectsTamperedStateAndConcurrentMutation(t *testing.T) {
	now := time.Date(2026, time.July, 21, 12, 0, 0, 0, time.UTC)
	grant := testGrant(t, now)
	store := NewStore(t.TempDir())
	if _, err := store.Create(grant, testRunContext()); err != nil {
		t.Fatal(err)
	}
	lock, err := os.OpenFile(store.lockPath(grant.ID), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkSubmitted(grant.ID, attestation.Digest([]byte("receipt")), now); !errors.Is(err, ErrConcurrentMutation) {
		t.Fatalf("concurrent mutation error = %v, want ErrConcurrentMutation", err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}

	record, err := store.load(grant.ID)
	if err != nil {
		t.Fatal(err)
	}
	record.Grant.Policy.Environment.Image = "unapproved"
	if err := writeAtomic(store.recordPath(grant.ID), record); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Lookup(grant.ID, now); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("tampered state error = %v, want ErrInvalidGrant", err)
	}
}

func testGrant(t *testing.T, now time.Time) Grant {
	t.Helper()
	return testGrantWithEntropy(t, now, 3)
}

func testGrantWithEntropy(t *testing.T, now time.Time, value byte) Grant {
	t.Helper()
	entropy := bytes.NewReader(append(bytes.Repeat([]byte{value}, 32), bytes.Repeat([]byte{value + 1}, 32)...))
	grant, err := issue(testPolicy(), strings.Repeat("a", 40), strings.Repeat("b", 40), strings.Repeat("c", 40), now, entropy)
	if err != nil {
		t.Fatal(err)
	}
	return grant
}

func testPolicy() policy.Policy {
	return policy.Policy{
		Version:    policy.Version,
		Repository: "github.com/acme/project",
		Profile:    "verify",
		Command:    []string{"go", "test", "./..."},
		Environment: policy.Environment{
			Image:          "sha256:" + strings.Repeat("c", 64),
			Platform:       "linux/amd64",
			Network:        "none",
			Memory:         "8g",
			CPUs:           "6",
			PIDsLimit:      1024,
			MaxOutputBytes: 16 << 20,
		},
		MaxAgeSeconds:  3600,
		TimeoutSeconds: 300,
	}
}

func testRunContext() Context {
	return Context{InstallationID: 123, PullRequestNumber: 7}
}
