package hosted

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDeliveryLeaseDeduplicatesAndRecoversAfterCrash(t *testing.T) {
	root := t.TempDir()
	store := NewStateStore(root)
	const deliveryID = "delivery-123"

	started, err := store.BeginDelivery(deliveryID)
	if err != nil || !started {
		t.Fatalf("first BeginDelivery = %v, %v; want true, nil", started, err)
	}
	started, err = store.BeginDelivery(deliveryID)
	if err != nil || started {
		t.Fatalf("concurrent BeginDelivery = %v, %v; want false, nil", started, err)
	}

	inflightPath := filepath.Join(root, "deliveries", digestName(deliveryID)+".inflight")
	stale := time.Now().Add(-deliveryLease - time.Minute)
	if err := os.Chtimes(inflightPath, stale, stale); err != nil {
		t.Fatal(err)
	}
	started, err = store.BeginDelivery(deliveryID)
	if err != nil || !started {
		t.Fatalf("stale BeginDelivery = %v, %v; want true, nil", started, err)
	}

	if err := store.CompleteDelivery(deliveryID); err != nil {
		t.Fatal(err)
	}
	started, err = store.BeginDelivery(deliveryID)
	if err != nil || started {
		t.Fatalf("completed BeginDelivery = %v, %v; want false, nil", started, err)
	}
}

func TestFallbackStateRecoversMonotonicallyAcrossRestarts(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, time.July, 21, 12, 0, 0, 0, time.UTC)
	state := FallbackState{
		ID:             "fallback-recovery",
		Repository:     "owner/project",
		InstallationID: 123,
		CheckRunID:     456,
		Workflow:       "cihash-fallback.yml",
		ExpiresAt:      now.Add(time.Hour),
	}
	if err := NewStateStore(root).CreateFallback(state); err != nil {
		t.Fatal(err)
	}
	if err := NewStateStore(root).BindWorkflowRun(state.ID, 789); err != nil {
		t.Fatal(err)
	}
	recovered, found, err := NewStateStore(root).LookupWorkflowRun(789)
	if err != nil || !found || recovered.ID != state.ID {
		t.Fatalf("recovered state = %+v, %v, %v", recovered, found, err)
	}
	if err := NewStateStore(root).CompleteFallback(state.ID, "success", now); err != nil {
		t.Fatal(err)
	}
	if err := NewStateStore(root).CompleteFallback(state.ID, "success", now.Add(time.Minute)); err != nil {
		t.Fatalf("idempotent completion: %v", err)
	}
	if err := NewStateStore(root).CompleteFallback(state.ID, "failure", now.Add(time.Minute)); err == nil {
		t.Fatal("conflicting completion succeeded")
	}
}

func TestFallbackStateRequiresWorkflowIdentity(t *testing.T) {
	state := FallbackState{
		ID:             "fallback-no-workflow",
		InstallationID: 123,
		CheckRunID:     456,
		ExpiresAt:      time.Now().Add(time.Hour),
	}
	if err := NewStateStore(t.TempDir()).CreateFallback(state); err == nil {
		t.Fatal("CreateFallback succeeded without workflow identity")
	}
}

func TestFallbackStateCorruptionFailsClosed(t *testing.T) {
	root := t.TempDir()
	state := FallbackState{
		ID:             "fallback-corrupt",
		InstallationID: 123,
		CheckRunID:     456,
		Workflow:       "cihash-fallback.yml",
		ExpiresAt:      time.Now().Add(time.Hour),
	}
	store := NewStateStore(root)
	if err := store.CreateFallback(state); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "fallbacks", digestName(state.ID)+".json")
	if err := os.WriteFile(path, []byte("{corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, found, err := NewStateStore(root).LookupFallback(state.ID); err == nil || found {
		t.Fatalf("LookupFallback = found %t, error %v; want fail closed", found, err)
	}
}
