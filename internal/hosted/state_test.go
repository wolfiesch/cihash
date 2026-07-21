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
