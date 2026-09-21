package gatewayagent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileStateStoreRoundTripIsProtectedAndSorted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "sessions.json")
	store, err := NewFileStateStore(path)
	if err != nil {
		t.Fatalf("NewFileStateStore: %v", err)
	}
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	records := []SessionRecord{
		{SessionID: testOtherTargetID, Status: sessionClosed, ClosedAt: &now},
		{SessionID: testGatewaySessionID, Status: sessionFailed, ClosedAt: &now},
	}
	if err := store.Save(context.Background(), records); err != nil {
		t.Fatalf("Save: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat state: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state mode = %o", info.Mode().Perm())
	}
	loaded, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(loaded) != 2 || loaded[0].SessionID != testGatewaySessionID || loaded[1].SessionID != testOtherTargetID {
		t.Fatalf("loaded records = %+v", loaded)
	}
}

func TestFileStateStoreRejectsTrailingAndUnknownJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.json")
	store, err := NewFileStateStore(path)
	if err != nil {
		t.Fatalf("NewFileStateStore: %v", err)
	}
	for name, value := range map[string]string{
		"trailing": `{"version":1,"sessions":[]} {}`,
		"unknown":  `{"version":1,"sessions":[],"unexpected":true}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
				t.Fatalf("write state: %v", err)
			}
			if _, err := store.Load(context.Background()); err == nil {
				t.Fatal("invalid state was accepted")
			}
		})
	}
}

func TestFileStateStoreHonorsCancelledContext(t *testing.T) {
	store, err := NewFileStateStore(filepath.Join(t.TempDir(), "sessions.json"))
	if err != nil {
		t.Fatalf("NewFileStateStore: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := store.Save(ctx, nil); err == nil {
		t.Fatal("Save with cancelled context succeeded")
	}
	if _, err := store.Load(ctx); err == nil {
		t.Fatal("Load with cancelled context succeeded")
	}
}

func TestFileStateStoreRejectsUnsafeStatePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"sessions":[]}`), 0o600); err != nil {
		t.Fatalf("write state: %v", err)
	}
	store, err := NewFileStateStore(path)
	if err != nil {
		t.Fatalf("NewFileStateStore: %v", err)
	}
	for _, mode := range []os.FileMode{0o660, 0o644} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatalf("chmod state to %o: %v", mode, err)
		}
		if _, err := store.Load(context.Background()); err == nil {
			t.Fatalf("state mode %o was accepted", mode)
		}
	}
}
