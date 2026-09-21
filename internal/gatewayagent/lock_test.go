package gatewayagent

import (
	"path/filepath"
	"testing"
)

func TestStateLockPreventsConcurrentAgentManagers(t *testing.T) {
	stateFile := filepath.Join(t.TempDir(), "state", "sessions.json")
	first, err := AcquireStateLock(stateFile)
	if err != nil {
		t.Fatalf("first AcquireStateLock: %v", err)
	}
	defer first.Close()
	if _, err := AcquireStateLock(stateFile); err == nil {
		t.Fatal("second state lock unexpectedly succeeded")
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close first lock: %v", err)
	}
	second, err := AcquireStateLock(stateFile)
	if err != nil {
		t.Fatalf("AcquireStateLock after release: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("close second lock: %v", err)
	}
}
