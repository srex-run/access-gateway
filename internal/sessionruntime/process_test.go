package sessionruntime

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/srex-run/access-gateway/internal/gatewayagent"
	"github.com/srex-run/access-gateway/internal/id"
)

// The subprocess exercises exec, descriptor inheritance and reattachment
// without requiring a TCP listener or a running control-plane database.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "session" {
		os.Exit(runProcessHelper())
	}
	os.Exit(m.Run())
}

type processObservation struct {
	PID       int    `json:"pid"`
	SessionID string `json:"session_id"`
	Target    string `json:"target"`
	HasSecret bool   `json:"has_secret"`
}

func runProcessHelper() int {
	args := flag.NewFlagSet("session", flag.ContinueOnError)
	configPath := args.String("config", "", "")
	state := args.String("state-dir", "", "")
	lockFD := args.Int("lock-fd", -1, "")
	if args.Parse(os.Args[2:]) != nil || *lockFD != 3 {
		return 2
	}
	lock := os.NewFile(3, "process lock")
	defer lock.Close()
	if syscall.Flock(3, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return 3
	}
	cfg, err := gatewayagent.LoadSessionConfig(*configPath)
	if err != nil {
		return 4
	}
	encoded, _ := json.Marshal(processObservation{PID: os.Getpid(), SessionID: cfg.Request.SessionID, Target: cfg.TargetHost,
		HasSecret: os.Getenv("ENCRYPTION_KEY") != "" || os.Getenv("DATABASE_URL") != "" || os.Getenv("AUDIT_COLLECTOR_SECRET") != ""})
	if os.WriteFile(filepath.Join(*state, "observed.json"), encoded, 0o600) != nil {
		return 5
	}
	for time.Now().Before(cfg.ExpiresAt) {
		if _, err := os.Stat(filepath.Join(*state, "stop")); err == nil {
			return 0
		}
		time.Sleep(10 * time.Millisecond)
	}
	return 0
}

func TestLocalSessionProcessesAreIsolatedAndRecoveredWithoutStoredPIDs(t *testing.T) {
	t.Setenv("ENCRYPTION_KEY", "must-not-inherit")
	t.Setenv("DATABASE_URL", "must-not-inherit")
	t.Setenv("AUDIT_COLLECTOR_SECRET", "must-not-inherit")
	c, err := NewHostClient(hostTestOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	configureHostFake(c, c.driver)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	first, second := hostTestRequest(), hostTestRequest()
	t.Cleanup(func() {
		for _, request := range []string{first.SessionID, second.SessionID} {
			_ = os.WriteFile(filepath.Join(c.store.agentPath(request), "stop"), []byte("{}"), 0o600)
		}
	})
	for _, request := range []struct{ sessionID, target string }{{first.SessionID, "one.internal"}, {second.SessionID, "two.internal"}} {
		grant := first
		grant.SessionID = request.sessionID
		if _, err := c.CreateApprovedSession(ctx, id.New(), grant, request.target); err != nil {
			t.Fatal(err)
		}
	}
	observations := make([]processObservation, 2)
	for i, request := range []string{first.SessionID, second.SessionID} {
		if err := pollHost(ctx, 10*time.Millisecond, func() (bool, error) {
			encoded, err := os.ReadFile(filepath.Join(c.store.agentPath(request), "observed.json"))
			if os.IsNotExist(err) {
				return false, nil
			}
			if err != nil {
				return false, err
			}
			// The helper writes once; retry if this read precedes completion.
			return json.Unmarshal(encoded, &observations[i]) == nil, nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if observations[0].PID == observations[1].PID || observations[0].PID == os.Getpid() || observations[0].HasSecret || observations[1].HasSecret ||
		observations[0].SessionID != first.SessionID || observations[1].SessionID != second.SessionID || observations[0].Target != "one.internal" || observations[1].Target != "two.internal" {
		t.Fatalf("process isolation: %+v", observations)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	recovered, err := NewHostClient(c.options)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	configureHostFake(recovered, recovered.driver)
	for _, sessionID := range []string{first.SessionID, second.SessionID} {
		if _, err := recovered.CloseSession(ctx, "", sessionID, "recovered-revocation"); err != nil {
			t.Fatal(err)
		}
	}
	for _, process := range observations {
		if err := pollHost(ctx, 10*time.Millisecond, func() (bool, error) {
			return syscall.Kill(process.PID, 0) == syscall.ESRCH, nil
		}); err != nil {
			t.Fatal("terminated session process was not reaped")
		}
	}
}
