package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/srex-run/access-gateway/internal/gateway"
	"github.com/srex-run/access-gateway/internal/gatewayagent"
	"github.com/srex-run/access-gateway/internal/id"
)

func TestSessionCommandCannotRestartTheSameGrant(t *testing.T) {
	directory := t.TempDir()
	started := time.Now().UTC().Truncate(time.Second).Add(-2 * time.Minute)
	cfg := gatewayagent.SessionConfig{Version: 1, GatewayID: id.New(), TargetHost: "asset.internal", StartedAt: started, ExpiresAt: started.Add(time.Minute),
		Request: gateway.CreateSessionRequest{SessionID: id.New(), TargetID: id.New(), TargetPort: 443, SourceIP: "127.0.0.1", TargetAccount: "operator", ConnectionMode: "native", TTLSeconds: 60, MaxConnections: gateway.MaxSessionConnections}}
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "session.json")
	if err := os.WriteFile(path, encoded, 0o400); err != nil {
		t.Fatal(err)
	}
	args := []string{"--config", path, "--state-dir", directory}
	if err := runSession(args, zerolog.Nop()); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired grant launch: %v", err)
	}
	if err := runSession(args, zerolog.Nop()); err == nil || !strings.Contains(err.Error(), "already started") {
		t.Fatalf("grant replay bypassed launch marker: %v", err)
	}
}
