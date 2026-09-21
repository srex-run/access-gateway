package gatewayagent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/srex-run/access-gateway/internal/gateway"
	"github.com/srex-run/access-gateway/internal/id"
)

func sessionTestConfig() SessionConfig {
	started := time.Now().UTC().Truncate(time.Second)
	return SessionConfig{Version: 1, GatewayID: id.New(), TargetHost: "asset.internal", StartedAt: started, ExpiresAt: started.Add(time.Minute),
		Request: gateway.CreateSessionRequest{SessionID: id.New(), TargetID: id.New(), TargetPort: 443, SourceIP: "127.0.0.1", TargetAccount: "operator", ConnectionMode: "native", TTLSeconds: 60, MaxConnections: gateway.MaxSessionConnections}}
}

func TestSessionHostNetworkValidationAndPodDefaults(t *testing.T) {
	cfg := sessionTestConfig()
	host, port := cfg.ListenerAddress()
	if err := cfg.Validate(); err != nil || host != "0.0.0.0" || port != SessionListenerPort || cfg.ManagementAddress() != ":8090" {
		t.Fatalf("Pod defaults changed: %v", err)
	}
	cfg.Network = &SessionNetwork{ListenerHost: "0.0.0.0", ListenerPort: 21000, ManagementPort: 31000}
	if err := cfg.Validate(); err != nil || cfg.ManagementAddress() != "127.0.0.1:31000" {
		t.Fatalf("host network configuration: %v", err)
	}
	for _, network := range []SessionNetwork{
		{ListenerHost: "public.example.test", ListenerPort: 21000, ManagementPort: 31000},
		{ListenerHost: "0.0.0.0", ListenerPort: 443, ManagementPort: 31000},
		{ListenerHost: "0.0.0.0", ListenerPort: 21000, ManagementPort: 21000},
		{ListenerHost: "0.0.0.0", ListenerPort: 21000, ManagementPort: 65536},
	} {
		cfg.Network = &network
		if err := cfg.Validate(); err == nil {
			t.Fatalf("invalid host network accepted: %+v", network)
		}
	}
}

func TestSessionConfigKeepsApprovalDeadlineAfterQueueing(t *testing.T) {
	cfg := sessionTestConfig()
	expires := cfg.StartedAt.Add(20 * time.Second)
	cfg.Request.ExpiresAt, cfg.ExpiresAt = &expires, expires
	if err := cfg.Validate(); err != nil {
		t.Fatalf("remaining approved time rejected: %v", err)
	}
	cfg.ExpiresAt = cfg.StartedAt.Add(time.Minute)
	if err := cfg.Validate(); err == nil {
		t.Fatal("agent accepted a deadline extended after approval")
	}
	expires = cfg.StartedAt.Add(2 * time.Minute)
	cfg.ExpiresAt = expires
	if err := cfg.Validate(); err == nil {
		t.Fatal("deadline beyond requested duration accepted")
	}
	cfg = sessionTestConfig()
	cfg.Request.TTLSeconds = 18001
	cfg.ExpiresAt = cfg.StartedAt.Add(18001 * time.Second)
	if err := cfg.Validate(); err == nil {
		t.Fatal("more than five hours accepted")
	}
}

func TestSessionStopMarkerRejectsLaunchBeforeOpeningPorts(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "stop"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RunSessionAgent(context.Background(), sessionTestConfig(), directory, zerolog.Nop()); err == nil {
		t.Fatal("revoked session opened listeners")
	}
}
