package config

import (
	"path/filepath"
	"testing"
)

func TestLocalSessionRuntimeDefaultsAndPortValidation(t *testing.T) {
	clearOptionalConfig(t)
	t.Setenv("HTTP_ADDR", "127.0.0.1:18080")
	cfg, err := Load()
	if err != nil || cfg.GatewayRuntime != "local" || cfg.SessionAgentControlPlaneURL != "http://127.0.0.1:18080" || !cfg.SessionAgentAllowAuditHTTP || cfg.SessionAgentPublicHost != "127.0.0.1" || !filepath.IsAbs(cfg.SessionAgentStateDirectory) {
		t.Fatalf("local defaults: runtime=%s endpoint=%s err=%v", cfg.GatewayRuntime, cfg.SessionAgentControlPlaneURL, err)
	}
	t.Setenv("SESSION_AGENT_PORT_END", "20001")
	if _, err := Load(); err == nil {
		t.Fatal("capacity larger than the port range was accepted")
	}
	t.Setenv("SESSION_AGENT_MAX_SESSIONS", "2")
	if _, err := Load(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SESSION_AGENT_CONTROL_PLANE_URL", "http://control.example.com")
	if _, err := Load(); err == nil {
		t.Fatal("non-loopback audit HTTP was implicitly enabled")
	}
}

func TestDockerSessionRuntimeRequiresHostPathsAndPublicAddress(t *testing.T) {
	clearOptionalConfig(t)
	t.Setenv("GATEWAY_RUNTIME", "docker")
	if _, err := Load(); err == nil {
		t.Fatal("incomplete Docker runtime accepted")
	}
	t.Setenv("SESSION_AGENT_STATE_DIR", "/var/lib/access-gateway/sessions")
	t.Setenv("SESSION_AGENT_DOCKER_STATE_DIR", "/srv/access-gateway/sessions")
	t.Setenv("SESSION_AGENT_IMAGE", "registry.test/agent:v1")
	t.Setenv("PUBLIC_URL", "https://access-gateway.example.com")
	t.Setenv("SESSION_AGENT_CONTROL_PLANE_URL", "https://control.example.com")
	if _, err := Load(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SESSION_AGENT_DOCKER_STATE_DIR", "relative/path")
	if _, err := Load(); err == nil {
		t.Fatal("relative Docker host state path accepted")
	}
}

func TestKubernetesSessionRuntimeConfiguration(t *testing.T) {
	clearOptionalConfig(t)
	t.Setenv("GATEWAY_RUNTIME", "invalid")
	if _, err := Load(); err == nil {
		t.Fatal("unknown runtime accepted")
	}
	t.Setenv("GATEWAY_RUNTIME", "kubernetes")
	if _, err := Load(); err == nil {
		t.Fatal("incomplete Kubernetes runtime accepted")
	}
	t.Setenv("SESSION_AGENT_IMAGE", "registry.test/agent:v1")
	t.Setenv("SESSION_AGENT_NODE_NAME", "worker-1")
	t.Setenv("PUBLIC_URL", "https://access-gateway.example.com")
	t.Setenv("SESSION_AGENT_CONTROL_PLANE_URL", "https://control.example.com")
	cfg, err := Load()
	if err != nil || cfg.GatewayRuntime != "kubernetes" {
		t.Fatalf("complete Kubernetes configuration: %v", err)
	}
	t.Setenv("SESSION_AGENT_STARTUP_TIMEOUT", "91s")
	if _, err := Load(); err == nil {
		t.Fatal("startup timeout exceeding state-machine clock tolerance accepted")
	}
}

func TestLoadRejectsRetiredHTTPRuntime(t *testing.T) {
	clearOptionalConfig(t)
	t.Setenv("GATEWAY_RUNTIME", "http")
	if _, err := Load(); err == nil {
		t.Fatal("retired HTTP runtime accepted")
	}
}
