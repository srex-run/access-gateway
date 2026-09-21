package config

import "testing"

func TestPublicURLControlsSessionIdentity(t *testing.T) {
	for _, tc := range []struct{ origin, wantURL, wantHost string }{
		{"", "http://127.0.0.1:18080", "127.0.0.1"},
		{"http://127.0.0.1", "http://127.0.0.1", "127.0.0.1"},
		{"https://access-gateway.srex.run/", "https://access-gateway.srex.run", "access-gateway.srex.run"},
		{"https://access-gateway.srex.run:8443", "https://access-gateway.srex.run:8443", "access-gateway.srex.run"},
		{" HTTPS://Access.Example.com:8443/ ", "https://access.example.com:8443", "access.example.com"},
		{"http://[::1]:8080", "http://[::1]:8080", "::1"},
	} {
		t.Run(tc.origin, func(t *testing.T) {
			clearOptionalConfig(t)
			t.Setenv("HTTP_ADDR", "127.0.0.1:18080")
			t.Setenv("PUBLIC_URL", tc.origin)
			t.Setenv("SESSION_AGENT_PUBLIC_HOST", "obsolete.example.com")
			cfg, err := Load()
			if err != nil {
				t.Fatal(err)
			}
			if cfg.PublicURL != tc.wantURL || cfg.SessionAgentPublicHost != tc.wantHost || cfg.SessionAgentControlPlaneURL != "http://127.0.0.1:18080" {
				t.Fatal("public URL and session identity diverged or private callback changed")
			}
		})
	}
}

func TestPublicURLRejectsInvalidOrigins(t *testing.T) {
	for _, value := range []string{"example.com", "ftp://example.com", "https://user:password@example.com", "https://example.com/path", "https://example.com?x=1", "https://example.com?", "https://example.com#", "http://0.0.0.0", "http://[::]", "https://example.com:", "https://example.com:70000", "https://example.com:0", "https://*.example.com", "https://bad_host"} {
		t.Run(value, func(t *testing.T) {
			cfg := Config{PublicURL: value}
			if err := cfg.loadPublicURL(); err == nil {
				t.Fatal("invalid public URL accepted")
			}
		})
	}
	for _, mode := range []string{"docker", "kubernetes"} {
		cfg := Config{HTTPAddr: ":8080", GatewayRuntime: mode}
		if err := cfg.loadPublicURL(); err == nil {
			t.Fatal("container runtime silently advertised loopback without PUBLIC_URL")
		}
	}
}
