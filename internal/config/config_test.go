package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadDoesNotRequireLegacyTokenSecrets(t *testing.T) {
	clearOptionalConfig(t)
	if _, err := Load(); err != nil {
		t.Fatalf("Load error = %v", err)
	}
}

func TestSessionDurationLimitIsFiveHours(t *testing.T) {
	clearOptionalConfig(t)
	t.Setenv("SESSION_DEFAULT_TTL", "30m")
	t.Setenv("SESSION_MAX_TTL", "5h")
	value, err := Load()
	if err != nil || value.SessionDefaultTTL != 30*time.Minute || value.SessionMaxTTL != 5*time.Hour {
		t.Fatalf("valid session duration limits: %v", err)
	}
	t.Setenv("SESSION_MAX_TTL", "5h1s")
	if _, err := Load(); err == nil {
		t.Fatal("session duration over five hours accepted")
	}
}

func TestLoadAcceptsSecureDefaults(t *testing.T) {
	clearOptionalConfig(t)
	config, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if config.DBMaxOpenConns != config.DBMaxIdleConns || config.DBConnMaxLifetime <= 0 {
		t.Fatalf("database pool defaults = %+v", config)
	}
	if config.GatewayHealthInterval != 10*time.Second || config.GatewayHeartbeatMaxAge != 30*time.Second || config.GatewayHealthFailureThreshold != 3 {
		t.Fatalf("gateway health defaults = %+v", config)
	}
}

func TestLoadDemoMode(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value string
		want  bool
	}{
		{name: "disabled by default"},
		{name: "enabled", value: "true", want: true},
		{name: "explicitly disabled", value: "false"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clearOptionalConfig(t)
			t.Setenv("DEMO_MODE", tc.value)
			config, err := Load()
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if config.DemoMode != tc.want {
				t.Fatalf("DemoMode = %t, want %t", config.DemoMode, tc.want)
			}
		})
	}
	t.Run("invalid boolean", func(t *testing.T) {
		clearOptionalConfig(t)
		t.Setenv("DEMO_MODE", "invalid")
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "DEMO_MODE must be a boolean") {
			t.Fatalf("invalid demo mode error = %v", err)
		}
	})
}

func clearOptionalConfig(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"HTTP_ADDR", "PUBLIC_URL", "SESSION_AGENT_BINARY", "SESSION_AGENT_STATE_DIR", "SESSION_AGENT_DOCKER_SOCKET", "SESSION_AGENT_DOCKER_STATE_DIR", "SESSION_AGENT_BIND_HOST", "SESSION_AGENT_PORT_START", "SESSION_AGENT_PORT_END",
		"GATEWAY_RUNTIME", "SESSION_AGENT_NAMESPACE", "SESSION_AGENT_IMAGE", "SESSION_AGENT_NODE_NAME", "SESSION_AGENT_PUBLIC_HOST", "SESSION_AGENT_CONTROL_PLANE_URL", "SESSION_AGENT_ALLOW_AUDIT_HTTP", "SESSION_AGENT_STARTUP_TIMEOUT", "SESSION_AGENT_MAX_SESSIONS",
		"AUTH_LOCAL_ENABLED", "AUTH_TIMEOUT", "AUTH_ALLOW_INSECURE_HTTP", "OIDC_ENABLED", "OAUTH2_ENABLED", "LDAP_ENABLED",
		"OIDC_CLIENT_SECRET", "OIDC_CLIENT_SECRET_FILE", "OAUTH2_CLIENT_SECRET", "OAUTH2_CLIENT_SECRET_FILE", "LDAP_BIND_PASSWORD", "LDAP_BIND_PASSWORD_FILE",
		"FEISHU_LOGIN_ENABLED", "FEISHU_BINDING_ENABLED", "FEISHU_NOTIFICATIONS_ENABLED", "FEISHU_CALLBACKS_ENABLED",
		"DATABASE_URL", "DATABASE_URL_FILE", "ENCRYPTION_KEY_FILE",
		"FEISHU_APP_SECRET_FILE", "FEISHU_CALLBACK_SECRET_FILE", "AUDIT_COLLECTOR_SECRET", "AUDIT_COLLECTOR_SECRET_FILE",
		"METRICS_BEARER_TOKEN", "METRICS_BEARER_TOKEN_FILE",
		"GATEWAY_HEALTH_INTERVAL", "GATEWAY_HEALTH_FAILURE_THRESHOLD",
		"GATEWAY_HEARTBEAT_MAX_AGE",
		"FEISHU_APP_ID", "FEISHU_APP_SECRET",
		"FEISHU_REDIRECT_URL", "FEISHU_CALLBACK_SECRET", "FEISHU_TENANT_KEY", "SESSION_SECRET",
		"ASSET_ENCRYPTION_KEY_FILE", "ASSET_ENCRYPTION_KEY_ID", "REQUIRE_ASSET_ENCRYPTION",
		"CMDB_URL", "CMDB_SOURCE", "CMDB_BEARER_TOKEN", "CMDB_BEARER_TOKEN_FILE",
		"CMDB_SYNC_INTERVAL", "CMDB_TIMEOUT", "CMDB_ALLOW_INSECURE_HTTP",
		"DEMO_MODE",
	} {
		t.Setenv(key, "")
	}
	t.Setenv("ENCRYPTION_KEY", strings.Repeat("m", 32))
}

func TestLoadReadsSecretsFromProtectedFiles(t *testing.T) {
	clearOptionalConfig(t)
	secretPath := filepath.Join(t.TempDir(), "audit-collector-secret")
	if err := os.WriteFile(secretPath, []byte("0123456789abcdef0123456789abcdef\n"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	t.Setenv("AUDIT_COLLECTOR_SECRET", "")
	t.Setenv("AUDIT_COLLECTOR_SECRET_FILE", secretPath)
	config, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if config.AuditCollectorSecret != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("audit collector secret was not loaded from file")
	}
}

func TestLoadAssetEncryptionDefaultsAndOverrides(t *testing.T) {
	clearOptionalConfig(t)
	for _, required := range []string{"", "true", "false", "retired-option"} {
		t.Setenv("REQUIRE_ASSET_ENCRYPTION", required)
		if _, err := Load(); err != nil {
			t.Fatalf("encryption key asset encryption with legacy flag %q: %v", required, err)
		}
	}
	t.Setenv("ASSET_ENCRYPTION_KEY_ID", "key-1")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "configured together") {
		t.Fatalf("key ID without key file error = %v", err)
	}
	t.Setenv("ASSET_ENCRYPTION_KEY_ID", "")
	t.Setenv("ASSET_ENCRYPTION_KEY_FILE", "/run/secrets/asset-key")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "configured together") {
		t.Fatalf("partial encryption config error = %v", err)
	}
	t.Setenv("ASSET_ENCRYPTION_KEY_ID", "key-1")
	if _, err := Load(); err != nil {
		t.Fatalf("complete encryption config: %v", err)
	}
}

func TestLoadCMDBWithDefaultAssetEncryption(t *testing.T) {
	clearOptionalConfig(t)
	t.Setenv("CMDB_URL", "https://cmdb.example.test/assets")
	t.Setenv("CMDB_BEARER_TOKEN", strings.Repeat("c", 32))
	if _, err := Load(); err != nil {
		t.Fatalf("CMDB with encryption key asset encryption: %v", err)
	}
}

func TestLoadRejectsInvalidGatewayHealthSettings(t *testing.T) {
	clearOptionalConfig(t)
	t.Setenv("GATEWAY_HEALTH_INTERVAL", "6m")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "gateway health") {
		t.Fatalf("gateway health interval error = %v", err)
	}
	t.Setenv("GATEWAY_HEALTH_INTERVAL", "10s")
	t.Setenv("GATEWAY_HEARTBEAT_MAX_AGE", "5s")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "gateway health") {
		t.Fatalf("gateway heartbeat max age error = %v", err)
	}
	t.Setenv("GATEWAY_HEARTBEAT_MAX_AGE", "30s")
	t.Setenv("GATEWAY_HEALTH_FAILURE_THRESHOLD", "101")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "gateway health") {
		t.Fatalf("gateway health threshold error = %v", err)
	}
}

func TestLoadIgnoresRetiredAuthenticationEnvironment(t *testing.T) {
	clearOptionalConfig(t)
	t.Setenv("FEISHU_APP_ID", "app-id")
	t.Setenv("FEISHU_APP_SECRET", "app-secret")
	t.Setenv("FEISHU_REDIRECT_URL", "https://console.example/callback")
	t.Setenv("FEISHU_CALLBACK_SECRET", "0123456789abcdef0123456789abcdef")
	t.Setenv("SESSION_SECRET", "0123456789abcdef0123456789abcdef")
	if _, err := Load(); err != nil {
		t.Fatalf("retired Feishu variables must not affect startup: %v", err)
	}
}
