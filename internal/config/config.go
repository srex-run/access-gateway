package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/srex-run/access-gateway/internal/secretstore"
)

type Config struct {
	HTTPAddr                         string
	WebAssetsDir                     string
	PublicURL                        string
	DatabaseURL                      string
	DBMaxOpenConns                   int
	DBMaxIdleConns                   int
	DBConnMaxLifetime                time.Duration
	DBConnMaxIdleTime                time.Duration
	SessionDefaultTTL                time.Duration
	SessionMaxTTL                    time.Duration
	ApprovalTimeout                  time.Duration
	AllowDevAuth                     bool
	DemoMode                         bool
	GatewayRuntime                   string
	SessionAgentBinary               string
	SessionAgentStateDirectory       string
	SessionAgentDockerSocket         string
	SessionAgentDockerStateDirectory string
	SessionAgentBindHost             string
	SessionAgentPortStart            int
	SessionAgentPortEnd              int
	SessionAgentNamespace            string
	SessionAgentImage                string
	SessionAgentNodeName             string
	SessionAgentPublicHost           string
	SessionAgentControlPlaneURL      string
	SessionAgentAllowAuditHTTP       bool
	SessionAgentStartupTimeout       time.Duration
	SessionAgentMaxSessions          int
	GatewayHealthInterval            time.Duration
	GatewayHeartbeatMaxAge           time.Duration
	GatewayHealthFailureThreshold    int
	AuditCollectorSecret             string
	EncryptionKey                    string
	AssetEncryptionKeyFile           string
	AssetEncryptionKeyID             string
	CMDBURL                          string
	CMDBSource                       string
	CMDBBearerToken                  string
	CMDBSyncInterval                 time.Duration
	CMDBTimeout                      time.Duration
	CMDBAllowHTTP                    bool
	AdminUserIDs                     map[string]struct{}
	MetricsEnabled                   bool
	MetricsBearerToken               string
	OTELServiceName                  string
	OTLPTraceEndpoint                string
}

func Load() (Config, error) {
	c := Config{
		HTTPAddr:                         envOrDefault("HTTP_ADDR", ":8080"),
		WebAssetsDir:                     strings.TrimSpace(os.Getenv("WEB_ASSETS_DIR")),
		PublicURL:                        strings.TrimSpace(os.Getenv("PUBLIC_URL")),
		DBMaxOpenConns:                   10,
		DBMaxIdleConns:                   10,
		DBConnMaxLifetime:                30 * time.Minute,
		DBConnMaxIdleTime:                5 * time.Minute,
		SessionDefaultTTL:                time.Hour,
		SessionMaxTTL:                    5 * time.Hour,
		ApprovalTimeout:                  24 * time.Hour,
		AllowDevAuth:                     false,
		GatewayRuntime:                   envOrDefault("GATEWAY_RUNTIME", "local"),
		SessionAgentBinary:               envOrDefault("SESSION_AGENT_BINARY", "gateway-agent"),
		SessionAgentStateDirectory:       strings.TrimSpace(os.Getenv("SESSION_AGENT_STATE_DIR")),
		SessionAgentDockerSocket:         envOrDefault("SESSION_AGENT_DOCKER_SOCKET", "/var/run/docker.sock"),
		SessionAgentDockerStateDirectory: strings.TrimSpace(os.Getenv("SESSION_AGENT_DOCKER_STATE_DIR")),
		SessionAgentBindHost:             envOrDefault("SESSION_AGENT_BIND_HOST", "0.0.0.0"),
		SessionAgentPortStart:            20000,
		SessionAgentPortEnd:              20999,
		SessionAgentNamespace:            envOrDefault("SESSION_AGENT_NAMESPACE", "access-gateway"),
		SessionAgentImage:                strings.TrimSpace(os.Getenv("SESSION_AGENT_IMAGE")),
		SessionAgentNodeName:             strings.TrimSpace(os.Getenv("SESSION_AGENT_NODE_NAME")),
		SessionAgentControlPlaneURL:      strings.TrimSpace(os.Getenv("SESSION_AGENT_CONTROL_PLANE_URL")),
		SessionAgentStartupTimeout:       90 * time.Second,
		SessionAgentMaxSessions:          100,
		GatewayHealthInterval:            10 * time.Second,
		GatewayHeartbeatMaxAge:           30 * time.Second,
		GatewayHealthFailureThreshold:    3,
		AssetEncryptionKeyFile:           strings.TrimSpace(os.Getenv("ASSET_ENCRYPTION_KEY_FILE")),
		AssetEncryptionKeyID:             strings.TrimSpace(os.Getenv("ASSET_ENCRYPTION_KEY_ID")),
		CMDBURL:                          strings.TrimSpace(os.Getenv("CMDB_URL")),
		CMDBSource:                       envOrDefault("CMDB_SOURCE", "primary-cmdb"),
		CMDBSyncInterval:                 5 * time.Minute,
		CMDBTimeout:                      15 * time.Second,
		AdminUserIDs:                     parseSet(os.Getenv("ADMIN_USER_IDS")),
		MetricsEnabled:                   true,
		OTELServiceName:                  envOrDefault("OTEL_SERVICE_NAME", "access-gateway"),
		OTLPTraceEndpoint:                strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")),
	}

	var err error
	if err := c.loadPublicURL(); err != nil {
		return Config{}, err
	}
	if err := c.loadSessionRuntime(); err != nil {
		return Config{}, err
	}
	for _, secret := range []struct {
		name string
		dest *string
		trim bool
	}{
		{name: "DATABASE_URL", dest: &c.DatabaseURL},
		{name: "ENCRYPTION_KEY", dest: &c.EncryptionKey},
		{name: "AUDIT_COLLECTOR_SECRET", dest: &c.AuditCollectorSecret, trim: true},
		{name: "METRICS_BEARER_TOKEN", dest: &c.MetricsBearerToken, trim: true},
		{name: "CMDB_BEARER_TOKEN", dest: &c.CMDBBearerToken, trim: true},
	} {
		value, secretErr := secretstore.FromEnvironment(secret.name)
		if secretErr != nil {
			return Config{}, secretErr
		}
		if secret.trim {
			value = strings.TrimSpace(value)
		}
		*secret.dest = value
	}
	if c.DBMaxOpenConns, err = envInt("DB_MAX_OPEN_CONNS", c.DBMaxOpenConns); err != nil {
		return Config{}, err
	}
	if c.DBMaxIdleConns, err = envInt("DB_MAX_IDLE_CONNS", c.DBMaxIdleConns); err != nil {
		return Config{}, err
	}
	if c.DBConnMaxLifetime, err = envDuration("DB_CONN_MAX_LIFETIME", c.DBConnMaxLifetime); err != nil {
		return Config{}, err
	}
	if c.DBConnMaxIdleTime, err = envDuration("DB_CONN_MAX_IDLE_TIME", c.DBConnMaxIdleTime); err != nil {
		return Config{}, err
	}
	if c.SessionDefaultTTL, err = envDuration("SESSION_DEFAULT_TTL", c.SessionDefaultTTL); err != nil {
		return Config{}, err
	}
	if c.SessionMaxTTL, err = envDuration("SESSION_MAX_TTL", c.SessionMaxTTL); err != nil {
		return Config{}, err
	}
	if c.ApprovalTimeout, err = envDuration("APPROVAL_TIMEOUT", c.ApprovalTimeout); err != nil {
		return Config{}, err
	}
	if c.GatewayHealthInterval, err = envDuration("GATEWAY_HEALTH_INTERVAL", c.GatewayHealthInterval); err != nil {
		return Config{}, err
	}
	if c.GatewayHeartbeatMaxAge, err = envDuration("GATEWAY_HEARTBEAT_MAX_AGE", c.GatewayHeartbeatMaxAge); err != nil {
		return Config{}, err
	}
	if c.GatewayHealthFailureThreshold, err = envInt("GATEWAY_HEALTH_FAILURE_THRESHOLD", c.GatewayHealthFailureThreshold); err != nil {
		return Config{}, err
	}
	if c.AllowDevAuth, err = envBool("ALLOW_DEV_AUTH", c.AllowDevAuth); err != nil {
		return Config{}, err
	}
	if c.DemoMode, err = envBool("DEMO_MODE", c.DemoMode); err != nil {
		return Config{}, err
	}
	if c.MetricsEnabled, err = envBool("METRICS_ENABLED", c.MetricsEnabled); err != nil {
		return Config{}, err
	}
	if c.CMDBSyncInterval, err = envDuration("CMDB_SYNC_INTERVAL", c.CMDBSyncInterval); err != nil {
		return Config{}, err
	}
	if c.CMDBTimeout, err = envDuration("CMDB_TIMEOUT", c.CMDBTimeout); err != nil {
		return Config{}, err
	}
	if c.CMDBAllowHTTP, err = envBool("CMDB_ALLOW_INSECURE_HTTP", c.CMDBAllowHTTP); err != nil {
		return Config{}, err
	}
	if c.DBMaxOpenConns < 1 || c.DBMaxIdleConns < 1 || c.DBMaxIdleConns != c.DBMaxOpenConns {
		return Config{}, fmt.Errorf("database pool limits are invalid: DB_MAX_IDLE_CONNS must equal DB_MAX_OPEN_CONNS")
	}
	if c.DBConnMaxLifetime <= 0 || c.DBConnMaxIdleTime <= 0 {
		return Config{}, fmt.Errorf("database connection lifetime settings are invalid")
	}
	if c.SessionDefaultTTL <= 0 || c.SessionMaxTTL <= 0 || c.SessionDefaultTTL > c.SessionMaxTTL || c.SessionMaxTTL > 5*time.Hour || c.ApprovalTimeout <= 0 {
		return Config{}, fmt.Errorf("session TTL settings are invalid")
	}
	if c.GatewayHealthInterval > 5*time.Minute || c.GatewayHeartbeatMaxAge < c.GatewayHealthInterval || c.GatewayHeartbeatMaxAge > 15*time.Minute || c.GatewayHealthFailureThreshold > 100 {
		return Config{}, fmt.Errorf("gateway health settings are invalid")
	}
	if c.MetricsBearerToken != "" && len([]byte(c.MetricsBearerToken)) < 32 {
		return Config{}, fmt.Errorf("METRICS_BEARER_TOKEN must contain at least 32 bytes when configured")
	}
	if c.AuditCollectorSecret != "" && len([]byte(c.AuditCollectorSecret)) < 32 {
		return Config{}, fmt.Errorf("AUDIT_COLLECTOR_SECRET must contain at least 32 bytes when configured")
	}
	if err := validateOTLPEndpoint(c.OTLPTraceEndpoint); err != nil {
		return Config{}, err
	}
	assetEncryptionParts := 0
	if c.AssetEncryptionKeyFile != "" {
		assetEncryptionParts++
	}
	if c.AssetEncryptionKeyID != "" {
		assetEncryptionParts++
	}
	if assetEncryptionParts == 1 {
		return Config{}, fmt.Errorf("ASSET_ENCRYPTION_KEY_FILE and ASSET_ENCRYPTION_KEY_ID must be configured together")
	}
	if c.AssetEncryptionKeyFile != "" && !filepath.IsAbs(c.AssetEncryptionKeyFile) {
		return Config{}, fmt.Errorf("ASSET_ENCRYPTION_KEY_FILE must be an absolute path")
	}
	if c.CMDBURL != "" || c.CMDBBearerToken != "" {
		if c.CMDBURL == "" || len([]byte(c.CMDBBearerToken)) < 32 {
			return Config{}, fmt.Errorf("CMDB_URL and a CMDB_BEARER_TOKEN of at least 32 bytes must be configured together")
		}
		if !validCMDBSource(c.CMDBSource) {
			return Config{}, fmt.Errorf("CMDB_SOURCE is invalid")
		}
		parsed, parseErr := url.Parse(c.CMDBURL)
		if parseErr != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.Opaque != "" {
			return Config{}, fmt.Errorf("CMDB_URL is invalid")
		}
		if parsed.Scheme != "https" && !c.CMDBAllowHTTP {
			return Config{}, fmt.Errorf("CMDB_URL must use HTTPS unless CMDB_ALLOW_INSECURE_HTTP=true")
		}
		if c.CMDBSyncInterval > 24*time.Hour || c.CMDBTimeout > time.Minute {
			return Config{}, fmt.Errorf("CMDB synchronization timing is invalid")
		}
	}
	if len([]byte(c.EncryptionKey)) < 32 {
		return Config{}, fmt.Errorf("ENCRYPTION_KEY or ENCRYPTION_KEY_FILE must provide at least 32 bytes")
	}
	return c, nil
}

func validateOTLPEndpoint(value string) error {
	if value == "" {
		return nil
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT must be an HTTP(S) URL")
	}
	return nil
}

func parseSet(value string) map[string]struct{} {
	result := make(map[string]struct{})
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			result[item] = struct{}{}
		}
	}
	return result
}

func validCMDBSource(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}

func envOrDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envInt(key string, fallback int) (int, error) {
	value := os.Getenv(key)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be a positive integer: %w", key, err)
	}
	if parsed < 1 {
		return 0, fmt.Errorf("%s must be a positive integer", key)
	}
	return parsed, nil
}

func envDuration(key string, fallback time.Duration) (time.Duration, error) {
	value := os.Getenv(key)
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be a positive duration: %w", key, err)
	}
	if parsed <= 0 {
		return 0, fmt.Errorf("%s must be a positive duration", key)
	}
	return parsed, nil
}

func envBool(key string, fallback bool) (bool, error) {
	value := os.Getenv(key)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean: %w", key, err)
	}
	return parsed, nil
}
