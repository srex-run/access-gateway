package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/rs/zerolog"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/srex-run/access-gateway/internal/cloudassets"
	"github.com/srex-run/access-gateway/internal/cmdb"
	"github.com/srex-run/access-gateway/internal/config"
	"github.com/srex-run/access-gateway/internal/db"
	"github.com/srex-run/access-gateway/internal/gateway"
	"github.com/srex-run/access-gateway/internal/gatewayauth"
	"github.com/srex-run/access-gateway/internal/httpapi"
	"github.com/srex-run/access-gateway/internal/observability"
	"github.com/srex-run/access-gateway/internal/realtime"
	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/secretstore"
	"github.com/srex-run/access-gateway/internal/security"
	"github.com/srex-run/access-gateway/internal/service"
	"github.com/srex-run/access-gateway/internal/sessionruntime"
	"github.com/srex-run/access-gateway/internal/worker"
)

type Components struct {
	DB      *sql.DB
	Service *service.AccessService
	HTTP    *httpapi.Server
	Worker  *worker.Runner
	Metrics *observability.Metrics
	Close   func() error
}

func configuredAssetCipher(cfg config.Config) (secretstore.Cipher, error) {
	if cfg.AssetEncryptionKeyFile != "" || cfg.AssetEncryptionKeyID != "" {
		return secretstore.NewAESGCMFromFile(cfg.AssetEncryptionKeyID, cfg.AssetEncryptionKeyFile)
	}
	// Persisted envelope IDs and derivation purposes are compatibility contracts;
	// the ENCRYPTION_KEY rename must not change them or invalidate stored data.
	return secretstore.NewAESGCM("asset-master-v1", security.DeriveKey(cfg.EncryptionKey, "asset-targets"))
}

func Initialize(ctx context.Context, cfg config.Config, logger zerolog.Logger) (*Components, error) {
	database, err := db.Open(ctx, db.Config{
		URL: cfg.DatabaseURL, MaxOpenConns: cfg.DBMaxOpenConns, MaxIdleConns: cfg.DBMaxIdleConns,
		ConnMaxLifetime: cfg.DBConnMaxLifetime, ConnMaxIdleTime: cfg.DBConnMaxIdleTime,
	})
	if err != nil {
		return nil, err
	}
	schemaCtx, cancelSchemaCheck := context.WithTimeout(ctx, 10*time.Second)
	err = service.CheckDatabaseSchema(schemaCtx, database)
	cancelSchemaCheck()
	if err != nil {
		_ = database.Close()
		return nil, fmt.Errorf("database schema check failed: %w", err)
	}
	var closeRuntime func() error
	var closeRealtime func() error
	closeDatabase := func() error {
		var realtimeErr error
		if closeRealtime != nil {
			realtimeErr = closeRealtime()
		}
		var runtimeErr error
		if closeRuntime != nil {
			runtimeErr = closeRuntime()
		}
		return errors.Join(realtimeErr, runtimeErr, database.Close())
	}
	closeOnError := func(err error) (*Components, error) {
		_ = closeDatabase()
		return nil, err
	}

	var gatewayClient gateway.Client = gateway.UnavailableClient{}
	settingsCipher, err := secretstore.NewAESGCM("master-v1", security.DeriveKey(cfg.EncryptionKey, "system-settings"))
	if err != nil {
		return closeOnError(err)
	}
	systemSettings, err := service.NewSystemSettingsService(database, settingsCipher, cfg.PublicURL)
	if err != nil {
		return closeOnError(err)
	}
	if _, err := systemSettings.Current(ctx); err != nil {
		return closeOnError(fmt.Errorf("load system settings: %w", err))
	}
	auditProfiles := systemSettings
	sessionAuditCredentials, err := gatewayauth.NewSessionCredentials(security.DeriveKey(cfg.EncryptionKey, "session-agent-audit"))
	if err != nil {
		return closeOnError(err)
	}
	if cfg.GatewayRuntime == "local" || cfg.GatewayRuntime == "docker" {
		runtime, runtimeErr := sessionruntime.NewHostClient(sessionruntime.HostOptions{
			AuditProfiles: auditProfiles,
			Mode:          cfg.GatewayRuntime, StateDirectory: cfg.SessionAgentStateDirectory, AgentBinary: cfg.SessionAgentBinary,
			DockerSocket: cfg.SessionAgentDockerSocket, DockerStateDirectory: cfg.SessionAgentDockerStateDirectory,
			Image: cfg.SessionAgentImage, BindHost: cfg.SessionAgentBindHost, PortStart: cfg.SessionAgentPortStart, PortEnd: cfg.SessionAgentPortEnd,
			PublicAddress: cfg.SessionAgentPublicHost, ControlPlaneURL: cfg.SessionAgentControlPlaneURL,
			AllowAuditHTTP: cfg.SessionAgentAllowAuditHTTP, StartupTimeout: cfg.SessionAgentStartupTimeout,
			MaxSessions: cfg.SessionAgentMaxSessions, Credentials: sessionAuditCredentials, Logger: logger,
		})
		if runtimeErr != nil {
			return closeOnError(fmt.Errorf("configure session runtime: %w", runtimeErr))
		}
		gatewayClient, closeRuntime = runtime, runtime.Close
	} else if cfg.GatewayRuntime == "kubernetes" {
		clusterConfig, configErr := rest.InClusterConfig()
		if configErr != nil {
			return closeOnError(fmt.Errorf("load session Kubernetes configuration: %w", configErr))
		}
		clusterConfig.Timeout = 10 * time.Second
		kube, clientErr := kubernetes.NewForConfig(clusterConfig)
		if clientErr != nil {
			return closeOnError(fmt.Errorf("configure session Kubernetes client: %w", clientErr))
		}
		gatewayClient, err = sessionruntime.NewClient(kube, sessionruntime.Options{
			AuditProfiles: auditProfiles,
			Namespace:     cfg.SessionAgentNamespace, Image: cfg.SessionAgentImage, NodeName: cfg.SessionAgentNodeName,
			PublicAddress: cfg.SessionAgentPublicHost, ControlPlaneURL: cfg.SessionAgentControlPlaneURL,
			AllowAuditHTTP: cfg.SessionAgentAllowAuditHTTP, StartupTimeout: cfg.SessionAgentStartupTimeout,
			MaxSessions: cfg.SessionAgentMaxSessions, Credentials: sessionAuditCredentials,
		})
		if err != nil {
			return closeOnError(fmt.Errorf("configure session runtime: %w", err))
		}
	}
	if len([]byte(cfg.EncryptionKey)) < 32 {
		return closeOnError(fmt.Errorf("encryption key must contain at least 32 bytes"))
	}
	sessionSigner, err := security.NewSessionSigner(string(security.DeriveKey(cfg.EncryptionKey, "browser-session")))
	if err != nil {
		return closeOnError(err)
	}
	cloudCipher, err := secretstore.NewAESGCM("cloud-master-v1", security.DeriveKey(cfg.EncryptionKey, "cloud-assets"))
	if err != nil {
		return closeOnError(err)
	}
	transportCipher, err := secretstore.NewAESGCM("browser-transport-v1", security.DeriveKey(cfg.EncryptionKey, "browser-transport"))
	if err != nil {
		return closeOnError(err)
	}
	identityCipher, err := secretstore.NewAESGCM("identity-v1", security.DeriveKey(cfg.EncryptionKey, "identity-security"))
	if err != nil {
		return closeOnError(err)
	}
	transport, err := service.NewBrowserTransportService(database, transportCipher)
	if err != nil {
		return closeOnError(err)
	}
	assetEncryptor, err := configuredAssetCipher(cfg)
	if err != nil {
		return closeOnError(fmt.Errorf("configure asset encryption: %w", err))
	}
	var cmdbClient cmdb.Client
	if cfg.CMDBURL != "" {
		cmdbClient, err = cmdb.NewHTTPClient(cmdb.HTTPClientConfig{
			Endpoint: cfg.CMDBURL, BearerToken: cfg.CMDBBearerToken,
			Timeout: cfg.CMDBTimeout, AllowHTTP: cfg.CMDBAllowHTTP,
		})
		if err != nil {
			return closeOnError(fmt.Errorf("configure CMDB client: %w", err))
		}
	}
	users := repository.NewUserRepository()
	regions := repository.NewRegionRepository()
	gateways := repository.NewGatewayRepository()
	assets := repository.NewAssetRepository()
	requests := repository.NewAccessRequestRepository()
	approvals := repository.NewApprovalRepository()
	sessions := repository.NewSessionRepository()
	sessionEvents := repository.NewSessionEventRepository()
	audits := repository.NewAuditEventRepository()
	accessEvidence := repository.NewAccessEvidenceRepository()
	outbox := repository.NewOutboxEventRepository()
	callbackEvents := repository.NewCallbackEventRepository()
	tokenDeliveries := repository.NewSessionTokenDeliveryRepository()
	oauthStates := repository.NewOAuthStateRepository()
	queue := worker.NewQueue(256)
	metrics, err := observability.NewMetrics("access_gateway")
	if err != nil {
		return closeOnError(fmt.Errorf("configure metrics: %w", err))
	}
	svc, err := service.NewAccessService(service.ServiceOptions{
		PublicURL: cfg.PublicURL, GatewayMaxSessions: cfg.SessionAgentMaxSessions,
		AuditProfiles: auditProfiles,
		CloudCipher:   cloudCipher, CloudDiscoverer: cloudassets.NewClient(),
		DB: database, Users: users, Regions: regions,
		Gateways: gateways, Assets: assets,
		Requests: requests, Approvals: approvals,
		Sessions: sessions, SessionEvents: sessionEvents,
		Audits: audits, AccessEvidence: accessEvidence, Outbox: outbox, Gateway: gatewayClient, Notifier: systemSettings,
		TokenDeliveries: tokenDeliveries, OAuthStates: oauthStates,
		Tasks: queue, Logger: logger,
		DefaultTTL: cfg.SessionDefaultTTL, MaxTTL: cfg.SessionMaxTTL, ApprovalTimeout: cfg.ApprovalTimeout,
		DemoMode:               cfg.DemoMode,
		GatewayHeartbeatMaxAge: cfg.GatewayHeartbeatMaxAge,
		AdminUserIDs:           cfg.AdminUserIDs, SystemSettings: systemSettings,
		IdentityCipher: identityCipher,
		AssetEncryptor: assetEncryptor,
		CMDB:           cmdbClient, CMDBSource: cfg.CMDBSource,
	})
	if err != nil {
		return closeOnError(fmt.Errorf("build service: %w", err))
	}
	runner, err := worker.NewRunnerWithOptions(queue, svc, logger, worker.RunnerOptions{
		RecoveryInterval:              time.Minute,
		GatewayHealthInterval:         cfg.GatewayHealthInterval,
		GatewayHealthFailureThreshold: cfg.GatewayHealthFailureThreshold,
		CMDBSyncInterval:              configuredCMDBInterval(cfg),
		Metrics:                       metrics,
	})
	if err != nil {
		return closeOnError(fmt.Errorf("build worker: %w", err))
	}
	listener, err := realtime.Start(ctx, cfg.DatabaseURL, logger)
	if err != nil {
		return closeOnError(err)
	}
	closeRealtime = listener.Close
	httpServer, err := httpapi.NewServerWithOptions(httpapi.ServerOptions{
		Realtime:  listener.Hub,
		PublicURL: cfg.PublicURL,
		Transport: transport,
		Settings:  systemSettings, Authentication: svc,
		Service: svc, DB: database, AllowDevAuth: cfg.AllowDevAuth,
		SessionSigner:           sessionSigner,
		SessionAuditCredentials: sessionAuditCredentials,
		AuditCollectorSecret:    cfg.AuditCollectorSecret, Logger: logger,
		CallbackEvents: callbackEvents,
		OAuthStates:    oauthStates,
		Metrics:        metrics, MetricsEnabled: cfg.MetricsEnabled, MetricsBearerToken: cfg.MetricsBearerToken,
	})
	if err != nil {
		return closeOnError(fmt.Errorf("build HTTP server: %w", err))
	}
	return &Components{DB: database, Service: svc, HTTP: httpServer, Worker: runner, Metrics: metrics, Close: closeDatabase}, nil
}

func configuredCMDBInterval(cfg config.Config) time.Duration {
	if cfg.CMDBURL == "" {
		return 0
	}
	return cfg.CMDBSyncInterval
}
