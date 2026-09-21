package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/emicklei/go-restful/v3"
	"github.com/rs/zerolog"

	"github.com/srex-run/access-gateway/internal/authn"
	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/feishu"
	"github.com/srex-run/access-gateway/internal/gateway"
	"github.com/srex-run/access-gateway/internal/gatewayauth"
	"github.com/srex-run/access-gateway/internal/observability"
	"github.com/srex-run/access-gateway/internal/operationaudit"
	"github.com/srex-run/access-gateway/internal/publicurl"
	"github.com/srex-run/access-gateway/internal/realtime"
	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/security"
	"github.com/srex-run/access-gateway/internal/service"
)

type Server struct {
	Realtime                *realtime.Hub
	publicOrigin            *url.URL
	MFA                     MFAService
	Invitations             InvitationService
	Transport               BrowserTransport
	Settings                SystemSettingsService
	Authentication          AuthenticationService
	AuthConfig              authn.Config
	RedirectProviders       map[string]authn.RedirectProvider
	LDAP                    authn.PasswordProvider
	LoginAttempts           LoginAttemptStore
	FeishuLoginEnabled      bool
	FeishuBindingEnabled    bool
	Service                 BackendService
	DB                      Database
	AllowDevAuth            bool
	FeishuCallbackSecret    string
	FeishuTenantKey         string
	OAuth                   *feishu.OAuthClient
	SessionSigner           *security.SessionSigner
	SessionCookieName       string
	FrontendRedirect        string
	GatewayInternalSecret   string
	GatewayAuditAuthMode    gatewayauth.Mode
	GatewayAuthenticator    gatewayauth.Authenticator
	SessionAuditCredentials *gatewayauth.SessionCredentials
	AuditCollectorSecret    string
	CallbackEvents          CallbackEventStore
	OAuthStates             OAuthStateStore
	Logger                  zerolog.Logger
	Metrics                 *observability.Metrics
	MetricsEnabled          bool
	MetricsBearerToken      string
	seenMu                  sync.Mutex
	seenCallbacks           map[string]time.Time
}

type Database interface {
	repository.DBTX
	PingContext(ctx context.Context) error
}

type CallbackEventStore interface {
	Claim(ctx context.Context, q repository.DBTX, eventID string, lease time.Duration) (bool, error)
	MarkProcessed(ctx context.Context, q repository.DBTX, eventID string) error
	Release(ctx context.Context, q repository.DBTX, eventID string) error
}

type OAuthStateStore interface {
	Create(ctx context.Context, q repository.DBTX, state domain.OAuthState) (domain.OAuthState, error)
	Consume(ctx context.Context, q repository.DBTX, stateHash string) (bool, error)
}

type BackendService interface {
	SyncFeishuUser(context.Context, feishu.Profile) (domain.User, error)
	CheckActiveUser(context.Context, string) error
	Authorize(context.Context, string, authz.Permission) error
	ListRegions(context.Context) ([]domain.Region, error)
	ListAssets(context.Context, string, string) ([]domain.Asset, error)
	ListManagedAssets(context.Context, string) ([]domain.Asset, error)
	ListAssetPorts(context.Context, string, string) ([]domain.AssetPort, error)
	CreateRegion(context.Context, string, service.CreateRegionInput) (domain.Region, error)
	UpdateRegionStatus(context.Context, string, string, domain.ResourceStatus) (domain.Region, error)
	CreateGateway(context.Context, string, service.CreateGatewayInput) (domain.Gateway, error)
	UpdateGatewayStatus(context.Context, string, string, domain.ResourceStatus) (domain.Gateway, error)
	UpdateGatewayCapacity(context.Context, string, string, int) (domain.Gateway, error)
	UpdateGatewayAuthSecretRef(context.Context, string, string, string) (domain.Gateway, error)
	ListGatewayCatalog(context.Context, string, string) ([]domain.GatewayCatalogEntry, error)
	CreateAsset(context.Context, string, service.CreateAssetInput) (domain.Asset, error)
	UpdateAsset(context.Context, string, string, service.UpdateAssetInput) (domain.Asset, error)
	UpdateAssetStatus(context.Context, string, string, domain.ResourceStatus) (domain.Asset, error)
	BindAssetGateway(context.Context, string, string, string, int) error
	ListAssetGatewayBindings(context.Context, string, string) ([]domain.AssetGatewayBinding, error)
	UpdateAssetGatewayBinding(context.Context, string, string, string, service.UpdateAssetGatewayBindingInput) (domain.AssetGatewayBinding, error)
	GrantRole(context.Context, string, service.GrantRoleInput) (domain.RoleAssignment, error)
	RevokeRole(context.Context, string, string) (domain.RoleAssignment, error)
	ListRoleAssignments(context.Context, string, string) ([]domain.RoleAssignment, error)
	CreateAssetPort(context.Context, string, string, domain.AssetPort) (domain.AssetPort, error)
	DeleteAssetPort(context.Context, string, string, string) error
	DeleteAsset(context.Context, string, string) error
	CreateAssetApprover(context.Context, string, string, domain.AssetApprover) (domain.AssetApprover, error)
	CreateAccessRequest(context.Context, service.CreateRequestInput) (domain.AccessRequest, error)
	ListMyAccessRequests(context.Context, string, int, int) ([]domain.AccessRequest, error)
	ListPendingApprovals(context.Context, string, int, int) ([]domain.Approval, error)
	DecideApproval(context.Context, string, string, domain.ApprovalDecision, *string) (service.ApprovalResult, error)
	GetAccessRequest(context.Context, string, string) (domain.AccessRequest, error)
	CancelAccessRequest(context.Context, string, string) (domain.AccessRequest, error)
	DecideApprovalByExternalUser(context.Context, string, string, domain.ApprovalDecision, *string) (service.ApprovalResult, error)
	GetSession(context.Context, string, string) (service.SessionView, error)
	GetSessionByRequest(context.Context, string, string) (service.SessionView, error)
	CloseSession(context.Context, string, string) (domain.Session, error)
	ForceCloseSession(context.Context, string, string, string) (domain.Session, error)
	ListSessionEvents(context.Context, string, string, int, int) ([]domain.SessionEvent, error)
	ListAuditEvents(context.Context, string, domain.AuditFilter) ([]domain.AuditEvent, error)
	ListOperationAuditEvents(context.Context, string, domain.OperationAuditFilter) ([]domain.OperationAuditEvent, error)
	RecordGatewayEvent(context.Context, service.GatewayEventInput) error
	RecordOperationAuditBatch(context.Context, []service.OperationAuditInput) (int, error)
	RecordSessionOperations(context.Context, string, string, []operationaudit.SessionEvent) ([]string, error)
}

func NewServer(svc BackendService, database Database, allowDevAuth bool, callbackSecret string, logger zerolog.Logger) (*Server, error) {
	return NewServerWithOptions(ServerOptions{
		Service: svc, DB: database, AllowDevAuth: allowDevAuth,
		FeishuCallbackSecret: callbackSecret, Logger: logger,
	})
}

type ServerOptions struct {
	Realtime                *realtime.Hub
	PublicURL               string
	MFA                     MFAService
	Invitations             InvitationService
	Transport               BrowserTransport
	Settings                SystemSettingsService
	Authentication          AuthenticationService
	AuthConfig              authn.Config
	RedirectProviders       map[string]authn.RedirectProvider
	LDAP                    authn.PasswordProvider
	LoginAttempts           LoginAttemptStore
	FeishuLoginEnabled      bool
	FeishuBindingEnabled    bool
	Service                 BackendService
	DB                      Database
	AllowDevAuth            bool
	FeishuCallbackSecret    string
	FeishuTenantKey         string
	OAuth                   *feishu.OAuthClient
	SessionSigner           *security.SessionSigner
	SessionCookieName       string
	FrontendRedirect        string
	GatewayInternalSecret   string
	GatewayAuditAuthMode    gatewayauth.Mode
	GatewayAuthenticator    gatewayauth.Authenticator
	SessionAuditCredentials *gatewayauth.SessionCredentials
	AuditCollectorSecret    string
	CallbackEvents          CallbackEventStore
	OAuthStates             OAuthStateStore
	Logger                  zerolog.Logger
	Metrics                 *observability.Metrics
	MetricsEnabled          bool
	MetricsBearerToken      string
}

func NewServerWithOptions(options ServerOptions) (*Server, error) {
	var publicOrigin *url.URL
	if options.PublicURL != "" {
		var err error
		publicOrigin, err = publicurl.Parse(options.PublicURL)
		if err != nil {
			return nil, err
		}
	}
	svc := options.Service
	if options.MFA == nil {
		options.MFA, _ = svc.(MFAService)
	}
	if options.Invitations == nil {
		options.Invitations, _ = svc.(InvitationService)
	}
	database := options.DB
	if svc == nil || database == nil {
		return nil, fmt.Errorf("http server requires service and database")
	}
	if options.SessionCookieName == "" {
		options.SessionCookieName = "access_gateway_session"
	}
	if options.Settings != nil && (options.SessionSigner == nil || options.Authentication == nil || options.OAuthStates == nil) {
		return nil, fmt.Errorf("system settings require browser authentication and durable OAuth states")
	}
	if options.FrontendRedirect == "" {
		options.FrontendRedirect = "/"
	}
	options.FrontendRedirect = strings.TrimSpace(options.FrontendRedirect)
	if err := validateFrontendRedirect(options.FrontendRedirect); err != nil {
		return nil, err
	}
	if (options.OAuth != nil || len(options.RedirectProviders) > 0) && options.OAuthStates == nil {
		return nil, fmt.Errorf("http server requires a durable OAuth state store when OAuth is configured")
	}
	if options.AuthConfig.Enabled() || options.FeishuLoginEnabled || options.FeishuBindingEnabled {
		if options.SessionSigner == nil || options.Authentication == nil {
			return nil, fmt.Errorf("platform authentication requires a session signer and account service")
		}
	}
	if (options.FeishuLoginEnabled || options.FeishuBindingEnabled) && options.OAuth == nil {
		return nil, fmt.Errorf("enabled Feishu login or binding requires an OAuth client")
	}
	if options.AuthConfig.OIDC.Enabled && options.RedirectProviders["oidc"] == nil {
		return nil, fmt.Errorf("enabled OIDC login requires a provider")
	}
	if options.AuthConfig.OAuth2.Enabled && options.RedirectProviders["oauth2"] == nil {
		return nil, fmt.Errorf("enabled OAuth2 login requires a provider")
	}
	if options.AuthConfig.GitHub.Enabled && options.RedirectProviders["github"] == nil {
		return nil, fmt.Errorf("enabled GitHub login requires a provider")
	}
	if options.AuthConfig.LDAP.Enabled && options.LDAP == nil {
		return nil, fmt.Errorf("enabled LDAP login requires a provider")
	}
	if options.LoginAttempts == nil {
		options.LoginAttempts = &repository.LoginAttemptRepository{}
	}
	if options.AuditCollectorSecret != "" && len([]byte(options.AuditCollectorSecret)) < 32 {
		return nil, fmt.Errorf("http server audit collector secret must contain at least 32 bytes")
	}
	mode, err := gatewayauth.ParseMode(string(options.GatewayAuditAuthMode))
	if err != nil {
		return nil, fmt.Errorf("http server: %w", err)
	}
	if options.GatewayInternalSecret != "" && len([]byte(options.GatewayInternalSecret)) < 32 {
		return nil, fmt.Errorf("http server gateway internal secret must contain at least 32 bytes")
	}
	if mode == gatewayauth.ModeTransition && len([]byte(options.GatewayInternalSecret)) < 32 {
		return nil, fmt.Errorf("http server transition gateway audit authentication requires the shared secret")
	}
	if mode != gatewayauth.ModeShared && options.GatewayAuthenticator == nil {
		return nil, fmt.Errorf("http server %s gateway audit authentication requires an authenticator", mode)
	}
	return &Server{
		MFA: options.MFA, Invitations: options.Invitations,
		Transport:      options.Transport,
		Settings:       options.Settings,
		publicOrigin:   publicOrigin,
		Authentication: options.Authentication, AuthConfig: options.AuthConfig,
		RedirectProviders: options.RedirectProviders, LDAP: options.LDAP, LoginAttempts: options.LoginAttempts,
		FeishuLoginEnabled: options.FeishuLoginEnabled, FeishuBindingEnabled: options.FeishuBindingEnabled,
		Service:                 svc,
		Realtime:                options.Realtime,
		DB:                      database,
		AllowDevAuth:            options.AllowDevAuth,
		FeishuCallbackSecret:    options.FeishuCallbackSecret,
		FeishuTenantKey:         strings.TrimSpace(options.FeishuTenantKey),
		OAuth:                   options.OAuth,
		SessionSigner:           options.SessionSigner,
		SessionCookieName:       options.SessionCookieName,
		FrontendRedirect:        options.FrontendRedirect,
		GatewayInternalSecret:   options.GatewayInternalSecret,
		GatewayAuditAuthMode:    mode,
		GatewayAuthenticator:    options.GatewayAuthenticator,
		SessionAuditCredentials: options.SessionAuditCredentials,
		AuditCollectorSecret:    options.AuditCollectorSecret,
		CallbackEvents:          options.CallbackEvents,
		OAuthStates:             options.OAuthStates,
		Logger:                  options.Logger,
		Metrics:                 options.Metrics,
		MetricsEnabled:          options.MetricsEnabled,
		MetricsBearerToken:      strings.TrimSpace(options.MetricsBearerToken),
		seenCallbacks:           make(map[string]time.Time),
	}, nil
}

func (s *Server) Container() *restful.Container {
	container := restful.NewContainer()
	container.Router(restful.CurlyRouter{})
	container.Filter(s.securityFilter)
	container.Filter(s.csrfFilter)
	container.Filter(s.settingsFilter)
	container.Filter(s.metricsFilter)
	container.Filter(s.authorizationFilter)
	container.Filter(s.transportFilter)
	ws := new(restful.WebService)
	ws.Path("/api/v1").Consumes(restful.MIME_JSON).Produces(restful.MIME_JSON)
	postWithoutContentType := []string{http.MethodPost}
	deleteWithoutContentType := []string{http.MethodDelete}
	ws.Route(ws.GET("/admin/settings").To(s.getSettings))
	ws.Route(ws.PATCH("/admin/settings").To(s.saveSettings))
	ws.Route(ws.POST("/admin/settings/audit/certificates").To(s.generateAuditCertificate))
	ws.Route(ws.GET("/admin/cloud-accounts").To(s.listCloudAccounts))
	ws.Route(ws.POST("/admin/cloud-accounts").To(s.saveCloudAccount))
	ws.Route(ws.PATCH("/admin/cloud-accounts/{account_id}").To(s.saveCloudAccount))
	ws.Route(ws.POST("/admin/cloud-accounts/{account_id}/sync").To(s.queueCloudSync))
	ws.Route(ws.GET("/admin/cloud-sync-jobs").To(s.listCloudSyncJobs))
	ws.Route(ws.GET("/admin/cloud-sync-gateways").To(s.listCloudSyncGateways))
	ws.Route(ws.POST("/admin/gateways/{gateway_id}/release").AllowedMethodsWithoutContentType(postWithoutContentType).To(s.exportGatewayRelease))
	ws.Route(ws.GET("/auth/providers").To(s.loginProviders))
	ws.Route(ws.POST("/auth/transport/challenges").To(s.createTransportChallenge))
	ws.Route(ws.POST("/auth/local/login").To(s.passwordLogin))
	ws.Route(ws.POST("/auth/ldap/login").To(s.passwordLogin))
	ws.Route(ws.GET("/auth/{provider}/login").To(s.externalLogin))
	ws.Route(ws.GET("/auth/{provider}/callback").To(s.externalCallback))
	ws.Route(ws.GET("/auth/account").To(s.account))
	ws.Route(ws.POST("/auth/password").To(s.changePassword))
	ws.Route(ws.POST("/auth/feishu/bind").AllowedMethodsWithoutContentType(postWithoutContentType).To(s.bindFeishu))
	ws.Route(ws.DELETE("/auth/feishu/bind").AllowedMethodsWithoutContentType(deleteWithoutContentType).To(s.unbindFeishu))
	ws.Route(ws.POST("/auth/logout").AllowedMethodsWithoutContentType(postWithoutContentType).To(s.logout))
	ws.Route(ws.GET("/auth/me").To(s.identity))
	ws.Route(ws.GET("/notifications").To(s.listNotifications))
	ws.Route(ws.GET("/events").Produces("text/event-stream", restful.MIME_JSON).To(s.streamEvents))
	ws.Route(ws.POST("/notifications/read").AllowedMethodsWithoutContentType(postWithoutContentType).To(s.markNotificationRead))
	ws.Route(ws.POST("/notifications/{notification_id}/read").AllowedMethodsWithoutContentType(postWithoutContentType).To(s.markNotificationRead))
	s.registerIdentitySecurity(ws)
	ws.Route(ws.GET("/approvals/pending").To(s.listPendingApprovals))
	ws.Route(ws.POST("/approvals/{approval_id}/approve").To(s.approve))
	ws.Route(ws.POST("/approvals/{approval_id}/reject").To(s.reject))
	ws.Route(ws.GET("/regions").To(s.listRegions))
	ws.Route(ws.GET("/regions/{region_id}/assets").To(s.listAssets))
	ws.Route(ws.GET("/assets/{asset_id}/ports").To(s.listAssetPorts))
	ws.Route(ws.POST("/access-requests").To(s.createAccessRequest))
	ws.Route(ws.POST("/admin/access-tests").To(s.createTestAccessRequest))
	ws.Route(ws.GET("/admin/users").To(s.listUsers))
	s.registerGovernance(ws)
	ws.Route(ws.POST("/admin/users").To(s.createLocalUser))
	ws.Route(ws.GET("/admin/assets/{asset_id}/approvers").To(s.listAssetApprovers))
	ws.Route(ws.GET("/assets/{asset_id}/approvers").To(s.listRequestApprovers))
	ws.Route(ws.GET("/access-requests").To(s.listAccessRequests))
	ws.Route(ws.GET("/access-requests/{request_id}").To(s.getAccessRequest))
	ws.Route(ws.GET("/access-requests/{request_id}/session").To(s.getSessionByRequest))
	ws.Route(ws.POST("/access-requests/{request_id}/cancel").AllowedMethodsWithoutContentType(postWithoutContentType).To(s.cancelAccessRequest))
	ws.Route(ws.GET("/sessions/{session_id}").To(s.getSession))
	ws.Route(ws.GET("/sessions/{session_id}/terminal").To(s.webTerminal))
	ws.Route(ws.POST("/sessions/{session_id}/terminal/preflight").AllowedMethodsWithoutContentType(postWithoutContentType).To(s.webTerminalPreflight))
	ws.Route(ws.POST("/sessions/{session_id}/terminal/demo-defaults").To(s.terminalDemoDefaults))
	ws.Route(ws.GET("/access-options").To(s.accessOptions))
	ws.Route(ws.GET("/sessions/{session_id}/events").To(s.listSessionEvents))
	ws.Route(ws.GET("/session-records").To(s.listSessionRecords))
	ws.Route(ws.GET("/session-records/{session_id}").To(s.getSessionRecord))
	ws.Route(ws.GET("/session-records/{session_id}/trace").To(s.listSessionTrace))
	ws.Route(ws.GET("/session-records/{session_id}/terminal-recordings/{channel_id}").To(s.listTerminalRecording))
	ws.Route(ws.GET("/access-requests/{request_id}/record").To(s.getSessionRecord))
	ws.Route(ws.POST("/sessions/{session_id}/close").AllowedMethodsWithoutContentType(postWithoutContentType).To(s.closeSession))
	ws.Route(ws.POST("/admin/sessions/{session_id}/force-close").AllowedMethodsWithoutContentType(postWithoutContentType).To(s.forceCloseSession))
	ws.Route(ws.GET("/audit-events").To(s.listAuditEvents))
	ws.Route(ws.GET("/operation-audit-events").To(s.listOperationAuditEvents))
	ws.Route(ws.GET("/operation-audit-sessions").To(s.listOperationAuditSessions))
	ws.Route(ws.POST("/admin/regions").To(s.createRegion))
	ws.Route(ws.PATCH("/admin/regions/{region_id}/status").To(s.updateRegionStatus))
	ws.Route(ws.POST("/admin/gateways").To(s.createGateway))
	ws.Route(ws.GET("/admin/gateway-runtime").To(s.gatewayRuntime))
	ws.Route(ws.PATCH("/admin/gateways/{gateway_id}/status").To(s.updateGatewayStatus))
	ws.Route(ws.PATCH("/admin/gateways/{gateway_id}/capacity").To(s.updateGatewayCapacity))
	ws.Route(ws.PATCH("/admin/gateways/{gateway_id}/credential-reference").To(s.updateGatewayCredentialReference))
	ws.Route(ws.GET("/admin/gateways/{gateway_id}/catalog").To(s.listGatewayCatalog))
	ws.Route(ws.GET("/admin/assets").To(s.listManagedAssets))
	ws.Route(ws.POST("/admin/assets").To(s.createAsset))
	ws.Route(ws.POST("/admin/assets/audit/certificates").To(s.generateAssetAuditCertificate))
	ws.Route(ws.GET("/admin/assets/{asset_id}/audit").To(s.getAssetAudit))
	ws.Route(ws.PATCH("/admin/assets/{asset_id}").To(s.updateAsset))
	ws.Route(ws.DELETE("/admin/assets/{asset_id}").AllowedMethodsWithoutContentType(deleteWithoutContentType).To(s.deleteAsset))
	ws.Route(ws.POST("/admin/assets/{asset_id}/gateways").To(s.bindAssetGateway))
	ws.Route(ws.GET("/admin/assets/{asset_id}/gateways").To(s.listAssetGatewayBindings))
	ws.Route(ws.PATCH("/admin/assets/{asset_id}/gateways/{gateway_id}").To(s.updateAssetGatewayBinding))
	ws.Route(ws.PATCH("/admin/assets/{asset_id}/status").To(s.updateAssetStatus))
	ws.Route(ws.POST("/admin/assets/{asset_id}/ports").To(s.createAssetPort))
	ws.Route(ws.DELETE("/admin/assets/{asset_id}/ports/{port_id}").AllowedMethodsWithoutContentType(deleteWithoutContentType).To(s.deleteAssetPort))
	ws.Route(ws.POST("/admin/assets/{asset_id}/approvers").To(s.createAssetApprover))
	ws.Route(ws.GET("/admin/role-assignments").To(s.listRoleAssignments))
	ws.Route(ws.POST("/admin/role-assignments").To(s.grantRole))
	ws.Route(ws.DELETE("/admin/role-assignments/{assignment_id}").AllowedMethodsWithoutContentType(deleteWithoutContentType).To(s.revokeRole))
	container.Add(ws)

	callbacks := new(restful.WebService)
	callbacks.Path("/callbacks").Consumes(restful.MIME_JSON).Produces(restful.MIME_JSON)
	callbacks.Route(callbacks.POST("/feishu").To(s.feishuCallback))
	container.Add(callbacks)

	internal := new(restful.WebService)
	internal.Path("/internal/gateway").Consumes(restful.MIME_JSON).Produces(restful.MIME_JSON)
	internal.Route(internal.POST("/events").To(s.gatewayEvent))
	internal.Route(internal.POST("/events/batch").To(s.gatewayEventBatch))
	internal.Route(internal.POST("/operations/batch").To(s.sessionOperationBatch))
	container.Add(internal)
	collectors := new(restful.WebService)
	collectors.Path("/internal/audit").Consumes(restful.MIME_JSON).Produces(restful.MIME_JSON)
	collectors.Route(collectors.POST("/operations/batch").To(s.operationAuditBatch))
	container.Add(collectors)

	health := new(restful.WebService)
	health.Path("").Produces(restful.MIME_JSON)
	health.Route(health.GET("/healthz").To(s.health))
	health.Route(health.GET("/readyz").To(s.ready))
	container.Add(health)
	if s.MetricsEnabled && s.Metrics != nil {
		container.Handle("/metrics", s.Metrics.Handler(s.MetricsBearerToken))
	}
	return container
}

func (s *Server) securityFilter(request *restful.Request, response *restful.Response, chain *restful.FilterChain) {
	if encryptedTerminalPath.MatchString(request.SelectedRoutePath()) || strings.HasSuffix(request.SelectedRoutePath(), "/terminal/preflight") {
		defer func() {
			if response.StatusCode() >= http.StatusBadRequest {
				s.Logger.Warn().Str("session_id", request.PathParameter("session_id")).
					Str("stage", "terminal_http").Int("status", response.StatusCode()).Msg("web terminal request rejected")
			}
		}()
	}
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.Header().Set("Referrer-Policy", "no-referrer")
	response.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	if request.Request.Body != nil {
		request.Request.Body = http.MaxBytesReader(response.ResponseWriter, request.Request.Body, 1<<20)
	}
	chain.ProcessFilter(request, response)
}

func (s *Server) csrfFilter(request *restful.Request, response *restful.Response, chain *restful.FilterChain) {
	if !strings.HasPrefix(request.Request.URL.Path, "/api/v1/") || csrfSafeMethod(request.Request.Method) {
		chain.ProcessFilter(request, response)
		return
	}
	route := request.SelectedRoutePath()
	loginRequest := route == "/api/v1/auth/local/login" || route == "/api/v1/auth/ldap/login" || route == "/api/v1/auth/transport/challenges" || anonymousIdentityRoute(route) || pendingMFARoute(route)
	if _, err := request.Request.Cookie(s.SessionCookieName); err != nil && !loginRequest {
		chain.ProcessFilter(request, response)
		return
	}
	source := strings.TrimSpace(request.Request.Header.Get("Origin"))
	if source == "" {
		source = strings.TrimSpace(request.Request.Header.Get("Referer"))
	}
	if !s.sameRequestOrigin(request.Request, source) {
		_ = response.WriteHeaderAndEntity(http.StatusForbidden, errorResponse{
			Error: "request origin does not match the configured public URL",
			Code:  "origin_mismatch",
		})
		return
	}
	chain.ProcessFilter(request, response)
}

func csrfSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

func (s *Server) sameRequestOrigin(request *http.Request, source string) bool {
	if source == "" || strings.EqualFold(source, "null") {
		return false
	}
	parsed, err := url.Parse(source)
	if err != nil || parsed.User != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return false
	}
	scheme := "http"
	if s.secureRequest(request) {
		scheme = "https"
	}
	authority := request.Host
	if s.publicOrigin != nil {
		authority = s.publicOrigin.Host
	}
	return strings.EqualFold(parsed.Scheme, scheme) && strings.EqualFold(canonicalAuthority(parsed.Host, parsed.Scheme), canonicalAuthority(authority, scheme))
}

func canonicalAuthority(authority, scheme string) string {
	host, port, err := net.SplitHostPort(authority)
	if err != nil {
		return strings.TrimSuffix(strings.ToLower(authority), ".")
	}
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		return strings.TrimSuffix(strings.ToLower(host), ".")
	}
	return net.JoinHostPort(strings.TrimSuffix(strings.ToLower(host), "."), port)
}

func (s *Server) metricsFilter(request *restful.Request, response *restful.Response, chain *restful.FilterChain) {
	startedAt := time.Now()
	chain.ProcessFilter(request, response)
	status := response.StatusCode()
	if status == 0 {
		status = http.StatusOK
	}
	s.Metrics.ObserveHTTP(request.Request.Method, request.SelectedRoutePath(), status, time.Since(startedAt))
}

func (s *Server) authorizationFilter(request *restful.Request, response *restful.Response, chain *restful.FilterChain) {
	// go-restful also runs container filters when routing fails. Let the router
	// return its error for an absent route; registered routes still fail closed.
	if request.SelectedRoutePath() == "" {
		chain.ProcessFilter(request, response)
		return
	}
	// Evidence readers need one of these read-capable roles. The service also
	// checks record membership; mutation routes retain their original permission.
	if isSessionRecordRoute(request.Request.Method, request.SelectedRoutePath()) || isOperationAuditRoute(request.Request.Method, request.SelectedRoutePath()) {
		actor, ok := s.currentUser(request, response)
		if !ok {
			return
		}
		permissions := []authz.Permission{authz.PermissionSessionManage, authz.PermissionApprovalManage, authz.PermissionAuditRead}
		if isOperationAuditRoute(request.Request.Method, request.SelectedRoutePath()) {
			permissions = []authz.Permission{authz.PermissionSessionManage, authz.PermissionAuditRead}
		}
		if request.SelectedRoutePath() == "/api/v1/session-records" && request.QueryParameter("status") == "open" {
			permissions = append(permissions, authz.PermissionSessionOverride)
		}
		for _, permission := range permissions {
			err := s.Service.Authorize(request.Request.Context(), actor, permission)
			if err == nil {
				chain.ProcessFilter(request, response)
				return
			}
			if !errors.Is(err, service.ErrForbidden) {
				s.writeError(response, err)
				return
			}
		}
		s.writeError(response, service.ErrForbidden)
		return
	}
	permission, protected := routePermission(request.Request.Method, request.SelectedRoutePath())
	if !protected {
		switch routeAccessException(request.Request.Method, request.SelectedRoutePath()) {
		case "authenticated":
			actor, ok := s.currentUser(request, response)
			if !ok {
				return
			}
			if err := s.requireActive(request.Request.Context(), actor); err != nil {
				s.writeError(response, err)
				return
			}
		case "public", "pending_mfa", "transport_target", "service_credentials":
			// The handler verifies credentials appropriate to this route.
		default:
			s.writeError(response, service.ErrForbidden)
			return
		}
		chain.ProcessFilter(request, response)
		return
	}
	userID, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	if err := s.Service.Authorize(request.Request.Context(), userID, permission); err != nil {
		s.writeError(response, err)
		return
	}
	chain.ProcessFilter(request, response)
}

func routePermission(method, path string) (authz.Permission, bool) {
	if path == "/api/v1/access-options" {
		return authz.PermissionRequestManage, true
	}
	if !strings.HasPrefix(path, "/api/v1/") || strings.HasPrefix(path, "/api/v1/auth/") {
		return "", false
	}
	if strings.HasPrefix(path, "/api/v1/admin/sessions/") {
		return authz.PermissionSessionOverride, true
	}
	if path == "/api/v1/admin/access-tests" {
		return authz.PermissionRoleManage, true
	}
	if strings.HasPrefix(path, "/api/v1/admin/users/") && strings.HasSuffix(path, "/mfa") && method != http.MethodGet {
		return authz.PermissionRoleManage, true
	}
	if path == "/api/v1/admin/invitations" || strings.HasPrefix(path, "/api/v1/admin/invitations/") {
		if method == http.MethodGet {
			return authz.PermissionUserRead, true
		}
		return authz.PermissionUserManage, true
	}
	if path == "/api/v1/admin/users" || strings.HasPrefix(path, "/api/v1/admin/users/") {
		if method == http.MethodGet {
			return authz.PermissionUserRead, true
		}
		return authz.PermissionUserManage, true
	}
	if path == "/api/v1/admin/roles" || path == "/api/v1/admin/permissions" || strings.HasPrefix(path, "/api/v1/admin/role-bindings") {
		return authz.PermissionRoleManage, true
	}
	if path == "/api/v1/admin/workflows" || strings.HasPrefix(path, "/api/v1/admin/ownerships") || (strings.HasPrefix(path, "/api/v1/admin/assets/") && strings.HasSuffix(path, "/labels")) {
		return authz.PermissionWorkflowManage, true
	}
	if strings.HasPrefix(path, "/api/v1/admin/role-assignments") || path == "/api/v1/admin/settings" || strings.HasPrefix(path, "/api/v1/admin/settings/") {
		return authz.PermissionRoleManage, true
	}
	if strings.HasPrefix(path, "/api/v1/admin/cloud-accounts") && method != http.MethodGet && !strings.HasSuffix(path, "/sync") {
		return authz.PermissionRoleManage, true
	}
	if strings.HasPrefix(path, "/api/v1/admin/") {
		return authz.PermissionCatalogManage, true
	}
	if path == "/api/v1/audit-events" {
		return authz.PermissionAuditRead, true
	}
	if path == "/api/v1/operation-audit-events" || path == "/api/v1/operation-audit-sessions" {
		return authz.PermissionSessionManage, true
	}
	if strings.HasPrefix(path, "/api/v1/access-requests") {
		return authz.PermissionRequestManage, true
	}
	if strings.HasPrefix(path, "/api/v1/approvals/") {
		return authz.PermissionApprovalManage, true
	}
	if strings.HasPrefix(path, "/api/v1/sessions") || strings.HasPrefix(path, "/api/v1/session-records") {
		return authz.PermissionSessionManage, true
	}
	if method == http.MethodGet && (path == "/api/v1/regions" || strings.HasPrefix(path, "/api/v1/regions/") || strings.HasPrefix(path, "/api/v1/assets/")) {
		return authz.PermissionDirectoryRead, true
	}
	return "", false
}

type createAccessRequestBody struct {
	RegionID         string     `json:"region_id"`
	AssetID          string     `json:"asset_id"`
	TargetPort       int        `json:"target_port"`
	SourceIP         string     `json:"source_ip"`
	TargetAccount    string     `json:"target_account"`
	Reason           string     `json:"reason"`
	TicketNo         *string    `json:"ticket_no"`
	RequestedStartAt *time.Time `json:"requested_start_at"`
	TTLSeconds       int        `json:"ttl_seconds"`
	Emergency        bool       `json:"emergency"`
}

type forceCloseBody struct {
	Reason string `json:"reason"`
}

type feishuCallbackBody struct {
	Type       string  `json:"type"`
	Challenge  string  `json:"challenge"`
	TenantKey  string  `json:"tenant_key"`
	ApprovalID string  `json:"approval_id"`
	ApproverID string  `json:"approver_id"`
	Decision   string  `json:"decision"`
	Comment    *string `json:"comment"`
	Header     struct {
		EventID   string `json:"event_id"`
		TenantKey string `json:"tenant_key"`
	} `json:"header"`
	Event struct {
		Operator struct {
			OpenID     string `json:"open_id"`
			OperatorID struct {
				OpenID string `json:"open_id"`
			} `json:"operator_id"`
		} `json:"operator"`
		Action struct {
			Value json.RawMessage `json:"value"`
		} `json:"action"`
	} `json:"event"`
}

type gatewayEventBody struct {
	EventID           string    `json:"event_id"`
	GatewayID         string    `json:"gateway_id"`
	ConnectionID      string    `json:"connection_id"`
	SessionID         string    `json:"session_id"`
	EventType         string    `json:"event_type"`
	SourceIP          *string   `json:"source_ip"`
	BackendSourceIP   *string   `json:"backend_source_ip"`
	BackendSourcePort *int      `json:"backend_source_port"`
	BytesUp           *int64    `json:"bytes_up"`
	BytesDown         *int64    `json:"bytes_down"`
	DurationMS        *int64    `json:"duration_ms"`
	Result            *string   `json:"result"`
	Reason            *string   `json:"reason"`
	OccurredAt        time.Time `json:"occurred_at"`
}

type gatewayEventBatchBody struct {
	Events []gatewayEventBody `json:"events"`
}

type operationAuditBatchBody struct {
	Events []service.OperationAuditInput `json:"events"`
}

type createRegionBody struct {
	Code   string `json:"code"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

type createGatewayBody struct {
	RegionID           string  `json:"region_id"`
	Name               string  `json:"name"`
	ManagementEndpoint string  `json:"management_endpoint"`
	PublicEndpoint     string  `json:"public_endpoint"`
	AuthSecretRef      *string `json:"auth_secret_ref"`
	Status             string  `json:"status"`
	MaxSessions        int     `json:"max_sessions"`
}

type updateGatewayCapacityBody struct {
	MaxSessions int `json:"max_sessions"`
}

type updateGatewayCredentialReferenceBody struct {
	AuthSecretRef string `json:"auth_secret_ref"`
}

type updateResourceStatusBody struct {
	Status string `json:"status"`
}

type bindAssetGatewayBody struct {
	GatewayID string `json:"gateway_id"`
	Priority  *int   `json:"priority"`
}

type updateAssetGatewayBindingBody struct {
	Enabled  bool `json:"enabled"`
	Priority int  `json:"priority"`
}

type createAssetBody struct {
	ApprovalWorkflowID *string                   `json:"approval_workflow_id"`
	RegionID           string                    `json:"region_id"`
	GatewayID          string                    `json:"gateway_id"`
	Name               string                    `json:"name"`
	AssetType          string                    `json:"asset_type"`
	Target             string                    `json:"target"`
	TargetCiphertext   string                    `json:"target_ciphertext"`
	RiskLevel          string                    `json:"risk_level"`
	MaxTTLSeconds      int                       `json:"max_ttl_seconds"`
	Status             string                    `json:"status"`
	Audit              *service.AssetAuditUpdate `json:"audit"`
}

type createAssetPortBody struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

type createAssetApproverBody struct {
	UserID        string `json:"user_id"`
	ApprovalLevel int    `json:"approval_level"`
	Role          string `json:"role"`
}

type grantRoleBody struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
}

type regionResponse struct {
	ID     string `json:"id"`
	Code   string `json:"code"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

type assetResponse struct {
	ApprovalWorkflowID *string    `json:"approval_workflow_id,omitempty"`
	ID                 string     `json:"id"`
	RegionID           string     `json:"region_id"`
	Name               string     `json:"name"`
	AssetType          string     `json:"asset_type"`
	RiskLevel          string     `json:"risk_level"`
	MaxTTLSeconds      int        `json:"max_ttl_seconds"`
	Status             string     `json:"status"`
	ExternalSource     *string    `json:"external_source,omitempty"`
	ExternalID         *string    `json:"external_id,omitempty"`
	LastSyncedAt       *time.Time `json:"last_synced_at,omitempty"`
}

func toAssetResponse(value domain.Asset) assetResponse {
	return assetResponse{ID: value.ID, RegionID: value.RegionID, Name: value.Name, AssetType: value.AssetType,
		RiskLevel: string(value.RiskLevel), MaxTTLSeconds: value.MaxTTLSeconds, Status: string(value.Status),
		ExternalSource: value.ExternalSource, ExternalID: value.ExternalID, LastSyncedAt: value.LastSyncedAt, ApprovalWorkflowID: value.ApprovalWorkflowID}
}

type assetGatewayBindingResponse struct {
	AssetID   string    `json:"asset_id"`
	GatewayID string    `json:"gateway_id"`
	Priority  int       `json:"priority"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type gatewayCatalogEntryResponse struct {
	TargetID       string  `json:"target_id"`
	ExternalSource *string `json:"external_source,omitempty"`
	ExternalID     *string `json:"external_id,omitempty"`
	Ports          []int   `json:"ports"`
}

type gatewayCatalogResponse struct {
	Version   int                           `json:"version"`
	GatewayID string                        `json:"gateway_id"`
	Assets    []gatewayCatalogEntryResponse `json:"assets"`
}

type assetPortResponse struct {
	ID                    string `json:"id"`
	AssetID               string `json:"asset_id"`
	Port                  int    `json:"port"`
	Protocol              string `json:"protocol"`
	TargetAccountRequired bool   `json:"target_account_required"`
}

type assetApproverResponse struct {
	ID            string    `json:"id"`
	AssetID       string    `json:"asset_id"`
	UserID        string    `json:"user_id"`
	ApprovalLevel int       `json:"approval_level"`
	Role          string    `json:"role"`
	Enabled       bool      `json:"enabled"`
	CreatedAt     time.Time `json:"created_at"`
}

type roleAssignmentResponse struct {
	ID        string     `json:"id"`
	UserID    string     `json:"user_id"`
	Role      string     `json:"role"`
	GrantedBy string     `json:"granted_by"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

type sessionEventResponse struct {
	ID        string         `json:"id"`
	SessionID string         `json:"session_id"`
	EventType string         `json:"event_type"`
	ActorType string         `json:"actor_type"`
	ActorID   *string        `json:"actor_id,omitempty"`
	Metadata  map[string]any `json:"metadata"`
	CreatedAt time.Time      `json:"created_at"`
}

type auditEventResponse struct {
	domain.AuditClassification
	ID            string         `json:"id"`
	EventType     string         `json:"event_type"`
	ActorType     string         `json:"actor_type"`
	ActorID       *string        `json:"actor_id,omitempty"`
	ActorName     string         `json:"actor_name,omitempty"`
	ActorUsername string         `json:"actor_username,omitempty"`
	SubjectUserID *string        `json:"subject_user_id,omitempty"`
	RequestID     *string        `json:"request_id,omitempty"`
	SessionID     *string        `json:"session_id,omitempty"`
	RegionID      *string        `json:"region_id,omitempty"`
	AssetID       *string        `json:"asset_id,omitempty"`
	TargetPort    *int           `json:"target_port,omitempty"`
	SourceIP      *string        `json:"source_ip,omitempty"`
	ClientVersion *string        `json:"client_version,omitempty"`
	Result        *string        `json:"result,omitempty"`
	Reason        *string        `json:"reason,omitempty"`
	Metadata      map[string]any `json:"metadata"`
	CreatedAt     time.Time      `json:"created_at"`
}

type operationAuditEventResponse struct {
	EventID              string         `json:"event_id"`
	ConnectionID         *string        `json:"connection_id,omitempty"`
	SessionID            *string        `json:"session_id,omitempty"`
	Protocol             string         `json:"protocol"`
	AssetID              string         `json:"asset_id"`
	TargetPort           int            `json:"target_port"`
	ActualAccount        string         `json:"actual_account"`
	OperationType        string         `json:"operation_type"`
	StatementFingerprint *string        `json:"statement_fingerprint,omitempty"`
	NormalizedOperation  *string        `json:"normalized_operation,omitempty"`
	ObjectName           *string        `json:"object_name,omitempty"`
	Result               string         `json:"result"`
	DurationMS           *int64         `json:"duration_ms,omitempty"`
	BackendSourceIP      string         `json:"backend_source_ip"`
	BackendSourcePort    int            `json:"backend_source_port"`
	SourceRecordID       string         `json:"source_record_id"`
	CorrelationStatus    string         `json:"correlation_status"`
	OccurredAt           time.Time      `json:"occurred_at"`
	Metadata             map[string]any `json:"metadata"`
	CreatedAt            time.Time      `json:"created_at"`
}

type accessRequestResponse struct {
	ApprovalMode     string     `json:"approval_mode"`
	ID               string     `json:"id"`
	ApplicantID      string     `json:"applicant_id"`
	AssetID          string     `json:"asset_id"`
	TargetPort       int        `json:"target_port"`
	SourceIP         *string    `json:"source_ip,omitempty"`
	TargetAccount    *string    `json:"target_account,omitempty"`
	Reason           string     `json:"reason"`
	TicketNo         *string    `json:"ticket_no,omitempty"`
	Emergency        bool       `json:"emergency"`
	RequestedStartAt *time.Time `json:"requested_start_at,omitempty"`
	TTLSeconds       int        `json:"ttl_seconds"`
	Status           string     `json:"status"`
	IdempotencyKey   string     `json:"idempotency_key"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

type sessionResponse struct {
	CanWebConnect   bool                       `json:"can_web_connect"`
	AuditPolicy     operationaudit.Policy      `json:"audit_policy,omitempty,omitzero"`
	ConnectionMode  string                     `json:"connection_mode"`
	SourceIP        *string                    `json:"source_ip,omitempty"`
	TargetAccount   *string                    `json:"target_account,omitempty"`
	CanConnect      bool                       `json:"can_connect"`
	ID              string                     `json:"id"`
	RequestID       string                     `json:"request_id"`
	GatewayID       string                     `json:"gateway_id"`
	Status          string                     `json:"status"`
	RemoteProcessID *string                    `json:"remote_process_id,omitempty"`
	StartedAt       *time.Time                 `json:"started_at,omitempty"`
	ExpiresAt       *time.Time                 `json:"expires_at,omitempty"`
	ClosedAt        *time.Time                 `json:"closed_at,omitempty"`
	FailureReason   *string                    `json:"failure_reason,omitempty"`
	GatewayEndpoint string                     `json:"gateway_endpoint,omitempty"`
	AuditTrust      *service.SessionAuditTrust `json:"audit_trust,omitempty"`
	GatewayHost     string                     `json:"gateway_host,omitempty"`
	GatewayPort     int                        `json:"gateway_port,omitempty"`
	ListenerPort    *int                       `json:"listener_port,omitempty"`
	ExposureMode    *string                    `json:"exposure_mode,omitempty"`
	ExposureRef     *string                    `json:"exposure_ref,omitempty"`
	TargetPort      int                        `json:"target_port,omitempty"`
	CreatedAt       time.Time                  `json:"created_at"`
	UpdatedAt       time.Time                  `json:"updated_at"`
}

type errorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code,omitempty"`
}

var errUnauthenticated = errors.New("authentication required")

// decodeJSONBody is the single JSON request-body boundary for the HTTP API.
// go-restful's ReadEntity uses the standard decoder but permits unknown fields
// and, depending on the reader, a second JSON value. Rejecting both keeps an
// authenticated request from being interpreted differently by different
// handlers or proxies.
func decodeJSONBody(request *http.Request, target any, allowEmpty bool) error {
	if request == nil || request.Body == nil {
		if allowEmpty {
			return nil
		}
		return fmt.Errorf("JSON request body is required")
	}
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		if err == io.EOF && allowEmpty {
			return nil
		}
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

func (s *Server) listRegions(request *restful.Request, response *restful.Response) {
	userID, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	if err := s.requireActive(request.Request.Context(), userID); err != nil {
		s.writeError(response, err)
		return
	}
	values, err := s.Service.ListRegions(request.Request.Context())
	if err != nil {
		s.writeError(response, err)
		return
	}
	result := make([]regionResponse, 0, len(values))
	for _, value := range values {
		result = append(result, regionResponse{ID: value.ID, Code: value.Code, Name: value.Name, Status: string(value.Status)})
	}
	_ = response.WriteEntity(result)
}

func (s *Server) createRegion(request *restful.Request, response *restful.Response) {
	actorID, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	var body createRegionBody
	if err := decodeJSONBody(request.Request, &body, false); err != nil {
		s.writeError(response, fmt.Errorf("decode region: %w", service.ErrValidation))
		return
	}
	value, err := s.Service.CreateRegion(request.Request.Context(), actorID, service.CreateRegionInput{Code: body.Code, Name: body.Name, Status: domain.ResourceStatus(body.Status)})
	if err != nil {
		s.writeError(response, err)
		return
	}
	_ = response.WriteHeaderAndEntity(http.StatusCreated, regionResponse{ID: value.ID, Code: value.Code, Name: value.Name, Status: string(value.Status)})
}

func (s *Server) updateRegionStatus(request *restful.Request, response *restful.Response) {
	actorID, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	var body updateResourceStatusBody
	if err := decodeJSONBody(request.Request, &body, false); err != nil {
		s.writeError(response, fmt.Errorf("decode region status: %w", service.ErrValidation))
		return
	}
	value, err := s.Service.UpdateRegionStatus(request.Request.Context(), actorID, request.PathParameter("region_id"), domain.ResourceStatus(body.Status))
	if err != nil {
		s.writeError(response, err)
		return
	}
	_ = response.WriteEntity(regionResponse{ID: value.ID, Code: value.Code, Name: value.Name, Status: string(value.Status)})
}

func (s *Server) createGateway(request *restful.Request, response *restful.Response) {
	actorID, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	var body createGatewayBody
	if err := decodeJSONBody(request.Request, &body, false); err != nil {
		s.writeError(response, fmt.Errorf("decode gateway: %w", service.ErrValidation))
		return
	}
	value, err := s.Service.CreateGateway(request.Request.Context(), actorID, service.CreateGatewayInput{RegionID: body.RegionID, Name: body.Name, ManagementEndpoint: body.ManagementEndpoint, PublicEndpoint: body.PublicEndpoint, AuthSecretRef: body.AuthSecretRef, Status: domain.ResourceStatus(body.Status), MaxSessions: body.MaxSessions})
	if err != nil {
		s.writeError(response, err)
		return
	}
	_ = response.WriteHeaderAndEntity(http.StatusCreated, map[string]any{"id": value.ID, "region_id": value.RegionID, "name": value.Name, "public_endpoint": value.PublicEndpoint, "status": value.Status, "max_sessions": value.MaxSessions})
}

func (s *Server) updateGatewayStatus(request *restful.Request, response *restful.Response) {
	actorID, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	var body updateResourceStatusBody
	if err := decodeJSONBody(request.Request, &body, false); err != nil {
		s.writeError(response, fmt.Errorf("decode gateway status: %w", service.ErrValidation))
		return
	}
	value, err := s.Service.UpdateGatewayStatus(request.Request.Context(), actorID, request.PathParameter("gateway_id"), domain.ResourceStatus(body.Status))
	if err != nil {
		s.writeError(response, err)
		return
	}
	_ = response.WriteEntity(map[string]any{"id": value.ID, "region_id": value.RegionID, "name": value.Name, "public_endpoint": value.PublicEndpoint, "status": value.Status, "max_sessions": value.MaxSessions})
}

func (s *Server) updateGatewayCapacity(request *restful.Request, response *restful.Response) {
	actorID, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	var body updateGatewayCapacityBody
	if err := decodeJSONBody(request.Request, &body, false); err != nil {
		s.writeError(response, fmt.Errorf("decode gateway capacity: %w", service.ErrValidation))
		return
	}
	value, err := s.Service.UpdateGatewayCapacity(request.Request.Context(), actorID, request.PathParameter("gateway_id"), body.MaxSessions)
	if err != nil {
		s.writeError(response, err)
		return
	}
	_ = response.WriteEntity(map[string]any{"id": value.ID, "max_sessions": value.MaxSessions, "updated_at": value.UpdatedAt})
}

func (s *Server) updateGatewayCredentialReference(request *restful.Request, response *restful.Response) {
	actorID, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	var body updateGatewayCredentialReferenceBody
	if err := decodeJSONBody(request.Request, &body, false); err != nil {
		s.writeError(response, fmt.Errorf("decode gateway credential reference: %w", service.ErrValidation))
		return
	}
	value, err := s.Service.UpdateGatewayAuthSecretRef(request.Request.Context(), actorID, request.PathParameter("gateway_id"), body.AuthSecretRef)
	if err != nil {
		s.writeError(response, err)
		return
	}
	_ = response.WriteEntity(map[string]any{"id": value.ID, "updated_at": value.UpdatedAt})
}

func (s *Server) listGatewayCatalog(request *restful.Request, response *restful.Response) {
	actorID, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	gatewayID := strings.TrimSpace(request.PathParameter("gateway_id"))
	values, err := s.Service.ListGatewayCatalog(request.Request.Context(), actorID, gatewayID)
	if err != nil {
		s.writeError(response, err)
		return
	}
	assets := make([]gatewayCatalogEntryResponse, 0, len(values))
	for _, value := range values {
		assets = append(assets, gatewayCatalogEntryResponse{
			TargetID: value.TargetID, ExternalSource: value.ExternalSource,
			ExternalID: value.ExternalID, Ports: value.Ports,
		})
	}
	_ = response.WriteEntity(gatewayCatalogResponse{Version: 1, GatewayID: gatewayID, Assets: assets})
}

func (s *Server) listManagedAssets(request *restful.Request, response *restful.Response) {
	actorID, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	values, err := s.Service.ListManagedAssets(request.Request.Context(), actorID)
	if err != nil {
		s.writeError(response, err)
		return
	}
	result := make([]assetResponse, 0, len(values))
	for _, value := range values {
		result = append(result, toAssetResponse(value))
	}
	_ = response.WriteEntity(result)
}

func (s *Server) createAsset(request *restful.Request, response *restful.Response) {
	actorID, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	var body createAssetBody
	if err := decodeJSONBody(request.Request, &body, false); err != nil {
		s.writeError(response, assetBodyValidation(err))
		return
	}
	value, err := s.Service.CreateAsset(request.Request.Context(), actorID, service.CreateAssetInput{RegionID: body.RegionID, GatewayID: body.GatewayID, Name: body.Name, AssetType: body.AssetType, Target: body.Target, TargetCiphertext: body.TargetCiphertext, RiskLevel: domain.RiskLevel(body.RiskLevel), MaxTTLSeconds: body.MaxTTLSeconds, Status: domain.ResourceStatus(body.Status), Audit: body.Audit, ApprovalWorkflowID: body.ApprovalWorkflowID})
	if err != nil {
		s.writeError(response, err)
		return
	}
	_ = response.WriteHeaderAndEntity(http.StatusCreated, toAssetResponse(value))
}

func (s *Server) updateAsset(request *restful.Request, response *restful.Response) {
	actorID, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	var body service.UpdateAssetInput
	if err := decodeJSONBody(request.Request, &body, false); err != nil {
		s.writeError(response, assetBodyValidation(err))
		return
	}
	value, err := s.Service.UpdateAsset(request.Request.Context(), actorID, request.PathParameter("asset_id"), body)
	if err != nil {
		s.writeError(response, err)
		return
	}
	_ = response.WriteEntity(toAssetResponse(value))
}

func (s *Server) updateAssetStatus(request *restful.Request, response *restful.Response) {
	actorID, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	var body updateResourceStatusBody
	if err := decodeJSONBody(request.Request, &body, false); err != nil {
		s.writeError(response, fmt.Errorf("decode asset status: %w", service.ErrValidation))
		return
	}
	value, err := s.Service.UpdateAssetStatus(request.Request.Context(), actorID, request.PathParameter("asset_id"), domain.ResourceStatus(body.Status))
	if err != nil {
		s.writeError(response, err)
		return
	}
	_ = response.WriteEntity(toAssetResponse(value))
}

func (s *Server) bindAssetGateway(request *restful.Request, response *restful.Response) {
	actorID, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	var body bindAssetGatewayBody
	if err := decodeJSONBody(request.Request, &body, false); err != nil {
		s.writeError(response, fmt.Errorf("decode asset gateway binding: %w", service.ErrValidation))
		return
	}
	priority := 100
	if body.Priority != nil {
		priority = *body.Priority
	}
	if err := s.Service.BindAssetGateway(request.Request.Context(), actorID, request.PathParameter("asset_id"), body.GatewayID, priority); err != nil {
		s.writeError(response, err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func (s *Server) listAssetGatewayBindings(request *restful.Request, response *restful.Response) {
	actorID, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	values, err := s.Service.ListAssetGatewayBindings(request.Request.Context(), actorID, request.PathParameter("asset_id"))
	if err != nil {
		s.writeError(response, err)
		return
	}
	result := make([]assetGatewayBindingResponse, 0, len(values))
	for _, value := range values {
		result = append(result, toAssetGatewayBindingResponse(value))
	}
	_ = response.WriteEntity(result)
}

func (s *Server) updateAssetGatewayBinding(request *restful.Request, response *restful.Response) {
	actorID, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	var body updateAssetGatewayBindingBody
	if err := decodeJSONBody(request.Request, &body, false); err != nil {
		s.writeError(response, fmt.Errorf("decode asset gateway binding: %w", service.ErrValidation))
		return
	}
	value, err := s.Service.UpdateAssetGatewayBinding(request.Request.Context(), actorID, request.PathParameter("asset_id"), request.PathParameter("gateway_id"), service.UpdateAssetGatewayBindingInput{Enabled: body.Enabled, Priority: body.Priority})
	if err != nil {
		s.writeError(response, err)
		return
	}
	_ = response.WriteEntity(toAssetGatewayBindingResponse(value))
}

func toAssetGatewayBindingResponse(value domain.AssetGatewayBinding) assetGatewayBindingResponse {
	return assetGatewayBindingResponse{AssetID: value.AssetID, GatewayID: value.GatewayID, Priority: value.Priority, Enabled: value.Enabled, CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt}
}

func (s *Server) createAssetPort(request *restful.Request, response *restful.Response) {
	actorID, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	var body createAssetPortBody
	if err := decodeJSONBody(request.Request, &body, false); err != nil {
		s.writeError(response, fmt.Errorf("decode asset port: %w", service.ErrValidation))
		return
	}
	value, err := s.Service.CreateAssetPort(request.Request.Context(), actorID, request.PathParameter("asset_id"), domain.AssetPort{Port: body.Port, Protocol: body.Protocol})
	if err != nil {
		s.writeError(response, err)
		return
	}
	_ = response.WriteHeaderAndEntity(http.StatusCreated, assetPortResponse{ID: value.ID, AssetID: value.AssetID, Port: value.Port, Protocol: value.Protocol})
}

func (s *Server) deleteAssetPort(request *restful.Request, response *restful.Response) {
	actorID, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	if err := s.Service.DeleteAssetPort(request.Request.Context(), actorID, request.PathParameter("asset_id"), request.PathParameter("port_id")); err != nil {
		s.writeError(response, err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func (s *Server) createAssetApprover(request *restful.Request, response *restful.Response) {
	actorID, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	var body createAssetApproverBody
	if err := decodeJSONBody(request.Request, &body, false); err != nil {
		s.writeError(response, fmt.Errorf("decode asset approver: %w", service.ErrValidation))
		return
	}
	value, err := s.Service.CreateAssetApprover(request.Request.Context(), actorID, request.PathParameter("asset_id"), domain.AssetApprover{UserID: body.UserID, ApprovalLevel: body.ApprovalLevel, Role: body.Role})
	if err != nil {
		s.writeError(response, err)
		return
	}
	_ = response.WriteHeaderAndEntity(http.StatusCreated, toAssetApproverResponse(value))
}

func (s *Server) grantRole(request *restful.Request, response *restful.Response) {
	actorID, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	var body grantRoleBody
	if err := decodeJSONBody(request.Request, &body, false); err != nil {
		s.writeError(response, fmt.Errorf("decode role assignment: %w", service.ErrValidation))
		return
	}
	value, err := s.Service.GrantRole(request.Request.Context(), actorID, service.GrantRoleInput{UserID: body.UserID, Role: body.Role})
	if err != nil {
		s.writeError(response, err)
		return
	}
	_ = response.WriteHeaderAndEntity(http.StatusCreated, toRoleAssignmentResponse(value))
}

func (s *Server) revokeRole(request *restful.Request, response *restful.Response) {
	actorID, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	value, err := s.Service.RevokeRole(request.Request.Context(), actorID, request.PathParameter("assignment_id"))
	if err != nil {
		s.writeError(response, err)
		return
	}
	_ = response.WriteEntity(toRoleAssignmentResponse(value))
}

func (s *Server) listRoleAssignments(request *restful.Request, response *restful.Response) {
	actorID, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	values, err := s.Service.ListRoleAssignments(request.Request.Context(), actorID, request.QueryParameter("user_id"))
	if err != nil {
		s.writeError(response, err)
		return
	}
	result := make([]roleAssignmentResponse, 0, len(values))
	for _, value := range values {
		result = append(result, toRoleAssignmentResponse(value))
	}
	_ = response.WriteEntity(result)
}

func toRoleAssignmentResponse(value domain.RoleAssignment) roleAssignmentResponse {
	return roleAssignmentResponse{
		ID: value.ID, UserID: value.UserID, Role: value.Role, GrantedBy: value.GrantedBy,
		CreatedAt: value.CreatedAt, RevokedAt: value.RevokedAt,
	}
}

func (s *Server) logout(request *restful.Request, response *restful.Response) {
	s.clearPendingMFA(request, response)
	secure := s.secureRequest(request.Request)
	http.SetCookie(response.ResponseWriter, &http.Cookie{
		Name:     s.SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
	_ = response.WriteEntity(map[string]string{"status": "logged_out"})
}

func (s *Server) listAssets(request *restful.Request, response *restful.Response) {
	userID, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	regionID := request.PathParameter("region_id")
	values, err := s.Service.ListAssets(request.Request.Context(), userID, regionID)
	if err != nil {
		s.writeError(response, err)
		return
	}
	result := make([]assetResponse, 0, len(values))
	for _, value := range values {
		result = append(result, toAssetResponse(value))
	}
	_ = response.WriteEntity(result)
}

func (s *Server) listAssetPorts(request *restful.Request, response *restful.Response) {
	userID, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	values, err := s.Service.ListAssetPorts(request.Request.Context(), userID, request.PathParameter("asset_id"))
	if err != nil {
		s.writeError(response, err)
		return
	}
	result := make([]assetPortResponse, 0, len(values))
	for _, value := range values {
		result = append(result, assetPortResponse{ID: value.ID, AssetID: value.AssetID, Port: value.Port, Protocol: value.Protocol, TargetAccountRequired: value.TargetAccountRequired})
	}
	_ = response.WriteEntity(result)
}

func (s *Server) createAccessRequest(request *restful.Request, response *restful.Response) {
	s.createRequestWithMode(request, response, false)
}

func (s *Server) createRequestWithMode(request *restful.Request, response *restful.Response, testAccess bool) {
	userID, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	var body createAccessRequestBody
	if err := decodeJSONBody(request.Request, &body, false); err != nil {
		s.writeError(response, &service.RequestValidationError{Message: "申请格式不正确，请检查端口、时长和预约时间后重试"})
		return
	}
	idempotencyKey := strings.TrimSpace(request.Request.Header.Get("Idempotency-Key"))
	input := service.CreateRequestInput{
		ApplicantID: userID, RegionID: body.RegionID, AssetID: body.AssetID, TargetPort: body.TargetPort,
		SourceIP: body.SourceIP, TargetAccount: body.TargetAccount,
		Reason: body.Reason, TicketNo: body.TicketNo, RequestedStartAt: body.RequestedStartAt,
		TTLSeconds: body.TTLSeconds, Emergency: body.Emergency, IdempotencyKey: idempotencyKey,
	}
	var value domain.AccessRequest
	var err error
	if testAccess {
		svc, ok := s.Service.(TestAccessService)
		if !ok {
			s.writeError(response, service.ErrNotConfigured)
			return
		}
		value, err = svc.CreateTestAccessRequest(request.Request.Context(), input)
	} else {
		value, err = s.Service.CreateAccessRequest(request.Request.Context(), input)
	}
	if err != nil {
		var validation *service.RequestValidationError
		if errors.Is(err, service.ErrValidation) && !errors.As(err, &validation) {
			err = &service.RequestValidationError{Message: "申请校验失败，请刷新后重试或联系管理员检查资产配置"}
		}
		s.writeError(response, err)
		return
	}
	_ = response.WriteHeaderAndEntity(http.StatusCreated, toAccessRequestResponse(value))
}

func (s *Server) listAccessRequests(request *restful.Request, response *restful.Response) {
	userID, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	limit, offset, pageErr := parsePageQuery(request, 50, 51)
	if pageErr != nil {
		s.writeError(response, pageErr)
		return
	}
	values, err := s.Service.ListMyAccessRequests(request.Request.Context(), userID, limit, offset)
	if err != nil {
		s.writeError(response, err)
		return
	}
	result := make([]accessRequestResponse, 0, len(values))
	for _, value := range values {
		result = append(result, toAccessRequestResponse(value))
	}
	_ = response.WriteEntity(result)
}

func (s *Server) getAccessRequest(request *restful.Request, response *restful.Response) {
	userID, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	value, err := s.Service.GetAccessRequest(request.Request.Context(), userID, request.PathParameter("request_id"))
	if err != nil {
		s.writeError(response, err)
		return
	}
	_ = response.WriteEntity(toAccessRequestResponse(value))
}

func (s *Server) getSessionByRequest(request *restful.Request, response *restful.Response) {
	userID, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	view, err := s.Service.GetSessionByRequest(request.Request.Context(), userID, request.PathParameter("request_id"))
	if err != nil {
		s.writeError(response, err)
		return
	}
	entity := toSessionResponse(view.Session)
	entity.CanConnect = view.CanConnect
	entity.GatewayEndpoint = view.GatewayEndpoint
	entity.AuditTrust = view.AuditTrust
	entity.CanWebConnect = view.CanWebConnect
	entity.GatewayHost = view.GatewayHost
	entity.GatewayPort = view.GatewayPort
	entity.TargetPort = view.Request.TargetPort
	entity.SourceIP = view.Request.SourceIP
	entity.TargetAccount = view.Request.TargetAccount
	_ = response.WriteEntity(entity)
}

func (s *Server) cancelAccessRequest(request *restful.Request, response *restful.Response) {
	userID, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	value, err := s.Service.CancelAccessRequest(request.Request.Context(), userID, request.PathParameter("request_id"))
	if err != nil {
		s.writeError(response, err)
		return
	}
	_ = response.WriteEntity(toAccessRequestResponse(value))
}

func (s *Server) getSession(request *restful.Request, response *restful.Response) {
	userID, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	view, err := s.Service.GetSession(request.Request.Context(), userID, request.PathParameter("session_id"))
	if err != nil {
		s.writeError(response, err)
		return
	}
	entity := toSessionResponse(view.Session)
	entity.CanConnect = view.CanConnect
	entity.GatewayEndpoint = view.GatewayEndpoint
	entity.AuditTrust = view.AuditTrust
	entity.CanWebConnect = view.CanWebConnect
	entity.GatewayHost = view.GatewayHost
	entity.GatewayPort = view.GatewayPort
	entity.TargetPort = view.Request.TargetPort
	entity.SourceIP = view.Request.SourceIP
	entity.TargetAccount = view.Request.TargetAccount
	_ = response.WriteEntity(entity)
}

func (s *Server) listSessionEvents(request *restful.Request, response *restful.Response) {
	userID, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	limit, offset, pageErr := parsePageQuery(request, 100, 500)
	if pageErr != nil {
		s.writeError(response, pageErr)
		return
	}
	values, err := s.Service.ListSessionEvents(request.Request.Context(), userID, request.PathParameter("session_id"), limit, offset)
	if err != nil {
		s.writeError(response, err)
		return
	}
	result := make([]sessionEventResponse, 0, len(values))
	for _, value := range values {
		result = append(result, toSessionEventResponse(value))
	}
	_ = response.WriteEntity(result)
}

func (s *Server) closeSession(request *restful.Request, response *restful.Response) {
	userID, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	value, err := s.Service.CloseSession(request.Request.Context(), userID, request.PathParameter("session_id"))
	if err != nil {
		s.writeError(response, err)
		return
	}
	_ = response.WriteEntity(toSessionResponse(value))
}

func (s *Server) forceCloseSession(request *restful.Request, response *restful.Response) {
	adminID, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	var body forceCloseBody
	if request.Request.ContentLength != 0 {
		if err := decodeJSONBody(request.Request, &body, true); err != nil {
			s.writeError(response, &service.RequestValidationError{Message: "回收请求格式不正确，请刷新页面后重新选择会话"})
			return
		}
	}
	value, err := s.Service.ForceCloseSession(request.Request.Context(), adminID, request.PathParameter("session_id"), body.Reason)
	if err != nil {
		s.writeError(response, err)
		return
	}
	// A remote close is dispatched through the durable outbox.  Return 202 for
	// a queued revoke so callers do not mistake the intermediate state for a
	// completed gateway operation.
	if value.Status == domain.SessionRevoking || value.Status == domain.SessionRevokeFailed {
		_ = response.WriteHeaderAndEntity(http.StatusAccepted, toSessionResponse(value))
		return
	}
	_ = response.WriteEntity(toSessionResponse(value))
}

func (s *Server) listAuditEvents(request *restful.Request, response *restful.Response) {
	userID, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	query := request.Request.URL.Query()
	limit, offset, pageErr := parsePageQuery(request, 100, 200)
	if pageErr != nil {
		s.writeError(response, pageErr)
		return
	}
	filter := domain.AuditFilter{
		Category: query.Get("category"), Action: query.Get("action"),
		EventType: query.Get("event_type"), ActorID: query.Get("actor_id"), SubjectUserID: query.Get("subject_user_id"),
		RequestID: query.Get("request_id"), SessionID: query.Get("session_id"), RegionID: query.Get("region_id"),
		AssetID: query.Get("asset_id"), SourceIP: query.Get("source_ip"), Result: query.Get("result"),
		Limit: limit, Offset: offset,
	}
	if raw := query.Get("from"); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			s.writeError(response, fmt.Errorf("invalid from time: %w", service.ErrValidation))
			return
		}
		filter.From = &parsed
	}
	if raw := query.Get("to"); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			s.writeError(response, fmt.Errorf("invalid to time: %w", service.ErrValidation))
			return
		}
		filter.To = &parsed
	}
	values, err := s.Service.ListAuditEvents(request.Request.Context(), userID, filter)
	if err != nil {
		s.writeError(response, err)
		return
	}
	result := make([]auditEventResponse, 0, len(values))
	for _, value := range values {
		result = append(result, toAuditEventResponse(value))
	}
	_ = response.WriteEntity(result)
}

func (s *Server) listOperationAuditEvents(request *restful.Request, response *restful.Response) {
	userID, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	filter, err := parseOperationAuditFilter(request, 100)
	if err != nil {
		s.writeError(response, err)
		return
	}
	values, err := s.Service.ListOperationAuditEvents(request.Request.Context(), userID, filter)
	if err != nil {
		s.writeError(response, err)
		return
	}
	result := make([]operationAuditEventResponse, 0, len(values))
	for _, value := range values {
		result = append(result, toOperationAuditEventResponse(value))
	}
	_ = response.WriteEntity(result)
}

func (s *Server) feishuCallback(request *restful.Request, response *restful.Response) {
	runtime := s.authRuntime(request.Request.Context())
	const maxCallbackBodyBytes = 1 << 20
	body, err := io.ReadAll(io.LimitReader(request.Request.Body, maxCallbackBodyBytes+1))
	if err != nil {
		s.writeError(response, fmt.Errorf("read callback: %w", err))
		return
	}
	if len(body) > maxCallbackBodyBytes {
		s.writeError(response, fmt.Errorf("callback body is too large: %w", service.ErrValidation))
		return
	}
	var payload feishuCallbackBody
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&payload); err != nil {
		s.writeError(response, fmt.Errorf("decode callback: %w", service.ErrValidation))
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		s.writeError(response, fmt.Errorf("decode callback: %w", service.ErrValidation))
		return
	}
	if runtime.CallbackSecret == "" {
		s.writeError(response, fmt.Errorf("feishu callback is not configured: %w", service.ErrNotConfigured))
		return
	}
	payload.normalizeCardAction()
	timestamp := firstHeader(request.Request.Header, "X-Feishu-Timestamp", "X-Lark-Request-Timestamp")
	eventID := request.Request.Header.Get("X-Feishu-Event-ID")
	if eventID == "" {
		eventID = payload.Header.EventID
	}
	signature := firstHeader(request.Request.Header, "X-Feishu-Signature", "X-Lark-Signature")
	var verifyErr error
	if nonce := request.Request.Header.Get("X-Lark-Request-Nonce"); nonce != "" {
		verifyErr = feishu.VerifyLarkCallback(runtime.CallbackSecret, timestamp, nonce, signature, body, time.Now(), 5*time.Minute)
	} else {
		verifyErr = feishu.VerifyCallback(runtime.CallbackSecret, timestamp, eventID, signature, body, time.Now(), 5*time.Minute)
	}
	if verifyErr != nil {
		s.writeError(response, fmt.Errorf("verify callback: %w", service.ErrForbidden))
		return
	}
	tenantKey := strings.TrimSpace(payload.Header.TenantKey)
	if tenantKey == "" {
		tenantKey = strings.TrimSpace(payload.TenantKey)
	}
	if runtime.Feishu.TenantKey != "" && tenantKey != runtime.Feishu.TenantKey {
		s.writeError(response, fmt.Errorf("callback tenant is not allowed: %w", service.ErrForbidden))
		return
	}
	if payload.Type == "url_verification" && payload.Challenge != "" {
		_ = response.WriteEntity(map[string]string{"challenge": payload.Challenge})
		return
	}
	if eventID == "" {
		// Some Lark card callbacks omit an event ID. A digest of the verified
		// envelope still gives retries a stable identity without persisting the
		// raw callback body.
		digest := sha256.Sum256(body)
		eventID = "body-" + fmt.Sprintf("%x", digest[:])
	}
	claimedDurably := false
	if s.CallbackEvents != nil {
		var claimErr error
		claimedDurably, claimErr = s.CallbackEvents.Claim(request.Request.Context(), s.DB, eventID, 10*time.Minute)
		if claimErr != nil {
			s.writeError(response, fmt.Errorf("claim Feishu callback: %w", claimErr))
			return
		}
		if !claimedDurably {
			_ = response.WriteEntity(map[string]string{"status": "already_processed"})
			return
		}
	} else if s.callbackProcessed(eventID) {
		_ = response.WriteEntity(map[string]string{"status": "already_processed"})
		return
	}
	completed := false
	defer func() {
		if completed || !claimedDurably {
			return
		}
		if releaseErr := s.CallbackEvents.Release(request.Request.Context(), s.DB, eventID); releaseErr != nil {
			s.Logger.Error().Err(releaseErr).Str("event_id", eventID).Msg("release failed Feishu callback claim")
		}
	}()
	decision := domain.ApprovalDecision(payload.Decision)
	if payload.ApprovalID == "" || payload.ApproverID == "" || (decision != domain.ApprovalApproved && decision != domain.ApprovalRejected) {
		s.writeError(response, fmt.Errorf("callback approval fields are invalid: %w", service.ErrValidation))
		return
	}
	if _, err := s.Service.DecideApprovalByExternalUser(request.Request.Context(), payload.ApproverID, payload.ApprovalID, decision, payload.Comment); err != nil {
		// A callback may be retried after the original response was lost. Once
		// the approval is no longer pending, treating it as processed is safe
		// and avoids re-running any provisioning side effects.
		if errors.Is(err, service.ErrStateConflict) {
			if claimedDurably {
				if markErr := s.CallbackEvents.MarkProcessed(request.Request.Context(), s.DB, eventID); markErr != nil {
					s.Logger.Error().Err(markErr).Str("event_id", eventID).Msg("mark already-processed Feishu callback failed")
					return
				}
				completed = true
			} else {
				s.markCallbackProcessed(eventID)
			}
			_ = response.WriteEntity(map[string]string{"status": "already_processed"})
			return
		}
		s.writeError(response, err)
		return
	}
	if claimedDurably {
		if err := s.CallbackEvents.MarkProcessed(request.Request.Context(), s.DB, eventID); err != nil {
			s.writeError(response, fmt.Errorf("mark Feishu callback processed: %w", err))
			return
		}
		completed = true
	} else {
		s.markCallbackProcessed(eventID)
	}
	_ = response.WriteEntity(map[string]string{"status": "processed"})
}

func (s *Server) gatewayEvent(request *restful.Request, response *restful.Response) {
	authenticatedGatewayID, err := s.authenticateGatewayAuditRequest(request.Request)
	if err != nil {
		s.writeError(response, err)
		return
	}
	var body gatewayEventBody
	if err := decodeJSONBody(request.Request, &body, false); err != nil {
		s.writeError(response, fmt.Errorf("decode gateway event: %w", service.ErrValidation))
		return
	}
	if authenticatedGatewayID != "" && strings.TrimSpace(body.GatewayID) != authenticatedGatewayID {
		s.writeError(response, fmt.Errorf("gateway event identity does not match the authenticated gateway: %w", service.ErrForbidden))
		return
	}
	if sessionID := request.HeaderParameter(gatewayauth.SessionIDHeader); sessionID != "" && body.SessionID != sessionID {
		s.writeError(response, fmt.Errorf("gateway event session does not match credential: %w", service.ErrForbidden))
		return
	}
	if err := s.Service.RecordGatewayEvent(request.Request.Context(), toGatewayEventInput(body)); err != nil {
		s.writeError(response, err)
		return
	}
	_ = response.WriteEntity(map[string]string{"status": "recorded"})
}

func (s *Server) gatewayEventBatch(request *restful.Request, response *restful.Response) {
	authenticatedGatewayID, err := s.authenticateGatewayAuditRequest(request.Request)
	if err != nil {
		s.writeError(response, err)
		return
	}
	var body gatewayEventBatchBody
	if err := decodeJSONBody(request.Request, &body, false); err != nil || len(body.Events) < 1 || len(body.Events) > 500 {
		s.writeError(response, fmt.Errorf("decode gateway event batch: %w", service.ErrValidation))
		return
	}
	acceptedEventIDs := make([]string, 0, len(body.Events))
	seenEventIDs := make(map[string]struct{}, len(body.Events))
	batchGatewayID := strings.TrimSpace(body.Events[0].GatewayID)
	if batchGatewayID == "" {
		s.writeError(response, fmt.Errorf("gateway event gateway ID is required: %w", service.ErrValidation))
		return
	}
	if authenticatedGatewayID != "" && batchGatewayID != authenticatedGatewayID {
		s.writeError(response, fmt.Errorf("gateway event identity does not match the authenticated gateway: %w", service.ErrForbidden))
		return
	}
	for _, event := range body.Events {
		if sessionID := request.HeaderParameter(gatewayauth.SessionIDHeader); sessionID != "" && event.SessionID != sessionID {
			s.writeError(response, fmt.Errorf("gateway event session does not match credential: %w", service.ErrForbidden))
			return
		}
		if strings.TrimSpace(event.GatewayID) != batchGatewayID {
			s.writeError(response, fmt.Errorf("gateway event batch contains multiple gateway identities: %w", service.ErrForbidden))
			return
		}
		eventID := strings.TrimSpace(event.EventID)
		if eventID == "" {
			s.writeError(response, fmt.Errorf("gateway event ID is required: %w", service.ErrValidation))
			return
		}
		if _, exists := seenEventIDs[eventID]; exists {
			s.writeError(response, fmt.Errorf("gateway event batch contains duplicate event ID: %w", service.ErrValidation))
			return
		}
		seenEventIDs[eventID] = struct{}{}
		acceptedEventIDs = append(acceptedEventIDs, eventID)
	}
	for _, event := range body.Events {
		if err := s.Service.RecordGatewayEvent(request.Request.Context(), toGatewayEventInput(event)); err != nil {
			s.writeError(response, err)
			return
		}
	}
	_ = response.WriteEntity(gateway.ConnectionEventBatchResponse{
		Version:          gateway.ConnectionEventBatchResponseVersion,
		AcceptedEventIDs: acceptedEventIDs,
	})
}

func (s *Server) authenticateGatewayAuditRequest(request *http.Request) (string, error) {
	gatewayIDs := request.Header.Values(gateway.AuditGatewayIDHeader)
	auditSecrets := request.Header.Values(gateway.AuditSecretHeader)
	internalSecrets := request.Header.Values(gateway.InternalSecretHeader)
	if sessionIDs := request.Header.Values(gatewayauth.SessionIDHeader); len(sessionIDs) != 0 {
		if len(sessionIDs) != 1 || len(gatewayIDs) != 1 || len(auditSecrets) != 1 || len(internalSecrets) != 0 ||
			!s.SessionAuditCredentials.Verify(gatewayIDs[0], sessionIDs[0], auditSecrets[0], time.Now()) {
			return "", fmt.Errorf("session audit authentication failed: %w", errUnauthenticated)
		}
		return gatewayIDs[0], nil
	}
	usesPerGatewayProtocol := len(gatewayIDs) != 0 || len(auditSecrets) != 0

	if s.GatewayAuditAuthMode == gatewayauth.ModeShared || s.GatewayAuditAuthMode == gatewayauth.ModeTransition && !usesPerGatewayProtocol {
		if usesPerGatewayProtocol || !validInternalSecret(request, gateway.InternalSecretHeader, s.GatewayInternalSecret) {
			return "", fmt.Errorf("gateway authentication failed: %w", errUnauthenticated)
		}
		return "", nil
	}
	if len(gatewayIDs) != 1 || strings.TrimSpace(gatewayIDs[0]) == "" || len(auditSecrets) != 1 || auditSecrets[0] == "" || len(internalSecrets) != 0 {
		return "", fmt.Errorf("gateway authentication failed: %w", errUnauthenticated)
	}
	gatewayID := strings.TrimSpace(gatewayIDs[0])
	if s.GatewayAuthenticator == nil {
		s.Logger.Error().Str("gateway_id", gatewayID).Msg("gateway audit authenticator is unavailable")
		return "", fmt.Errorf("gateway authentication failed: %w", errUnauthenticated)
	}
	authenticated, err := s.GatewayAuthenticator.Authenticate(request.Context(), gatewayID, auditSecrets[0])
	if err != nil {
		s.Logger.Error().Err(err).Str("gateway_id", gatewayID).Msg("gateway audit authentication backend failed")
		return "", fmt.Errorf("gateway authentication failed: %w", errUnauthenticated)
	}
	if !authenticated {
		return "", fmt.Errorf("gateway authentication failed: %w", errUnauthenticated)
	}
	return gatewayID, nil
}

func (s *Server) operationAuditBatch(request *restful.Request, response *restful.Response) {
	if !validInternalSecret(request.Request, "X-Audit-Collector-Secret", s.AuditCollectorSecret) {
		s.writeError(response, fmt.Errorf("audit collector authentication failed: %w", service.ErrForbidden))
		return
	}
	var body operationAuditBatchBody
	if err := decodeJSONBody(request.Request, &body, false); err != nil || len(body.Events) < 1 || len(body.Events) > 500 {
		s.writeError(response, fmt.Errorf("decode operation audit batch: %w", service.ErrValidation))
		return
	}
	inserted, err := s.Service.RecordOperationAuditBatch(request.Request.Context(), body.Events)
	if err != nil {
		s.writeError(response, err)
		return
	}
	_ = response.WriteEntity(map[string]any{"status": "recorded", "received": len(body.Events), "inserted": inserted})
}

func (s *Server) sessionOperationBatch(request *restful.Request, response *restful.Response) {
	identity, err := s.authenticateGatewayAuditRequest(request.Request)
	sessionID := request.HeaderParameter(gatewayauth.SessionIDHeader)
	if err != nil || identity == "" || sessionID == "" {
		s.writeError(response, fmt.Errorf("session audit credentials required: %w", service.ErrForbidden))
		return
	}
	var body operationaudit.SessionBatch
	if decodeJSONBody(request.Request, &body, false) != nil {
		s.writeError(response, service.ErrValidation)
		return
	}
	ids, err := s.Service.RecordSessionOperations(request.Request.Context(), identity, sessionID, body.Events)
	if err != nil {
		s.writeError(response, err)
		return
	}
	_ = response.WriteEntity(gateway.ConnectionEventBatchResponse{Version: gateway.ConnectionEventBatchResponseVersion, AcceptedEventIDs: ids})
}

func toGatewayEventInput(body gatewayEventBody) service.GatewayEventInput {
	return service.GatewayEventInput{
		EventID: body.EventID, GatewayID: body.GatewayID, ConnectionID: body.ConnectionID,
		SessionID: body.SessionID, EventType: body.EventType, SourceIP: body.SourceIP,
		BackendSourceIP: body.BackendSourceIP, BackendSourcePort: body.BackendSourcePort,
		BytesUp: body.BytesUp, BytesDown: body.BytesDown, DurationMS: body.DurationMS,
		Result: body.Result, Reason: body.Reason, OccurredAt: body.OccurredAt,
	}
}

func validInternalSecret(request *http.Request, header, expected string) bool {
	values := request.Header.Values(header)
	return expected != "" && len(values) == 1 && hmacEqualString(expected, values[0])
}

func (s *Server) health(request *restful.Request, response *restful.Response) {
	_ = response.WriteEntity(map[string]string{"status": "ok"})
}

func (s *Server) ready(request *restful.Request, response *restful.Response) {
	ctx, cancel := context.WithTimeout(request.Request.Context(), 2*time.Second)
	defer cancel()
	if err := s.DB.PingContext(ctx); err != nil {
		s.writeError(response, fmt.Errorf("database is not ready: %w", err))
		return
	}
	_ = response.WriteEntity(map[string]string{"status": "ready"})
}

func (s *Server) currentUser(request *restful.Request, response *restful.Response) (string, bool) {
	userID := ""
	if s.AllowDevAuth {
		if devUserID := strings.TrimSpace(request.Request.Header.Get("X-User-ID")); devUserID != "" {
			userID = devUserID
		}
	}
	if userID == "" && s.SessionSigner != nil {
		if cookie, err := request.Request.Cookie(s.SessionCookieName); err == nil {
			if signedID, version, valid := s.SessionSigner.VerifyVersioned(cookie.Value, time.Now()); valid {
				if s.Authentication != nil {
					if err := s.Authentication.ValidateBrowserSession(request.Request.Context(), signedID, version); err != nil {
						if errors.Is(err, service.ErrInvalidCredentials) {
							err = errUnauthenticated
						}
						s.writeError(response, err)
						return "", false
					}
				}
				if s.MFA != nil {
					if err := s.MFA.ValidateMFASession(request.Request.Context(), signedID, s.SessionSigner.MFAVerified(cookie.Value, time.Now())); err != nil {
						s.writeError(response, err)
						return "", false
					}
				}
				userID = signedID
			}
		}
	}
	if userID == "" {
		s.writeError(response, fmt.Errorf("authentication required: %w", errUnauthenticated))
		return "", false
	}
	return userID, true
}

func hmacEqualString(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func (body *feishuCallbackBody) normalizeCardAction() {
	if body.ApproverID == "" {
		body.ApproverID = body.Event.Operator.OpenID
		if body.ApproverID == "" {
			body.ApproverID = body.Event.Operator.OperatorID.OpenID
		}
	}
	if len(body.Event.Action.Value) == 0 {
		return
	}
	var value struct {
		ApprovalID string  `json:"approval_id"`
		Decision   string  `json:"decision"`
		Comment    *string `json:"comment"`
	}
	raw := body.Event.Action.Value
	if len(raw) > 0 && raw[0] == '"' {
		var encoded string
		if json.Unmarshal(raw, &encoded) != nil {
			return
		}
		raw = []byte(encoded)
	}
	if json.Unmarshal(raw, &value) != nil {
		return
	}
	if body.ApprovalID == "" {
		body.ApprovalID = value.ApprovalID
	}
	if body.Decision == "" {
		body.Decision = value.Decision
	}
	if body.Comment == nil {
		body.Comment = value.Comment
	}
}

func firstHeader(header http.Header, names ...string) string {
	for _, name := range names {
		if value := strings.TrimSpace(header.Get(name)); value != "" {
			return value
		}
	}
	return ""
}

func (s *Server) secureRequest(request *http.Request) bool {
	if s.publicOrigin != nil {
		return s.publicOrigin.Scheme == "https"
	}
	if request.TLS != nil {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(request.Header.Get("X-Forwarded-Proto")), "https")
}

func validateFrontendRedirect(value string) error {
	if value == "" || strings.ContainsAny(value, "\r\n") {
		return fmt.Errorf("frontend redirect is invalid: %w", service.ErrValidation)
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || strings.HasPrefix(parsed.Path, "//") || !strings.HasPrefix(parsed.Path, "/") {
		return fmt.Errorf("frontend redirect must be a same-origin path: %w", service.ErrValidation)
	}
	return nil
}

func (s *Server) requireActive(ctx context.Context, userID string) error {
	return s.Service.CheckActiveUser(ctx, userID)
}

func (s *Server) callbackProcessed(eventID string) bool {
	s.seenMu.Lock()
	defer s.seenMu.Unlock()
	now := time.Now()
	for key, at := range s.seenCallbacks {
		if now.Sub(at) > 10*time.Minute {
			delete(s.seenCallbacks, key)
		}
	}
	_, exists := s.seenCallbacks[eventID]
	return exists
}

func (s *Server) markCallbackProcessed(eventID string) {
	if eventID == "" {
		return
	}
	s.seenMu.Lock()
	defer s.seenMu.Unlock()
	s.seenCallbacks[eventID] = time.Now()
}

func (s *Server) writeError(response *restful.Response, err error) {
	if errors.Is(err, context.Canceled) {
		// Navigation, aborted fetches and proxy restarts cancel in-flight SQL.
		// Report cancellation separately from server failures; there is no
		// useful error body to send to a client that has abandoned the request.
		const statusClientClosedRequest = 499
		response.WriteHeader(statusClientClosedRequest)
		return
	}
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, service.ErrMFAFailed), errors.Is(err, service.ErrInvitationUnavailable):
		status = http.StatusBadRequest
	case errors.Is(err, errUnauthenticated), errors.Is(err, service.ErrInvalidCredentials):
		status = http.StatusUnauthorized
	case errors.Is(err, service.ErrValidation):
		status = http.StatusBadRequest
	case errors.Is(err, service.ErrForbidden):
		status = http.StatusForbidden
	case errors.Is(err, repository.ErrNotFound):
		status = http.StatusNotFound
	case errors.Is(err, repository.ErrConflict), errors.Is(err, service.ErrStateConflict):
		status = http.StatusConflict
	case errors.Is(err, service.ErrNotConfigured):
		status = http.StatusServiceUnavailable
	}
	if status >= 500 {
		s.Logger.Error().Err(err).Msg("request failed")
	}
	if status == http.StatusUnauthorized {
		response.Header().Set("WWW-Authenticate", "Bearer")
	}
	message := publicError(status)
	if errors.Is(err, service.ErrMFAFailed) {
		message = service.ErrMFAFailed.Error()
	}
	if errors.Is(err, service.ErrInvitationUnavailable) {
		message = service.ErrInvitationUnavailable.Error()
	}
	var validation *service.RequestValidationError
	if status == http.StatusBadRequest && errors.As(err, &validation) {
		message = validation.Message
	}
	_ = response.WriteHeaderAndEntity(status, errorResponse{Error: message})
}

func publicError(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "bad request"
	case http.StatusForbidden:
		return "forbidden"
	case http.StatusUnauthorized:
		return "authentication required"
	case http.StatusNotFound:
		return "not found"
	case http.StatusConflict:
		return "conflict"
	case http.StatusServiceUnavailable:
		return "service unavailable"
	default:
		return "internal server error"
	}
}

func parseIntQuery(request *restful.Request, key string, fallback int) int {
	value, err := strconv.Atoi(request.Request.URL.Query().Get(key))
	if err != nil {
		return fallback
	}
	return value
}

func parsePageQuery(request *restful.Request, defaultLimit int, maximum ...int) (int, int, error) {
	if defaultLimit < 1 {
		defaultLimit = 50
	}
	maxLimit := defaultLimit
	if len(maximum) > 0 && maximum[0] > 0 {
		maxLimit = maximum[0]
	}
	if maxLimit < defaultLimit {
		defaultLimit = maxLimit
	}
	query := request.Request.URL.Query()
	limit := defaultLimit
	if raw := strings.TrimSpace(query.Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 {
			return 0, 0, fmt.Errorf("limit must be a positive integer: %w", service.ErrValidation)
		}
		if parsed > maxLimit {
			return 0, 0, fmt.Errorf("limit must not exceed %d: %w", maxLimit, service.ErrValidation)
		}
		limit = parsed
	}
	offset := 0
	if raw := strings.TrimSpace(query.Get("offset")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			return 0, 0, fmt.Errorf("offset must be a non-negative integer: %w", service.ErrValidation)
		}
		offset = parsed
	}
	return limit, offset, nil
}

func toAccessRequestResponse(value domain.AccessRequest) accessRequestResponse {
	return accessRequestResponse{ApprovalMode: value.ApprovalMode, ID: value.ID, ApplicantID: value.ApplicantID, AssetID: value.AssetID, TargetPort: value.TargetPort, SourceIP: value.SourceIP, TargetAccount: value.TargetAccount, Reason: value.Reason, TicketNo: value.TicketNo, Emergency: value.Emergency, RequestedStartAt: value.RequestedStartAt, TTLSeconds: value.TTLSeconds, Status: string(value.Status), IdempotencyKey: value.IdempotencyKey, CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt}
}

func toAssetApproverResponse(value domain.AssetApprover) assetApproverResponse {
	return assetApproverResponse{ID: value.ID, AssetID: value.AssetID, UserID: value.UserID, ApprovalLevel: value.ApprovalLevel, Role: value.Role, Enabled: value.Enabled, CreatedAt: value.CreatedAt}
}

func toSessionEventResponse(value domain.SessionEvent) sessionEventResponse {
	return sessionEventResponse{ID: value.ID, SessionID: value.SessionID, EventType: value.EventType, ActorType: value.ActorType, ActorID: value.ActorID, Metadata: value.Metadata, CreatedAt: value.CreatedAt}
}

func toAuditEventResponse(value domain.AuditEvent) auditEventResponse {
	return auditEventResponse{AuditClassification: domain.ClassifyAuditEvent(value.EventType), ID: value.ID, EventType: value.EventType, ActorType: value.ActorType, ActorID: value.ActorID, ActorName: value.ActorName, ActorUsername: value.ActorUsername, SubjectUserID: value.SubjectUserID, RequestID: value.RequestID, SessionID: value.SessionID, RegionID: value.RegionID, AssetID: value.AssetID, TargetPort: value.TargetPort, SourceIP: value.SourceIP, ClientVersion: value.ClientVersion, Result: value.Result, Reason: value.Reason, Metadata: value.Metadata, CreatedAt: value.CreatedAt}
}

func toOperationAuditEventResponse(value domain.OperationAuditEvent) operationAuditEventResponse {
	return operationAuditEventResponse{
		EventID: value.EventID, ConnectionID: value.ConnectionID, SessionID: value.SessionID,
		Protocol: value.Protocol, AssetID: value.AssetID, TargetPort: value.TargetPort,
		ActualAccount: value.ActualAccount, OperationType: value.OperationType,
		StatementFingerprint: value.StatementFingerprint, NormalizedOperation: value.NormalizedOperation,
		ObjectName: value.ObjectName, Result: value.Result, DurationMS: value.DurationMS,
		BackendSourceIP: value.BackendSourceIP, BackendSourcePort: value.BackendSourcePort,
		SourceRecordID: value.SourceRecordID, CorrelationStatus: value.CorrelationStatus,
		OccurredAt: value.OccurredAt, Metadata: value.Metadata, CreatedAt: value.CreatedAt,
	}
}

func toSessionResponse(value domain.Session) sessionResponse {
	return sessionResponse{AuditPolicy: value.AuditPolicy, ConnectionMode: gateway.NormalizeConnectionMode(value.ConnectionMode), ID: value.ID, RequestID: value.RequestID, GatewayID: value.GatewayID, Status: string(value.Status), RemoteProcessID: value.RemoteProcessID, StartedAt: value.StartedAt, ExpiresAt: value.ExpiresAt, ClosedAt: value.ClosedAt, FailureReason: value.FailureReason, ListenerPort: value.ListenerPort, GatewayPort: valueOrZero(value.ExternalPort), ExposureMode: value.ExposureMode, ExposureRef: value.ExposureRef, CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt}
}

func valueOrZero(value *int) int {
	if value == nil {
		return 0
	}
	return *value
}
