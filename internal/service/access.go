package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/rs/zerolog"

	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/cloudassets"
	"github.com/srex-run/access-gateway/internal/cmdb"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/feishu"
	"github.com/srex-run/access-gateway/internal/gateway"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/operationaudit"
	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/secretstore"
	"github.com/srex-run/access-gateway/internal/security"
	"github.com/srex-run/access-gateway/internal/sessionproxy"
)

type CreateRequestInput struct {
	ApplicantID      string
	RegionID         string
	AssetID          string
	TargetPort       int
	SourceIP         string
	TargetAccount    string
	Reason           string
	TicketNo         *string
	RequestedStartAt *time.Time
	TTLSeconds       int
	Emergency        bool
	IdempotencyKey   string
}

const maxAccessRequestTTL = 5 * time.Hour
const demoSessionTTL = 5 * time.Minute

type ApprovalResult struct {
	Request  domain.AccessRequest
	Approval domain.Approval
	Session  *domain.Session
}

type SessionView struct {
	CanWebConnect   bool
	AuditTrust      *SessionAuditTrust
	CanConnect      bool
	Session         domain.Session
	Request         domain.AccessRequest
	GatewayEndpoint string
	GatewayHost     string
	GatewayPort     int
}

type GatewayEventInput struct {
	EventID           string
	GatewayID         string
	ConnectionID      string
	SessionID         string
	EventType         string
	SourceIP          *string
	BackendSourceIP   *string
	BackendSourcePort *int
	BytesUp           *int64
	BytesDown         *int64
	DurationMS        *int64
	Result            *string
	Reason            *string
	OccurredAt        time.Time
}

type OperationAuditInput = operationaudit.Event

type GatewayHealthResult struct {
	GatewayID string
	Err       error
}

type OperationalStats struct {
	OutboxPending          int64
	OutboxOldestAgeSeconds float64
	DatabaseMaxOpen        int
	DatabaseOpen           int
	DatabaseInUse          int
	DatabaseIdle           int
	DatabaseWaitCount      int64
	DatabaseWaitSeconds    float64
}

var errUnsupportedOutboxEvent = errors.New("unsupported outbox event")

type ServiceOptions struct {
	PublicURL              string
	GatewayBaseURL         string
	GatewayMaxSessions     int
	AuditProfiles          sessionproxy.ProfileSource
	CloudCipher            secretstore.Cipher
	CloudDiscoverer        cloudassets.Discoverer
	DB                     *sql.DB
	Users                  *repository.UserRepository
	Regions                *repository.RegionRepository
	Gateways               *repository.GatewayRepository
	Assets                 *repository.AssetRepository
	Requests               *repository.AccessRequestRepository
	Approvals              *repository.ApprovalRepository
	Sessions               *repository.SessionRepository
	SessionEvents          *repository.SessionEventRepository
	Audits                 *repository.AuditEventRepository
	AccessEvidence         *repository.AccessEvidenceRepository
	Outbox                 *repository.OutboxEventRepository
	Roles                  *repository.RoleRepository
	Gateway                gateway.Client
	Notifier               feishu.Notifier
	TokenDeliveries        *repository.SessionTokenDeliveryRepository
	OAuthStates            *repository.OAuthStateRepository
	Tasks                  TaskEnqueuer
	Logger                 zerolog.Logger
	DefaultTTL             time.Duration
	MaxTTL                 time.Duration
	DemoMode               bool
	ApprovalTimeout        time.Duration
	GatewayHeartbeatMaxAge time.Duration
	AdminUserIDs           map[string]struct{}
	FeishuTenantKey        string
	SystemSettings         *SystemSettingsService
	IdentityCipher         secretstore.Cipher
	Clock                  func() time.Time
	Authorizer             *authz.Policy
	AssetEncryptor         secretstore.Encryptor
	GatewayCredentials     secretstore.CredentialResolver
	CMDB                   cmdb.Client
	CMDBSource             string
}

type AccessService struct {
	publicURL              string
	gatewayBaseURL         string
	gatewayMaxSessions     int
	auditProfiles          sessionproxy.ProfileSource
	cloud                  *repository.CloudRepository
	cloudCipher            secretstore.Cipher
	cloudDiscoverer        cloudassets.Discoverer
	db                     *sql.DB
	users                  *repository.UserRepository
	regions                *repository.RegionRepository
	gateways               *repository.GatewayRepository
	assets                 *repository.AssetRepository
	requests               *repository.AccessRequestRepository
	approvals              *repository.ApprovalRepository
	sessions               *repository.SessionRepository
	sessionEvents          *repository.SessionEventRepository
	audits                 *repository.AuditEventRepository
	accessEvidence         *repository.AccessEvidenceRepository
	outbox                 *repository.OutboxEventRepository
	roles                  *repository.RoleRepository
	gateway                gateway.Client
	notifier               feishu.Notifier
	tokenDeliveries        *repository.SessionTokenDeliveryRepository
	oauthStates            *repository.OAuthStateRepository
	tasks                  TaskEnqueuer
	logger                 zerolog.Logger
	defaultTTL             time.Duration
	maxTTL                 time.Duration
	demoMode               bool
	approvalTimeout        time.Duration
	gatewayHeartbeatMaxAge time.Duration
	adminUserIDs           map[string]struct{}
	adminMu                sync.RWMutex
	feishuTenantKey        string
	systemSettings         *SystemSettingsService
	identityCipher         secretstore.Cipher
	clock                  func() time.Time
	authorizer             *authz.Policy
	assetEncryptor         secretstore.Encryptor
	gatewayCredentials     secretstore.CredentialResolver
	cmdb                   cmdb.Client
	cmdbSource             string
}

const provisioningLease = time.Minute

const maxConcurrentGatewayProbes = 8

func (s *AccessService) SyncFeishuUser(ctx context.Context, profile feishu.Profile) (domain.User, error) {
	profile.OpenID = strings.TrimSpace(profile.OpenID)
	profile.UnionID = strings.TrimSpace(profile.UnionID)
	profile.Nickname = strings.TrimSpace(profile.Nickname)
	profile.Email = strings.TrimSpace(profile.Email)
	profile.Department = strings.TrimSpace(profile.Department)
	profile.TenantKey = strings.TrimSpace(profile.TenantKey)
	tenant, tenantErr := s.expectedFeishuTenant(ctx)
	if tenantErr != nil {
		return domain.User{}, tenantErr
	}
	if tenant != "" && profile.TenantKey != tenant {
		return domain.User{}, fmt.Errorf("Feishu tenant is not allowed: %w", ErrForbidden)
	}
	if profile.OpenID == "" {
		return domain.User{}, fmt.Errorf("Feishu profile is incomplete: %w", ErrValidation)
	}
	if len(profile.OpenID) > 128 || len(profile.UnionID) > 128 || len(profile.TenantKey) > 128 || len(profile.Username) > 256 || len(profile.Nickname) > 128 || len(profile.Email) > 256 || len(profile.Department) > 256 {
		return domain.User{}, fmt.Errorf("Feishu profile field is too long: %w", ErrValidation)
	}
	status := domain.UserStatusInactive
	if profile.Active {
		status = domain.UserStatusActive
	}
	var unionID, email, department *string
	if profile.UnionID != "" {
		unionID = stringPtr(profile.UnionID)
	}
	if profile.Email != "" {
		email = stringPtr(profile.Email)
	}
	if profile.Department != "" {
		department = stringPtr(profile.Department)
	}
	value := domain.User{ID: id.New(), FeishuOpenID: profile.OpenID, FeishuUnionID: unionID, Username: security.ExternalUsername(profile.Username, profile.Email, "feishu", profile.TenantKey+"\x00"+profile.OpenID), Nickname: profile.Nickname, Email: email, Department: department, Status: status}
	err := InTx(ctx, s.db, func(q repository.DBTX) error {
		if err := (repository.IAMRepository{}).Lock(ctx, q, false); err != nil {
			return err
		}
		if err := s.validateFeishuSettings(ctx, q, tenant); err != nil {
			return err
		}
		var upsertErr error
		value, upsertErr = s.users.UpsertByFeishu(ctx, q, value)
		if upsertErr != nil {
			return upsertErr
		}
		return s.appendAudit(ctx, q, domain.AuditEvent{
			EventType:     "user.feishu_synced",
			ActorType:     "feishu",
			SubjectUserID: stringPtr(value.ID),
			Result:        stringPtr(string(value.Status)),
		})
	})
	if err != nil {
		return domain.User{}, fmt.Errorf("sync Feishu user: %w", err)
	}
	if value.Status == domain.UserStatusInactive {
		if revokeErr := s.enqueueUserRevocations(ctx, value.ID); revokeErr != nil {
			s.logger.Error().Err(revokeErr).Str("user_id", value.ID).Msg("enqueue inactive user session revocations failed")
		}
	}
	return value, nil
}

func NewAccessService(options ServiceOptions) (*AccessService, error) {
	if options.DB == nil {
		return nil, fmt.Errorf("access service: database is required")
	}
	if options.Users == nil || options.Regions == nil || options.Gateways == nil || options.Assets == nil || options.Requests == nil || options.Approvals == nil || options.Sessions == nil || options.SessionEvents == nil || options.Audits == nil {
		return nil, fmt.Errorf("access service: repositories are required")
	}
	if options.Outbox == nil {
		options.Outbox = repository.NewOutboxEventRepository()
	}
	if options.AccessEvidence == nil {
		options.AccessEvidence = repository.NewAccessEvidenceRepository()
	}
	if options.Roles == nil {
		options.Roles = repository.NewRoleRepository()
	}
	if options.Gateway == nil {
		return nil, fmt.Errorf("access service: gateway client is required")
	}
	if options.Notifier == nil {
		options.Notifier = feishu.NoopNotifier{}
	}
	if options.TokenDeliveries == nil {
		options.TokenDeliveries = repository.NewSessionTokenDeliveryRepository()
	}
	if options.OAuthStates == nil {
		options.OAuthStates = repository.NewOAuthStateRepository()
	}
	if options.Tasks == nil {
		options.Tasks = NoopTaskEnqueuer{}
	}
	if options.DefaultTTL <= 0 {
		options.DefaultTTL = time.Hour
	}
	if options.MaxTTL <= 0 {
		options.MaxTTL = maxAccessRequestTTL
	}
	if options.ApprovalTimeout <= 0 {
		options.ApprovalTimeout = 24 * time.Hour
	}
	if options.GatewayHeartbeatMaxAge <= 0 {
		options.GatewayHeartbeatMaxAge = 30 * time.Second
	}
	if options.DefaultTTL > options.MaxTTL {
		return nil, fmt.Errorf("access service: default TTL exceeds maximum TTL")
	}
	if options.MaxTTL > maxAccessRequestTTL {
		return nil, fmt.Errorf("access service: maximum TTL exceeds gateway policy")
	}
	if options.Clock == nil {
		options.Clock = time.Now
	}
	if options.Authorizer == nil {
		var policyErr error
		options.Authorizer, policyErr = authz.NewPolicy()
		if policyErr != nil {
			return nil, fmt.Errorf("access service: configure authorization policy: %w", policyErr)
		}
	}
	if options.CMDB != nil {
		if options.AssetEncryptor == nil {
			return nil, fmt.Errorf("access service: CMDB synchronization requires asset encryption")
		}
		if !validExternalSource(options.CMDBSource) {
			return nil, fmt.Errorf("access service: CMDB source is invalid")
		}
	}
	adminUserIDs := make(map[string]struct{}, len(options.AdminUserIDs))
	for userID := range options.AdminUserIDs {
		adminUserIDs[userID] = struct{}{}
	}
	return &AccessService{
		publicURL:              options.PublicURL,
		gatewayBaseURL:         options.GatewayBaseURL,
		gatewayMaxSessions:     options.GatewayMaxSessions,
		auditProfiles:          options.AuditProfiles,
		db:                     options.DB,
		users:                  options.Users,
		regions:                options.Regions,
		gateways:               options.Gateways,
		assets:                 options.Assets,
		requests:               options.Requests,
		approvals:              options.Approvals,
		sessions:               options.Sessions,
		sessionEvents:          options.SessionEvents,
		audits:                 options.Audits,
		accessEvidence:         options.AccessEvidence,
		outbox:                 options.Outbox,
		roles:                  options.Roles,
		gateway:                options.Gateway,
		notifier:               options.Notifier,
		tokenDeliveries:        options.TokenDeliveries,
		oauthStates:            options.OAuthStates,
		tasks:                  options.Tasks,
		logger:                 options.Logger,
		defaultTTL:             options.DefaultTTL,
		maxTTL:                 options.MaxTTL,
		demoMode:               options.DemoMode,
		approvalTimeout:        options.ApprovalTimeout,
		gatewayHeartbeatMaxAge: options.GatewayHeartbeatMaxAge,
		adminUserIDs:           adminUserIDs,
		feishuTenantKey:        strings.TrimSpace(options.FeishuTenantKey),
		systemSettings:         options.SystemSettings,
		identityCipher:         options.IdentityCipher,
		cloud:                  &repository.CloudRepository{},
		cloudCipher:            options.CloudCipher,
		cloudDiscoverer:        options.CloudDiscoverer,
		clock:                  options.Clock,
		authorizer:             options.Authorizer,
		assetEncryptor:         options.AssetEncryptor,
		gatewayCredentials:     options.GatewayCredentials,
		cmdb:                   options.CMDB,
		cmdbSource:             strings.TrimSpace(options.CMDBSource),
	}, nil
}

func (s *AccessService) ListRegions(ctx context.Context) ([]domain.Region, error) {
	values, err := s.regions.ListActive(ctx, s.db)
	if err != nil {
		return nil, fmt.Errorf("list regions: %w", err)
	}
	return values, nil
}

func (s *AccessService) GetOperationalStats(ctx context.Context) (OperationalStats, error) {
	queue, err := s.outbox.QueueStats(ctx, s.db)
	if err != nil {
		return OperationalStats{}, fmt.Errorf("read operational outbox stats: %w", err)
	}
	database := s.db.Stats()
	return OperationalStats{
		OutboxPending: queue.PendingCount, OutboxOldestAgeSeconds: queue.OldestAgeSeconds,
		DatabaseMaxOpen: database.MaxOpenConnections, DatabaseOpen: database.OpenConnections,
		DatabaseInUse: database.InUse, DatabaseIdle: database.Idle,
		DatabaseWaitCount: database.WaitCount, DatabaseWaitSeconds: database.WaitDuration.Seconds(),
	}, nil
}

// ProbeGateways checks every enabled Gateway Agent and records successful
// observations using the control plane's database clock. Alternate gateway
// transports can omit ReadinessChecker; their normal session command remains
// the availability boundary.
func (s *AccessService) ProbeGateways(ctx context.Context) ([]GatewayHealthResult, error) {
	checker, ok := s.gateway.(gateway.ReadinessChecker)
	if !ok {
		return nil, nil
	}
	gateways, err := s.gateways.ListEnabled(ctx, s.db)
	if err != nil {
		return nil, fmt.Errorf("list gateways for health probe: %w", err)
	}
	results := make([]GatewayHealthResult, len(gateways))
	semaphore := make(chan struct{}, maxConcurrentGatewayProbes)
	var wait sync.WaitGroup
	for index, gatewayRecord := range gateways {
		select {
		case semaphore <- struct{}{}:
		case <-ctx.Done():
			results[index] = GatewayHealthResult{GatewayID: gatewayRecord.ID, Err: ctx.Err()}
			continue
		}
		wait.Add(1)
		go func(index int, gatewayRecord domain.Gateway) {
			defer wait.Done()
			defer func() { <-semaphore }()
			results[index] = GatewayHealthResult{
				GatewayID: gatewayRecord.ID,
				Err:       s.probeGateway(ctx, checker, gatewayRecord),
			}
		}(index, gatewayRecord)
	}
	wait.Wait()
	return results, nil
}

func (s *AccessService) probeGateway(ctx context.Context, checker gateway.ReadinessChecker, gatewayRecord domain.Gateway) error {
	if reporter, ok := checker.(gateway.ReadinessReporter); ok {
		report, err := reporter.GetReadiness(ctx, gatewayRecord.ManagementEndpoint)
		if err != nil {
			return fmt.Errorf("gateway readiness check failed: %w", err)
		}
		if report.MaxSessions != nil {
			if _, err := s.gateways.RecordHealth(ctx, s.db, gatewayRecord.ID, *report.MaxSessions); err != nil {
				return fmt.Errorf("record gateway health: %w", err)
			}
			return nil
		}
	} else if err := checker.CheckReady(ctx, gatewayRecord.ManagementEndpoint); err != nil {
		return fmt.Errorf("gateway readiness check failed: %w", err)
	}
	if _, err := s.gateways.RecordHeartbeat(ctx, s.db, gatewayRecord.ID); err != nil {
		return fmt.Errorf("record gateway heartbeat: %w", err)
	}
	return nil
}

func (s *AccessService) ListAssets(ctx context.Context, userID, regionID string) ([]domain.Asset, error) {
	if err := s.requireActiveUser(ctx, userID); err != nil {
		return nil, err
	}
	if err := validateUUID(regionID, "region ID"); err != nil {
		return nil, err
	}
	region, err := s.regions.GetByID(ctx, s.db, regionID)
	if err != nil {
		return nil, fmt.Errorf("validate region: %w", err)
	}
	if region.Status != domain.ResourceStatusEnabled {
		return nil, fmt.Errorf("list assets: region is not enabled: %w", ErrValidation)
	}
	values, err := s.assets.ListActiveByRegion(ctx, s.db, regionID)
	if err != nil {
		return nil, fmt.Errorf("list assets: %w", err)
	}
	// TargetCiphertext is needed by the provisioning worker, but directory
	// callers only need display metadata and must not receive it.
	for index := range values {
		values[index].TargetCiphertext = ""
	}
	return values, nil
}

func (s *AccessService) ListAssetPorts(ctx context.Context, userID, assetID string) ([]domain.AssetPort, error) {
	if err := s.requireActiveUser(ctx, userID); err != nil {
		return nil, err
	}
	if err := validateUUID(assetID, "asset ID"); err != nil {
		return nil, err
	}
	asset, err := s.assets.GetByID(ctx, s.db, assetID)
	if err != nil {
		return nil, fmt.Errorf("validate asset: %w", err)
	}
	if asset.Status != domain.ResourceStatusEnabled {
		return nil, fmt.Errorf("list asset ports: %w", ErrValidation)
	}
	region, err := s.regions.GetByID(ctx, s.db, asset.RegionID)
	if err != nil {
		return nil, fmt.Errorf("validate asset region: %w", err)
	}
	if region.Status != domain.ResourceStatusEnabled {
		return nil, fmt.Errorf("list asset ports: region is not enabled: %w", ErrValidation)
	}
	values, err := s.assets.ListPorts(ctx, s.db, assetID)
	if err != nil {
		return nil, fmt.Errorf("list asset ports: %w", err)
	}
	audit, err := s.loadSessionAudit(ctx, s.db, assetID)
	if err != nil {
		return nil, fmt.Errorf("load asset port requirements: %w", err)
	}
	for i := range values {
		values[i].TargetAccountRequired = values[i].Protocol == "tcp" && audit.targetAccountRequired(values[i].Port)
	}
	return values, nil
}

func (s *AccessService) CreateAccessRequest(ctx context.Context, input CreateRequestInput) (domain.AccessRequest, error) {
	if s.demoMode {
		return s.createAccessRequest(ctx, input, "demo")
	}
	return s.createAccessRequest(ctx, input, "required")
}

// CreateTestAccessRequest is a separate administrator operation. A normal
// request body cannot select or bypass its approval policy.
func (s *AccessService) CreateTestAccessRequest(ctx context.Context, input CreateRequestInput) (domain.AccessRequest, error) {
	if err := s.Authorize(ctx, input.ApplicantID, authz.PermissionRoleManage); err != nil {
		return domain.AccessRequest{}, err
	}
	if err := validateTestAccessInput(input); err != nil {
		return domain.AccessRequest{}, err
	}
	return s.createAccessRequest(ctx, input, "admin_test")
}

func validateTestAccessInput(input CreateRequestInput) error {
	if input.TTLSeconds < 1 || input.TTLSeconds > 600 {
		return requestValidation("管理员测试连接的时长必须为 1–600 秒")
	}
	if input.Emergency || input.RequestedStartAt != nil {
		return requestValidation("管理员测试连接立即开始，不支持预约或紧急申请")
	}
	return nil
}

func (s *AccessService) createAccessRequest(ctx context.Context, input CreateRequestInput, approvalMode string) (domain.AccessRequest, error) {
	input.ApplicantID = strings.TrimSpace(input.ApplicantID)
	input.RegionID = strings.TrimSpace(input.RegionID)
	input.AssetID = strings.TrimSpace(input.AssetID)
	input.SourceIP = strings.TrimSpace(input.SourceIP)
	input.TargetAccount = strings.TrimSpace(input.TargetAccount)
	input.Reason = strings.TrimSpace(input.Reason)
	input.IdempotencyKey = strings.TrimSpace(input.IdempotencyKey)
	if input.TicketNo != nil {
		trimmed := strings.TrimSpace(*input.TicketNo)
		if trimmed == "" {
			input.TicketNo = nil
		} else {
			input.TicketNo = &trimmed
		}
	}
	if err := validateCreateInput(input); err != nil {
		return domain.AccessRequest{}, err
	}
	// Normalize before comparing idempotency payloads so retries of a request
	// made with a longer duration resolve to the same five-minute grant.
	if s.demoMode {
		input.TTLSeconds = int(demoSessionTTL / time.Second)
	}
	if input.SourceIP != "" {
		input.SourceIP = net.ParseIP(input.SourceIP).String()

	}
	if err := s.requireActiveUser(ctx, input.ApplicantID); err != nil {
		return domain.AccessRequest{}, err
	}
	if existing, err := s.requests.GetByIdempotencyKey(ctx, s.db, input.IdempotencyKey); err == nil {
		if existing.ApplicantID != input.ApplicantID {
			return domain.AccessRequest{}, fmt.Errorf("idempotency key belongs to another user: %w", ErrForbidden)
		}
		if !sameRequestPayload(existing, input) || existing.ApprovalMode != approvalMode {
			return domain.AccessRequest{}, fmt.Errorf("idempotency key was reused with a different request: %w", repository.ErrConflict)
		}
		return existing, nil
	} else if !errors.Is(err, repository.ErrNotFound) {
		return domain.AccessRequest{}, fmt.Errorf("check idempotency key: %w", err)
	}

	if input.SourceIP != "" {
		enabled, err := s.clientAccessEnabled(ctx)
		if err != nil {
			return domain.AccessRequest{}, err
		}
		if !enabled {
			return domain.AccessRequest{}, requestValidation("客户端访问尚未开启，请使用站内终端，或联系管理员在系统设置开启客户端访问")
		}
	}

	asset, err := s.assets.GetByID(ctx, s.db, input.AssetID)
	if err != nil {
		return domain.AccessRequest{}, fmt.Errorf("load asset: %w", err)
	}
	if asset.RegionID != input.RegionID || asset.Status != domain.ResourceStatusEnabled {
		return domain.AccessRequest{}, requestValidation("所选资产已停用或不属于当前区域，请刷新后重新选择")
	}
	region, err := s.regions.GetByID(ctx, s.db, input.RegionID)
	if err != nil {
		return domain.AccessRequest{}, fmt.Errorf("load request region: %w", err)
	}
	if region.Status != domain.ResourceStatusEnabled {
		return domain.AccessRequest{}, requestValidation("资产所属区域已停用，请联系管理员启用")
	}
	if _, err := s.assets.GetPort(ctx, s.db, input.AssetID, input.TargetPort, "tcp"); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return domain.AccessRequest{}, requestValidation("目标端口未配置或已停用，请先在资产管理的“端口”中添加对应 TCP 端口")
		}
		return domain.AccessRequest{}, fmt.Errorf("validate target port: %w", err)
	}
	plannedApprovals := []domain.Approval{}

	ttlSeconds := input.TTLSeconds
	if ttlSeconds == 0 {
		ttlSeconds = int(s.defaultTTL / time.Second)
	}
	maxTTL := asset.MaxTTLSeconds
	if configuredMax := int(maxAccessRequestTTL / time.Second); configuredMax < maxTTL {
		maxTTL = configuredMax
	}
	if configuredMax := int(s.maxTTL / time.Second); configuredMax < maxTTL {
		maxTTL = configuredMax
	}
	if ttlSeconds < 1 || ttlSeconds > maxTTL {
		return domain.AccessRequest{}, requestValidation(fmt.Sprintf("访问时长需在 1–%d 秒之间，受资产及平台最大时限限制", maxTTL))
	}
	if _, err := s.sessions.FindActiveByApplicantAssetPort(ctx, s.db, input.ApplicantID, input.AssetID, input.TargetPort); err == nil {
		return domain.AccessRequest{}, fmt.Errorf("an active session already exists: %w", repository.ErrConflict)
	} else if !errors.Is(err, repository.ErrNotFound) {
		return domain.AccessRequest{}, fmt.Errorf("check active session: %w", err)
	}

	request := domain.AccessRequest{
		ApprovalMode:     approvalMode,
		ID:               id.New(),
		ApplicantID:      input.ApplicantID,
		AssetID:          input.AssetID,
		TargetPort:       input.TargetPort,
		Reason:           input.Reason,
		TicketNo:         input.TicketNo,
		Emergency:        input.Emergency,
		RequestedStartAt: input.RequestedStartAt,
		TTLSeconds:       ttlSeconds,
		Status:           domain.AccessRequestPendingApproval,
		IdempotencyKey:   input.IdempotencyKey,
		SourceIP:         optionalString(input.SourceIP),
		TargetAccount:    optionalString(input.TargetAccount),
	}
	autoApproved := approvalMode == "admin_test" || approvalMode == "demo"
	if autoApproved {
		request.Status = domain.AccessRequestApproved
	}
	err = InTx(ctx, s.db, func(q repository.DBTX) error {
		if err := (repository.IAMRepository{}).Lock(ctx, q, true); err != nil {
			return err
		}
		if err := s.authorizeIn(ctx, q, input.ApplicantID, authz.PermissionRequestManage); err != nil {
			return err
		}
		if approvalMode == "required" {
			var err error
			plannedApprovals, err = s.materializeApproval(ctx, q, &request)
			if err != nil {
				return err
			}
		}
		if approvalMode == "admin_test" {
			if err := s.authorizeIn(ctx, q, input.ApplicantID, authz.PermissionRoleManage); err != nil {
				return err
			}
		}
		if autoApproved {
			if err := s.sessions.LockApplicantAssetPort(ctx, q, input.ApplicantID, input.AssetID, input.TargetPort); err != nil {
				return err
			}
			if _, err := s.sessions.FindActiveByApplicantAssetPort(ctx, q, input.ApplicantID, input.AssetID, input.TargetPort); err == nil {
				return repository.ErrConflict
			} else if !errors.Is(err, repository.ErrNotFound) {
				return err
			}
		}
		// Serialize new grants with deletion/status changes after taking the
		// applicant/asset lock, matching approval's lock order.
		currentAsset, err := s.assets.GetByIDForUpdate(ctx, q, asset.ID)
		if err != nil {
			return err
		}
		if currentAsset.Status != domain.ResourceStatusEnabled {
			return ErrStateConflict
		}
		asset = currentAsset
		if s.demoMode && asset.MaxTTLSeconds < ttlSeconds {
			return requestValidation("资产最大访问时长不足 5 分钟，无法创建演示会话")
		}
		policy, err := s.sessionAuditPolicy(ctx, q, asset, request)
		if err != nil {
			return err
		}
		if err := validateWebAccess(request, policy); err != nil {
			return err
		}
		created, createErr := s.requests.Create(ctx, q, request)
		if createErr != nil {
			return createErr
		}
		request = created
		for _, approver := range plannedApprovals {
			approver.RequestID = request.ID
			_, createErr := s.approvals.Create(ctx, q, approver)
			if createErr != nil {
				return createErr
			}
		}
		if auditErr := s.appendAudit(ctx, q, domain.AuditEvent{
			EventType:     "access_request.created",
			ActorType:     "user",
			ActorID:       stringPtr(input.ApplicantID),
			SubjectUserID: stringPtr(input.ApplicantID),
			RequestID:     stringPtr(request.ID),
			RegionID:      stringPtr(input.RegionID),
			AssetID:       stringPtr(input.AssetID),
			TargetPort:    intPtr(input.TargetPort),
			SourceIP:      optionalString(input.SourceIP),
			Result:        stringPtr("accepted"),
			Reason:        stringPtr(request.Reason),
			Metadata:      map[string]any{"approval_mode": approvalMode},
		}); auditErr != nil {
			return auditErr
		}
		if autoApproved {
			newSession, err := s.newSession(ctx, q, asset, request)
			if err != nil {
				return err
			}
			session, err := s.sessions.Create(ctx, q, newSession)
			if err != nil {
				return err
			}
			audit := domain.AuditEvent{
				EventType: "access_request.admin_test_started", ActorType: "admin",
				ActorID: stringPtr(input.ApplicantID), SubjectUserID: stringPtr(input.ApplicantID),
				RequestID: stringPtr(request.ID), SessionID: stringPtr(session.ID), AssetID: stringPtr(asset.ID),
				TargetPort: intPtr(input.TargetPort), SourceIP: optionalString(input.SourceIP), Reason: stringPtr(input.Reason),
				Result: stringPtr("queued"), Metadata: map[string]any{"approval_mode": approvalMode, "ttl_seconds": ttlSeconds},
			}
			if approvalMode == "demo" {
				audit.EventType, audit.ActorType, audit.ActorID = "access_request.demo_auto_approved", "system", nil
				audit.Result, audit.Reason = stringPtr("approved"), stringPtr("demo_mode")
			}
			if err := s.appendAudit(ctx, q, audit); err != nil {
				return err
			}
			if err := s.appendOutbox(ctx, q, "session", session.ID, outboxSessionProvision, map[string]any{"session_id": session.ID}); err != nil {
				return err
			}
			if approvalMode == "demo" {
				return s.appendOutbox(ctx, q, "access_request", request.ID, outboxNotifyRequestResult, map[string]any{"request_id": request.ID})
			}
			return nil
		}
		return s.appendOutbox(ctx, q, "access_request", request.ID, outboxNotifyApproval, map[string]any{"request_id": request.ID})
	})
	if err != nil {
		if errors.Is(err, repository.ErrConflict) {
			if existing, lookupErr := s.requests.GetByIdempotencyKey(ctx, s.db, input.IdempotencyKey); lookupErr == nil && existing.ApplicantID == input.ApplicantID {
				if sameRequestPayload(existing, input) && existing.ApprovalMode == approvalMode {
					return existing, nil
				}
				return domain.AccessRequest{}, fmt.Errorf("idempotency key was reused with a different request: %w", repository.ErrConflict)
			}
		}
		return domain.AccessRequest{}, fmt.Errorf("create access request: %w", err)
	}
	return request, nil
}

func (s *AccessService) GetAccessRequest(ctx context.Context, userID, requestID string) (domain.AccessRequest, error) {
	if err := s.requireActiveUser(ctx, userID); err != nil {
		return domain.AccessRequest{}, err
	}
	if err := validateUUID(requestID, "request ID"); err != nil {
		return domain.AccessRequest{}, err
	}
	request, err := s.requests.GetByID(ctx, s.db, requestID)
	if err != nil {
		return domain.AccessRequest{}, fmt.Errorf("get access request: %w", err)
	}
	if request.ApplicantID != userID && !s.isAdminUser(ctx, userID) {
		approvals, approvalErr := s.approvals.ListByRequest(ctx, s.db, request.ID)
		if approvalErr != nil {
			return domain.AccessRequest{}, fmt.Errorf("load request approvers: %w", approvalErr)
		}
		allowed := false
		for _, approval := range approvals {
			if approval.ApproverID == userID {
				allowed = true
				break
			}
		}
		if !allowed {
			return domain.AccessRequest{}, fmt.Errorf("get access request: %w", ErrForbidden)
		}
	}
	return request, nil
}

func (s *AccessService) ListMyAccessRequests(ctx context.Context, userID string, limit, offset int) ([]domain.AccessRequest, error) {
	if err := s.requireActiveUser(ctx, userID); err != nil {
		return nil, err
	}
	values, err := s.requests.ListByApplicant(ctx, s.db, userID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list access requests: %w", err)
	}
	return values, nil
}

func (s *AccessService) ListPendingApprovals(ctx context.Context, userID string, limit, offset int) ([]domain.Approval, error) {
	if err := s.Authorize(ctx, userID, authz.PermissionApprovalManage); err != nil {
		return nil, err
	}
	values, err := s.approvals.ListPendingByApprover(ctx, s.db, userID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list pending approvals: %w", err)
	}
	return values, nil
}

func (s *AccessService) CancelAccessRequest(ctx context.Context, userID, requestID string) (domain.AccessRequest, error) {
	if err := s.requireActiveUser(ctx, userID); err != nil {
		return domain.AccessRequest{}, err
	}
	if err := validateUUID(requestID, "request ID"); err != nil {
		return domain.AccessRequest{}, err
	}
	request, err := s.requests.GetByID(ctx, s.db, requestID)
	if err != nil {
		return domain.AccessRequest{}, fmt.Errorf("load access request: %w", err)
	}
	isAdmin := request.ApplicantID != userID && s.isAdminUser(ctx, userID)
	if request.ApplicantID != userID && !isAdmin {
		return domain.AccessRequest{}, fmt.Errorf("cancel access request: %w", ErrForbidden)
	}
	var cancelled domain.AccessRequest
	var linkedSession *domain.Session
	revokeQueued := false
	requestAlreadyTerminal := false
	err = InTx(ctx, s.db, func(q repository.DBTX) error {
		// Lock the request first, then the linked session. Final approval and
		// provisioning completion use the same order, so cancellation cannot miss
		// a session created in the approved transition or deadlock with a worker.
		currentRequest, lockErr := s.requests.GetByIDForUpdate(ctx, q, requestID)
		if lockErr != nil {
			return lockErr
		}
		request = currentRequest
		if currentRequest.Status == domain.AccessRequestCancelled || currentRequest.Status == domain.AccessRequestRejected || currentRequest.Status == domain.AccessRequestApprovalExpired {
			// A prior cancellation is idempotent. There should normally be no
			// linked session, but inspect one below so an older deployment cannot
			// leave an orphaned running session behind.
			cancelled = currentRequest
			requestAlreadyTerminal = true
		} else if currentRequest.Status != domain.AccessRequestPendingApproval && currentRequest.Status != domain.AccessRequestApproved {
			return fmt.Errorf("cancel access request from state %q: %w", currentRequest.Status, ErrStateConflict)
		} else {
			cancelled, lockErr = s.requests.Cancel(ctx, q, requestID)
			if lockErr != nil {
				return lockErr
			}
		}

		// Resolve the session while the request row is locked. If approval won
		// the race before this transaction, the session is visible here; if
		// cancellation won, no later approval can create one under the request
		// lock.
		if session, lookupErr := s.sessions.GetByRequestID(ctx, q, requestID); lookupErr == nil {
			current, sessionErr := s.sessions.GetByIDForUpdate(ctx, q, session.ID)
			if sessionErr != nil {
				return sessionErr
			}
			linkedSession = &current
		} else if !errors.Is(lookupErr, repository.ErrNotFound) {
			return fmt.Errorf("load request session during cancellation: %w", lookupErr)
		}

		if linkedSession != nil {
			switch linkedSession.Status {
			case domain.SessionProvisioning:
				if linkedSession.Version == 0 {
					if updateErr := s.sessions.MarkProvisionFailed(ctx, q, linkedSession.ID, linkedSession.Version, "access request cancelled before session start"); updateErr != nil {
						return updateErr
					}
					if eventErr := s.sessionEvents.Append(ctx, q, domain.SessionEvent{
						ID: id.New(), SessionID: linkedSession.ID, EventType: "session.cancelled_before_start",
						ActorType: cancellationActorType(isAdmin), ActorID: stringPtr(userID), Metadata: map[string]any{},
					}); eventErr != nil {
						return eventErr
					}
				} else {
					// A claimed provisioning session may already have a remote
					// process.  It must remain retryable instead of being marked as
					// an ordinary provisioning failure.
					const revokeReason = "access request cancelled during provisioning"
					if updateErr := s.sessions.MarkProvisionRevokeFailed(ctx, q, linkedSession.ID, linkedSession.Version, revokeReason); updateErr != nil {
						return updateErr
					}
					if eventErr := s.sessionEvents.Append(ctx, q, domain.SessionEvent{
						ID: id.New(), SessionID: linkedSession.ID, EventType: "session.revoke_failed",
						ActorType: cancellationActorType(isAdmin), ActorID: stringPtr(userID), Metadata: map[string]any{"reason": revokeReason},
					}); eventErr != nil {
						return eventErr
					}
					if auditErr := s.appendAudit(ctx, q, domain.AuditEvent{
						EventType: "session.revoke_failed", ActorType: cancellationActorType(isAdmin), ActorID: stringPtr(userID),
						SubjectUserID: stringPtr(request.ApplicantID), RequestID: stringPtr(request.ID),
						SessionID: stringPtr(linkedSession.ID), AssetID: stringPtr(request.AssetID),
						TargetPort: intPtr(request.TargetPort), Result: stringPtr("failed"), Reason: stringPtr(revokeReason),
					}); auditErr != nil {
						return auditErr
					}
					_, outboxErr := s.outbox.CreateIfNoActive(ctx, q, domain.OutboxEvent{
						ID: id.New(), AggregateType: "session", AggregateID: linkedSession.ID,
						EventType: outboxSessionRevoke,
						Payload:   map[string]any{"session_id": linkedSession.ID, "reason": "request_cancelled"},
						Status:    "pending",
					})
					if outboxErr != nil {
						return outboxErr
					}
					revokeQueued = true
				}
			case domain.SessionRunning, domain.SessionRevokeFailed, domain.SessionManualIntervention:
				if _, updateErr := s.sessions.BeginRevoke(ctx, q, linkedSession.ID); updateErr != nil {
					return updateErr
				}
				if eventErr := s.sessionEvents.Append(ctx, q, domain.SessionEvent{
					ID: id.New(), SessionID: linkedSession.ID, EventType: "session.revoke_requested",
					ActorType: cancellationActorType(isAdmin), ActorID: stringPtr(userID), Metadata: map[string]any{"reason": "request_cancelled"},
				}); eventErr != nil {
					return eventErr
				}
				revokeQueued = true
			case domain.SessionRevoking:
				// Usually the first transition already owns a durable revoke event.
				// Re-check it through CreateIfNoActive below so a row recovered from
				// an older deployment (or a manually repaired row) cannot remain
				// stuck in revoking without a command.
				revokeQueued = true
			}
		}
		if !requestAlreadyTerminal {
			if auditErr := s.appendAudit(ctx, q, domain.AuditEvent{
				EventType:     "access_request.cancelled",
				ActorType:     cancellationActorType(isAdmin),
				ActorID:       stringPtr(userID),
				SubjectUserID: stringPtr(request.ApplicantID),
				RequestID:     stringPtr(request.ID),
				AssetID:       stringPtr(request.AssetID),
				TargetPort:    intPtr(request.TargetPort),
				Result:        stringPtr("success"),
			}); auditErr != nil {
				return auditErr
			}
			if outboxErr := s.appendOutbox(ctx, q, "access_request", request.ID, outboxNotifyRequestResult, map[string]any{"request_id": request.ID}); outboxErr != nil {
				return outboxErr
			}
		}
		if revokeQueued {
			_, outboxErr := s.outbox.CreateIfNoActive(ctx, q, domain.OutboxEvent{
				ID: id.New(), AggregateType: "session", AggregateID: linkedSession.ID,
				EventType: outboxSessionRevoke,
				Payload:   map[string]any{"session_id": linkedSession.ID, "reason": "request_cancelled"}, Status: "pending",
			})
			return outboxErr
		}
		return nil
	})
	if err != nil {
		return domain.AccessRequest{}, fmt.Errorf("cancel access request: %w", err)
	}
	if linkedSession != nil {
		s.discardSessionToken(ctx, linkedSession.ID)
	}
	return cancelled, nil
}

func (s *AccessService) DecideApproval(ctx context.Context, approverID, approvalID string, decision domain.ApprovalDecision, comment *string) (ApprovalResult, error) {
	if decision != domain.ApprovalApproved && decision != domain.ApprovalRejected {
		return ApprovalResult{}, fmt.Errorf("unsupported approval decision: %w", ErrValidation)
	}
	if err := s.Authorize(ctx, approverID, authz.PermissionApprovalManage); err != nil {
		return ApprovalResult{}, err
	}
	if err := validateUUID(approvalID, "approval ID"); err != nil {
		return ApprovalResult{}, err
	}
	if comment != nil {
		trimmed := strings.TrimSpace(*comment)
		if len([]rune(trimmed)) > 4000 {
			return ApprovalResult{}, fmt.Errorf("approval comment is too long: %w", ErrValidation)
		}
		if trimmed == "" {
			comment = nil
		} else {
			comment = &trimmed
		}
	}
	approval, err := s.approvals.GetByID(ctx, s.db, approvalID)
	if err != nil {
		return ApprovalResult{}, fmt.Errorf("load approval: %w", err)
	}
	request, err := s.requests.GetByID(ctx, s.db, approval.RequestID)
	if err != nil {
		return ApprovalResult{}, fmt.Errorf("load approval request: %w", err)
	}
	if approval.ApproverID != approverID {
		return ApprovalResult{}, fmt.Errorf("decide approval: %w", ErrForbidden)
	}
	if request.ApplicantID == approverID {
		return ApprovalResult{}, fmt.Errorf("self approval is forbidden: %w", ErrForbidden)
	}
	if request.Status != domain.AccessRequestPendingApproval || approval.Decision != nil {
		return ApprovalResult{}, fmt.Errorf("approval has already been processed: %w", ErrStateConflict)
	}
	approvals, err := s.approvals.ListByRequest(ctx, s.db, request.ID)
	if err != nil {
		return ApprovalResult{}, fmt.Errorf("load approval chain: %w", err)
	}
	currentLevel, complete := nextApprovalLevel(approvals)
	if complete || approval.ApprovalLevel != currentLevel {
		return ApprovalResult{}, fmt.Errorf("approval is not for the current approval level: %w", ErrStateConflict)
	}

	result := ApprovalResult{Request: request}
	err = InTx(ctx, s.db, func(q repository.DBTX) error {
		if err := (repository.IAMRepository{}).Lock(ctx, q, true); err != nil {
			return err
		}
		// Serialize every approval decision with cancellation and the final
		// approved->provisioning transition. Re-read both rows under the lock so
		// the preflight snapshot cannot authorize a stale decision.
		lockedRequest, lockErr := s.requests.GetByIDForUpdate(ctx, q, request.ID)
		if lockErr != nil {
			return lockErr
		}
		request = lockedRequest
		lockedApproval, approvalErr := s.approvals.GetByID(ctx, q, approvalID)
		if approvalErr != nil {
			return approvalErr
		}
		approval = lockedApproval
		if err := s.validateWorkflowVoter(ctx, q, request, approval); err != nil {
			return err
		}
		if approval.ApproverID != approverID {
			return fmt.Errorf("decide approval: %w", ErrForbidden)
		}
		if request.ApplicantID == approverID {
			return fmt.Errorf("self approval is forbidden: %w", ErrForbidden)
		}
		if request.Status != domain.AccessRequestPendingApproval || approval.Decision != nil {
			return fmt.Errorf("approval has already been processed: %w", ErrStateConflict)
		}
		currentApprovals, chainErr := s.approvals.ListByRequest(ctx, q, request.ID)
		if chainErr != nil {
			return chainErr
		}
		currentLevel, complete := nextApprovalLevel(currentApprovals)
		if complete || approval.ApprovalLevel != currentLevel {
			return fmt.Errorf("approval is not for the current approval level: %w", ErrStateConflict)
		}
		decided, decideErr := s.approvals.Decide(ctx, q, approvalID, approverID, decision, comment)
		if decideErr != nil {
			return decideErr
		}
		result.Approval = decided
		shouldTransition := decision == domain.ApprovalRejected
		targetStatus := domain.AccessRequestRejected
		if decision == domain.ApprovalApproved {
			// The immutable per-level threshold supports both any and all modes.
			updatedApprovals, listErr := s.approvals.ListByRequest(ctx, q, request.ID)
			if listErr != nil {
				return listErr
			}
			_, allLevelsApproved := nextApprovalLevel(updatedApprovals)
			shouldTransition = allLevelsApproved
			if shouldTransition {
				targetStatus = domain.AccessRequestApproved
			}
		}
		if shouldTransition {
			updated, transitionErr := s.requests.TransitionStatus(ctx, q, request.ID, domain.AccessRequestPendingApproval, targetStatus)
			if transitionErr != nil {
				return transitionErr
			}
			result.Request = updated
		}
		if decision == domain.ApprovalApproved && shouldTransition {
			if lockErr := s.sessions.LockApplicantAssetPort(ctx, q, request.ApplicantID, request.AssetID, request.TargetPort); lockErr != nil {
				return lockErr
			}
			if _, activeErr := s.sessions.FindActiveByApplicantAssetPort(ctx, q, request.ApplicantID, request.AssetID, request.TargetPort); activeErr == nil {
				return fmt.Errorf("an active session already exists: %w", repository.ErrConflict)
			} else if !errors.Is(activeErr, repository.ErrNotFound) {
				return activeErr
			}
			asset, assetErr := s.assets.GetByIDForUpdate(ctx, q, request.AssetID)
			if assetErr != nil {
				return assetErr
			}
			if asset.Status != domain.ResourceStatusEnabled {
				return ErrStateConflict
			}
			newSession, sessionErr := s.newSession(ctx, q, asset, request)
			if sessionErr != nil {
				return sessionErr
			}
			session, sessionErr := s.sessions.Create(ctx, q, newSession)
			if sessionErr != nil {
				return sessionErr
			}
			result.Session = &session
		}
		if auditErr := s.appendAudit(ctx, q, domain.AuditEvent{
			EventType:     "access_request.approval_decided",
			ActorType:     "user",
			ActorID:       stringPtr(approverID),
			SubjectUserID: stringPtr(request.ApplicantID),
			RequestID:     stringPtr(request.ID),
			AssetID:       stringPtr(request.AssetID),
			TargetPort:    intPtr(request.TargetPort),
			Result:        stringPtr(string(decision)),
			Reason:        comment,
		}); auditErr != nil {
			return auditErr
		}
		if result.Session != nil {
			if auditErr := s.appendAudit(ctx, q, domain.AuditEvent{
				EventType:     "session.provisioning",
				ActorType:     "system",
				SubjectUserID: stringPtr(request.ApplicantID),
				RequestID:     stringPtr(request.ID),
				SessionID:     stringPtr(result.Session.ID),
				AssetID:       stringPtr(request.AssetID),
				TargetPort:    intPtr(request.TargetPort),
				Result:        stringPtr("queued"),
			}); auditErr != nil {
				return auditErr
			}
			if outboxErr := s.appendOutbox(ctx, q, "session", result.Session.ID, outboxSessionProvision, map[string]any{"session_id": result.Session.ID}); outboxErr != nil {
				return outboxErr
			}
		}
		if result.Request.Status == domain.AccessRequestPendingApproval {
			return s.appendOutbox(ctx, q, "access_request", result.Request.ID, outboxNotifyApproval, map[string]any{"request_id": result.Request.ID})
		}
		return s.appendOutbox(ctx, q, "access_request", result.Request.ID, outboxNotifyRequestResult, map[string]any{"request_id": result.Request.ID})
	})
	if err != nil {
		return ApprovalResult{}, fmt.Errorf("decide approval: %w", err)
	}
	return result, nil
}

// DecideApprovalByExternalUser accepts either the platform UUID or a Feishu
// open_id. Feishu callbacks carry the latter, while the rest of the service
// uses internal UUIDs. Resolving it here keeps the HTTP adapter from bypassing
// the same authorization and state checks as the normal approval endpoint.
func (s *AccessService) DecideApprovalByExternalUser(ctx context.Context, approverRef, approvalID string, decision domain.ApprovalDecision, comment *string) (ApprovalResult, error) {
	approverRef = strings.TrimSpace(approverRef)
	if approverRef == "" {
		return ApprovalResult{}, fmt.Errorf("approver identity is required: %w", ErrValidation)
	}
	approverID := approverRef
	if !id.IsUUID(approverRef) {
		user, err := s.users.GetByFeishuOpenID(ctx, s.db, approverRef)
		if err != nil {
			if !errors.Is(err, repository.ErrNotFound) {
				return ApprovalResult{}, fmt.Errorf("resolve Feishu approver: %w", err)
			}
			user, err = s.users.GetByFeishuUnionID(ctx, s.db, approverRef)
			if err != nil {
				return ApprovalResult{}, fmt.Errorf("resolve Feishu approver: %w", err)
			}
		}
		approverID = user.ID
	}
	return s.DecideApproval(ctx, approverID, approvalID, decision, comment)
}

func (s *AccessService) ProvisionSession(ctx context.Context, sessionID string) (domain.Session, error) {
	if err := validateUUID(sessionID, "session ID"); err != nil {
		return domain.Session{}, err
	}
	session, err := s.sessions.GetByID(ctx, s.db, sessionID)
	if err != nil {
		return domain.Session{}, fmt.Errorf("load provisioning session: %w", err)
	}
	if session.Status != domain.SessionProvisioning {
		return session, nil
	}
	request, err := s.requests.GetByID(ctx, s.db, session.RequestID)
	if err != nil {
		return domain.Session{}, fmt.Errorf("load provisioning request: %w", err)
	}
	if request.Status != domain.AccessRequestApproved {
		return s.failProvision(ctx, session, request, "access request is no longer approved")
	}
	if validateWebAccess(request, session.AuditPolicy) != nil {
		return s.failProvision(ctx, session, request, "approved request is missing direct-access constraints")
	}
	approvalExpiry := approvedSessionExpiry(session, request)
	if !approvalExpiry.After(s.clock()) {
		return s.failProvision(ctx, session, request, "access request session validity has expired")
	}
	applicant, err := s.users.GetByID(ctx, s.db, request.ApplicantID)
	if err != nil {
		return domain.Session{}, fmt.Errorf("load provisioning applicant: %w", err)
	}
	if applicant.Status != domain.UserStatusActive {
		return s.failProvision(ctx, session, request, "applicant is inactive")
	}
	if request.ApprovalMode == "admin_test" {
		if err := s.Authorize(ctx, request.ApplicantID, authz.PermissionRoleManage); err != nil {
			return s.failProvision(ctx, session, request, "test access administrator permission is no longer available")
		}
	}
	asset, err := s.assets.GetByID(ctx, s.db, request.AssetID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return s.failProvision(ctx, session, request, "asset is no longer available")
		}
		return domain.Session{}, fmt.Errorf("load provisioning asset: %w", err)
	}
	if asset.Status != domain.ResourceStatusEnabled {
		return s.failProvision(ctx, session, request, "asset is not enabled")
	}
	if _, err := s.assets.GetPort(ctx, s.db, asset.ID, request.TargetPort, "tcp"); err != nil {
		return s.failProvision(ctx, session, request, "approved asset port is no longer enabled")
	}
	checker, readinessSupported := s.gateway.(gateway.ReadinessChecker)
	var heartbeatAfter *time.Time
	if readinessSupported {
		cutoff := s.clock().Add(-s.gatewayHeartbeatMaxAge)
		heartbeatAfter = &cutoff
	}
	candidates, err := s.gateways.ListAvailableForAsset(ctx, s.db, asset.ID, session.ID, heartbeatAfter)
	if err != nil {
		return domain.Session{}, fmt.Errorf("list provisioning gateway candidates: %w", err)
	}
	var gatewayRecord domain.Gateway
	var claimed domain.Session
	for _, candidate := range candidates {
		if readinessSupported {
			if probeErr := s.probeGateway(ctx, checker, candidate); probeErr != nil {
				s.logger.Warn().Err(probeErr).Str("session_id", session.ID).Str("gateway_id", candidate.ID).Msg("skip unavailable provisioning gateway")
				continue
			}
		}
		claimErr := InTx(ctx, s.db, func(q repository.DBTX) error {
			if lockErr := s.gateways.LockCapacity(ctx, q, candidate.ID); lockErr != nil {
				return lockErr
			}
			var assignErr error
			claimed, assignErr = s.sessions.ClaimProvisioningOnGateway(
				ctx, q, session.ID, session.Version, s.clock().Add(-provisioningLease),
				candidate.ID, asset.ID, heartbeatAfter,
			)
			return assignErr
		})
		if claimErr == nil {
			gatewayRecord = candidate
			break
		}
		if !errors.Is(claimErr, repository.ErrNotFound) {
			return domain.Session{}, fmt.Errorf("claim provisioning gateway capacity: %w", claimErr)
		}
		current, getErr := s.sessions.GetByID(ctx, s.db, session.ID)
		if getErr != nil {
			return domain.Session{}, fmt.Errorf("read concurrently claimed session: %w", getErr)
		}
		if current.Status != domain.SessionProvisioning || current.Version != session.Version {
			return current, nil
		}
	}
	if claimed.ID == "" {
		return session, fmt.Errorf("no healthy gateway capacity is available: %w", gateway.ErrUnavailable)
	}
	session = claimed
	if err := gateway.ValidateConnectionIdentity(session.ConnectionMode, ""); err != nil {
		return s.failProvision(ctx, session, request, "unsupported session protocol; request a new session")
	}
	attemptCtx, stopLeaseHeartbeat, leaseFailures := s.startProvisioningLeaseHeartbeat(ctx, session)
	targetAccount := ""
	if request.TargetAccount != nil {
		targetAccount = *request.TargetAccount
	}
	response, err := s.createGatewaySession(attemptCtx, gatewayRecord, asset, gateway.CreateSessionRequest{
		ConnectionMode: session.ConnectionMode,
		AuditPolicy:    session.AuditPolicy,
		SessionID:      session.ID,
		TargetID:       asset.ID,
		TargetPort:     request.TargetPort,
		SourceIP:       requestSourceIP(request),
		WebOnly:        request.SourceIP == nil,
		TargetAccount:  targetAccount,
		TTLSeconds:     request.TTLSeconds,
		ExpiresAt:      &approvalExpiry,
		MaxConnections: gateway.MaxSessionConnections,
	})
	stopLeaseHeartbeat()
	if leaseErr := readProvisioningLeaseFailure(leaseFailures); leaseErr != nil {
		if err == nil {
			err = fmt.Errorf("provisioning lease heartbeat failed: %w", leaseErr)
		} else {
			err = errors.Join(err, fmt.Errorf("provisioning lease heartbeat failed: %w", leaseErr))
		}
	}
	if err != nil {
		s.logger.Error().Err(err).Str("session_id", session.ID).Str("gateway_id", gatewayRecord.ID).Msg("create gateway session failed")
		current, owned, stateErr := s.provisioningLeaseState(ctx, session)
		if stateErr != nil {
			return session, errors.Join(fmt.Errorf("create gateway session: %w", err), fmt.Errorf("verify provisioning lease ownership: %w", stateErr))
		}
		if current.Status == domain.SessionRunning || isTerminalSession(current.Status) {
			return current, nil
		}
		if !owned {
			return current, fmt.Errorf("create gateway session: %w (provisioning lease was replaced)", err)
		}
		// A transport response can be lost after the gateway has created the
		// process. The provisioning lease guarantees this worker owns the attempt,
		// so it is safe to probe and compensate before marking the local session
		// failed. The gateway's own TTL remains the final fallback if both calls
		// fail.
		cleanupErr := error(nil)
		if remote, statusErr := s.gateway.GetSession(ctx, gatewayRecord.ManagementEndpoint, session.ID); statusErr == nil {
			if !isTerminalGatewayStatus(remote.Status) {
				cleanupErr = s.compensateGatewaySession(ctx, gatewayRecord.ManagementEndpoint, session.ID)
			}
		} else {
			// A failed status probe leaves the remote state unknown. The close
			// endpoint is idempotent, so issue the compensation anyway.
			cleanupErr = s.compensateGatewaySession(ctx, gatewayRecord.ManagementEndpoint, session.ID)
		}
		if cleanupErr != nil {
			return s.failProvisionRevokeFailed(ctx, session, request, "gateway_session_creation_failed", cleanupErr)
		}
		return s.failProvision(ctx, session, request, "gateway_session_creation_failed")
	}
	if !validGatewayCreateResponse(response, session.ID, session.ConnectionMode) {
		current, owned, stateErr := s.provisioningLeaseState(ctx, session)
		if stateErr != nil {
			return session, errors.Join(fmt.Errorf("gateway returned an invalid session response: %w", ErrStateConflict), fmt.Errorf("verify provisioning lease ownership: %w", stateErr))
		}
		if current.Status == domain.SessionRunning || isTerminalSession(current.Status) {
			return current, nil
		}
		if !owned {
			return current, fmt.Errorf("gateway returned an invalid session response: %w (provisioning lease was replaced)", ErrStateConflict)
		}
		cleanupErr := s.compensateGatewaySession(ctx, gatewayRecord.ManagementEndpoint, session.ID)
		if cleanupErr != nil {
			return s.failProvisionRevokeFailed(ctx, session, request, "gateway returned an invalid session response", cleanupErr)
		}
		failed, failErr := s.failProvision(ctx, session, request, "gateway returned an invalid session response")
		return failed, failErr
	}
	now := s.clock()
	startedAt := response.StartedAt
	if startedAt.IsZero() {
		startedAt = now
	}
	const gatewayClockSkew = 2 * time.Minute
	if startedAt.Before(now.Add(-gatewayClockSkew)) || startedAt.After(now.Add(gatewayClockSkew)) {
		current, owned, stateErr := s.provisioningLeaseState(ctx, session)
		if stateErr != nil {
			return session, errors.Join(fmt.Errorf("gateway returned an invalid start time: %w", ErrStateConflict), fmt.Errorf("verify provisioning lease ownership: %w", stateErr))
		}
		if current.Status == domain.SessionRunning || isTerminalSession(current.Status) {
			return current, nil
		}
		if !owned {
			return current, fmt.Errorf("gateway returned an invalid start time: %w (provisioning lease was replaced)", ErrStateConflict)
		}
		cleanupErr := s.compensateGatewaySession(ctx, gatewayRecord.ManagementEndpoint, session.ID)
		if cleanupErr != nil {
			return s.failProvisionRevokeFailed(ctx, session, request, "gateway returned an invalid start time", cleanupErr)
		}
		failed, failErr := s.failProvision(ctx, session, request, "gateway returned an invalid start time")
		return failed, failErr
	}
	expiresAt := response.ExpiresAt
	if expiresAt.IsZero() {
		expiresAt = approvalExpiry
	}
	if !expiresAt.After(startedAt) || !expiresAt.After(now) || expiresAt.After(approvalExpiry) || expiresAt.After(startedAt.Add(time.Duration(request.TTLSeconds)*time.Second)) {
		current, owned, stateErr := s.provisioningLeaseState(ctx, session)
		if stateErr != nil {
			return session, errors.Join(fmt.Errorf("gateway expiry exceeds requested TTL: %w", ErrStateConflict), fmt.Errorf("verify provisioning lease ownership: %w", stateErr))
		}
		if current.Status == domain.SessionRunning || isTerminalSession(current.Status) {
			return current, nil
		}
		if !owned {
			return current, fmt.Errorf("gateway expiry exceeds requested TTL: %w (provisioning lease was replaced)", ErrStateConflict)
		}
		cleanupErr := s.compensateGatewaySession(ctx, gatewayRecord.ManagementEndpoint, session.ID)
		if cleanupErr != nil {
			return s.failProvisionRevokeFailed(ctx, session, request, "gateway expiry exceeds requested TTL", cleanupErr)
		}
		failed, failErr := s.failProvision(ctx, session, request, "gateway expiry exceeds requested TTL")
		return failed, failErr
	}
	var running domain.Session
	requestCancelled := false
	err = InTx(ctx, s.db, func(q repository.DBTX) error {
		// Lock the request before the session. Cancellation and final approval use
		// this same order, which prevents an approved->cancelled race from leaving
		// a newly-created session orphaned.
		currentRequest, requestLockErr := s.requests.GetByIDForUpdate(ctx, q, request.ID)
		if requestLockErr != nil {
			return requestLockErr
		}
		request = currentRequest
		currentSession, lockErr := s.sessions.GetByIDForUpdate(ctx, q, session.ID)
		if lockErr != nil {
			return lockErr
		}
		if currentSession.Status != domain.SessionProvisioning || currentSession.Version != session.Version {
			// Another worker or the cancellation path already resolved this
			// attempt.  Its durable revoke command, when needed, owns cleanup.
			running = currentSession
			if currentSession.Status == domain.SessionRevokeFailed || currentSession.Status == domain.SessionRevoking || isTerminalSession(currentSession.Status) {
				requestCancelled = true
				return nil
			}
			return fmt.Errorf("provisioning lease was replaced: %w", ErrStateConflict)
		}

		// Serialize the final authorization decision with catalog/user lifecycle
		// changes.  This closes the window where a resource is disabled after the
		// remote Agent created a process but before the local row becomes running.
		latestApplicant, applicantErr := s.users.GetByIDForUpdate(ctx, q, request.ApplicantID)
		if applicantErr != nil {
			return applicantErr
		}
		latestRegion, regionErr := s.regions.GetByIDForUpdate(ctx, q, asset.RegionID)
		if regionErr != nil {
			return regionErr
		}
		latestAsset, assetErr := s.assets.GetByIDForUpdate(ctx, q, asset.ID)
		if assetErr != nil {
			return assetErr
		}
		latestGateway, gatewayErr := s.gateways.GetByIDForUpdate(ctx, q, gatewayRecord.ID)
		if gatewayErr != nil {
			return gatewayErr
		}
		var safetyReason string
		switch {
		case latestApplicant.Status != domain.UserStatusActive:
			safetyReason = "applicant_inactive_after_gateway_session_creation"
		case latestRegion.Status != domain.ResourceStatusEnabled:
			safetyReason = "region_disabled_after_gateway_session_creation"
		case latestAsset.Status != domain.ResourceStatusEnabled:
			safetyReason = "asset_disabled_after_gateway_session_creation"
		case latestGateway.Status != domain.ResourceStatusEnabled:
			safetyReason = "gateway_disabled_after_gateway_session_creation"
		}
		if safetyReason == "" {
			binding, bindingErr := s.gateways.GetAssetBindingForUpdate(ctx, q, asset.ID, gatewayRecord.ID)
			if bindingErr != nil {
				if errors.Is(bindingErr, repository.ErrNotFound) {
					safetyReason = "gateway_binding_removed_after_gateway_session_creation"
				} else {
					return bindingErr
				}
			} else if !binding.Enabled {
				safetyReason = "gateway_binding_disabled_after_gateway_session_creation"
			}
		}
		if safetyReason == "" {
			port, portErr := s.assets.GetPortForUpdate(ctx, q, asset.ID, request.TargetPort, "tcp")
			if portErr != nil {
				if errors.Is(portErr, repository.ErrNotFound) {
					safetyReason = "asset_port_removed_after_gateway_session_creation"
				} else {
					return portErr
				}
			} else if !port.Enabled {
				safetyReason = "asset_port_disabled_after_gateway_session_creation"
			}
		}

		if request.Status != domain.AccessRequestApproved || safetyReason != "" {
			// The gateway response proves that a remote session may exist even
			// though authorization was withdrawn.  Keep the local row retryable and
			// hand cleanup to the durable revoke outbox.
			revokeReason := "access request cancelled after gateway session creation"
			outboxReason := "request_cancelled"
			if safetyReason != "" && request.Status == domain.AccessRequestApproved {
				revokeReason = safetyReason
				outboxReason = "authorization_changed"
			}
			if updateErr := s.sessions.MarkProvisionRevokeFailed(ctx, q, session.ID, session.Version, revokeReason); updateErr != nil {
				return updateErr
			}
			var readErr error
			running, readErr = s.sessions.GetByID(ctx, q, session.ID)
			if readErr != nil {
				return readErr
			}
			if eventErr := s.sessionEvents.Append(ctx, q, domain.SessionEvent{
				ID: id.New(), SessionID: session.ID, EventType: "session.revoke_failed",
				ActorType: "system", Metadata: map[string]any{"reason": revokeReason},
			}); eventErr != nil {
				return eventErr
			}
			if auditErr := s.appendAudit(ctx, q, domain.AuditEvent{
				EventType: "session.revoke_failed", ActorType: "system",
				SubjectUserID: stringPtr(request.ApplicantID), RequestID: stringPtr(request.ID),
				SessionID: stringPtr(session.ID), AssetID: stringPtr(request.AssetID),
				TargetPort: intPtr(request.TargetPort), Result: stringPtr("failed"), Reason: stringPtr(revokeReason),
			}); auditErr != nil {
				return auditErr
			}
			if _, outboxErr := s.outbox.CreateIfNoActive(ctx, q, domain.OutboxEvent{
				ID: id.New(), AggregateType: "session", AggregateID: session.ID,
				EventType: outboxSessionRevoke,
				Payload:   map[string]any{"session_id": session.ID, "reason": outboxReason}, Status: "pending",
			}); outboxErr != nil {
				return outboxErr
			}
			requestCancelled = true
			return nil
		}

		var updateErr error
		running, updateErr = s.sessions.MarkDirectRunning(
			ctx, q, session.ID, session.Version, response.ProcessID,
			response.ListenerPort, response.ExternalPort, response.ExposureMode, response.ExposureRef,
			startedAt, expiresAt, "", "",
		)
		if updateErr != nil {
			return updateErr
		}
		if eventErr := s.sessionEvents.Append(ctx, q, domain.SessionEvent{
			ID:        id.New(),
			SessionID: session.ID,
			EventType: "session.started",
			ActorType: "system",
			Metadata: map[string]any{
				"connection_mode": gateway.NormalizeConnectionMode(session.ConnectionMode),
				"gateway_id":      gatewayRecord.ID,
				"process_id":      response.ProcessID,
				"listener_port":   response.ListenerPort,
				"external_port":   response.ExternalPort,
				"exposure_mode":   response.ExposureMode,
				"exposure_ref":    response.ExposureRef,
			},
		}); eventErr != nil {
			return eventErr
		}
		if auditErr := s.appendAudit(ctx, q, domain.AuditEvent{
			EventType:     "session.started",
			ActorType:     "system",
			SubjectUserID: stringPtr(request.ApplicantID),
			RequestID:     stringPtr(request.ID),
			SessionID:     stringPtr(session.ID),
			RegionID:      stringPtr(asset.RegionID),
			AssetID:       stringPtr(asset.ID),
			TargetPort:    intPtr(request.TargetPort),
			SourceIP:      request.SourceIP,
			Result:        stringPtr("success"),
		}); auditErr != nil {
			return auditErr
		}
		// Re-check after the conditional update as well.  A caller that changes
		// the request through another path can race this transaction; in that
		// case immediately queue revocation and suppress the ready notification.
		latestRequest, requestErr := s.requests.GetByID(ctx, q, request.ID)
		if requestErr != nil {
			return requestErr
		}
		if latestRequest.Status != domain.AccessRequestApproved {
			var revokeErr error
			running, revokeErr = s.sessions.BeginRevoke(ctx, q, session.ID)
			if revokeErr != nil {
				return revokeErr
			}
			if eventErr := s.sessionEvents.Append(ctx, q, domain.SessionEvent{
				ID: id.New(), SessionID: session.ID, EventType: "session.revoke_requested",
				ActorType: "system", Metadata: map[string]any{"reason": "request_cancelled"},
			}); eventErr != nil {
				return eventErr
			}
			if auditErr := s.appendAudit(ctx, q, domain.AuditEvent{
				EventType: "session.revoke_requested", ActorType: "system",
				SubjectUserID: stringPtr(request.ApplicantID), RequestID: stringPtr(request.ID),
				SessionID: stringPtr(session.ID), AssetID: stringPtr(request.AssetID),
				TargetPort: intPtr(request.TargetPort), Result: stringPtr("queued"), Reason: stringPtr("request_cancelled"),
			}); auditErr != nil {
				return auditErr
			}
			if _, outboxErr := s.outbox.CreateIfNoActive(ctx, q, domain.OutboxEvent{
				ID: id.New(), AggregateType: "session", AggregateID: session.ID,
				EventType: outboxSessionRevoke,
				Payload:   map[string]any{"session_id": session.ID, "reason": "request_cancelled"}, Status: "pending",
			}); outboxErr != nil {
				return outboxErr
			}
			requestCancelled = true
			return nil
		}
		return s.appendOutbox(ctx, q, "session", session.ID, outboxNotifySessionReady, map[string]any{"session_id": session.ID})
	})
	if err != nil {
		// A duplicate provisioning worker can lose the optimistic version race
		// after another worker has taken over.  The version is the bounded lease
		// identity: if it changed, this worker no longer owns the remote attempt
		// and must not close a session created by the newer owner.
		current, stateErr := s.sessions.GetByID(ctx, s.db, session.ID)
		if stateErr != nil {
			return session, errors.Join(fmt.Errorf("persist running session: %w", err), fmt.Errorf("verify provisioning lease ownership: %w", stateErr))
		}
		if current.Status == domain.SessionRunning || isTerminalSession(current.Status) {
			return current, nil
		}
		if current.Status != domain.SessionProvisioning || current.Version != session.Version {
			return current, fmt.Errorf("persist running session: %w (provisioning lease was replaced)", err)
		}

		cleanupErr := s.compensateGatewaySession(ctx, gatewayRecord.ManagementEndpoint, session.ID)
		if cleanupErr != nil {
			failed, failureErr := s.failProvisionRevokeFailed(ctx, session, request, "persist running session failed", cleanupErr)
			return failed, errors.Join(fmt.Errorf("persist running session: %w", err), failureErr)
		}
		failed, failureErr := s.failProvision(ctx, session, request, "persist running session failed")
		return failed, errors.Join(fmt.Errorf("persist running session: %w", err), failureErr)
	}
	if requestCancelled {
		return running, nil
	}
	return running, nil
}

func (s *AccessService) GetSession(ctx context.Context, userID, sessionID string) (SessionView, error) {
	if err := s.requireActiveUser(ctx, userID); err != nil {
		return SessionView{}, err
	}
	if err := validateUUID(sessionID, "session ID"); err != nil {
		return SessionView{}, err
	}
	session, err := s.sessions.GetByID(ctx, s.db, sessionID)
	if err != nil {
		return SessionView{}, fmt.Errorf("get session: %w", err)
	}
	request, err := s.requests.GetByID(ctx, s.db, session.RequestID)
	if err != nil {
		return SessionView{}, fmt.Errorf("get session request: %w", err)
	}
	if request.ApplicantID != userID && !s.isAdminUser(ctx, userID) {
		return SessionView{}, fmt.Errorf("get session: %w", ErrForbidden)
	}
	return s.sessionView(ctx, userID, session, request)
}

func (s *AccessService) sessionView(ctx context.Context, userID string, session domain.Session, request domain.AccessRequest) (SessionView, error) {
	gatewayRecord, err := s.gateways.GetByID(ctx, s.db, session.GatewayID)
	if err != nil {
		return SessionView{}, fmt.Errorf("get session gateway: %w", err)
	}
	var host string
	if _, ok := s.gateway.(gateway.ApprovedSessionClient); ok {
		host, err = s.clientAccessHost(ctx)
	} else {
		host, err = directGatewayHost(gatewayRecord.PublicEndpoint)
	}
	if err != nil {
		return SessionView{}, fmt.Errorf("get session gateway address: %w", err)
	}
	view := SessionView{Session: session, Request: request, GatewayHost: host}
	if session.ConnectionMode == gateway.ConnectionModeAudit {
		view.AuditTrust, err = s.sessionAuditTrust(ctx, session, request.AssetID)
		if err != nil {
			return SessionView{}, err
		}
	}
	view.CanConnect = request.ApplicantID == userID && request.Status == domain.AccessRequestApproved &&
		session.Status == domain.SessionRunning && session.ExpiresAt != nil && session.ExpiresAt.After(s.clock()) &&
		(session.ConnectionMode == gateway.ConnectionModeNative || session.ConnectionMode == gateway.ConnectionModeAudit)
	view.CanWebConnect = canUseWebTerminal(userID, session, request, s.clock())
	view.CanConnect = view.CanConnect && request.SourceIP != nil
	if request.SourceIP == nil {
		view.GatewayHost = ""
	}
	if session.ExternalPort != nil && request.SourceIP != nil {
		view.GatewayPort = *session.ExternalPort
		view.GatewayEndpoint = net.JoinHostPort(host, fmt.Sprintf("%d", *session.ExternalPort))
	}
	return view, nil
}

func (s *AccessService) GetSessionByRequest(ctx context.Context, userID, requestID string) (SessionView, error) {
	if err := validateUUID(requestID, "request ID"); err != nil {
		return SessionView{}, err
	}
	request, err := s.GetAccessRequest(ctx, userID, requestID)
	if err != nil {
		return SessionView{}, err
	}
	if request.ApplicantID != userID && !s.isAdminUser(ctx, userID) {
		return SessionView{}, fmt.Errorf("get request session: %w", ErrForbidden)
	}
	session, err := s.sessions.GetByRequestID(ctx, s.db, request.ID)
	if err != nil {
		return SessionView{}, fmt.Errorf("get request session: %w", err)
	}
	return s.GetSession(ctx, userID, session.ID)
}

func (s *AccessService) CloseSession(ctx context.Context, userID, sessionID string) (domain.Session, error) {
	if err := s.requireActiveUser(ctx, userID); err != nil {
		return domain.Session{}, err
	}
	if err := validateUUID(sessionID, "session ID"); err != nil {
		return domain.Session{}, err
	}
	session, err := s.sessions.GetByID(ctx, s.db, sessionID)
	if err != nil {
		return domain.Session{}, fmt.Errorf("load session: %w", err)
	}
	request, err := s.requests.GetByID(ctx, s.db, session.RequestID)
	if err != nil {
		return domain.Session{}, fmt.Errorf("load session request: %w", err)
	}
	if request.ApplicantID != userID && !s.isAdminUser(ctx, userID) {
		return domain.Session{}, fmt.Errorf("close session: %w", ErrForbidden)
	}
	if isTerminalSession(session.Status) {
		return session, nil
	}
	if session.Status == domain.SessionProvisioning {
		return domain.Session{}, fmt.Errorf("session is still provisioning: %w", ErrStateConflict)
	}
	var transitioned domain.Session
	err = InTx(ctx, s.db, func(q repository.DBTX) error {
		current, lockErr := s.sessions.GetByIDForUpdate(ctx, q, sessionID)
		if lockErr != nil {
			return lockErr
		}
		if isTerminalSession(current.Status) {
			transitioned = current
			return nil
		}
		switch current.Status {
		case domain.SessionProvisioning:
			return fmt.Errorf("session is still provisioning: %w", ErrStateConflict)
		case domain.SessionRunning, domain.SessionRevokeFailed:
			var beginErr error
			transitioned, beginErr = s.sessions.BeginRevoke(ctx, q, current.ID)
			if beginErr != nil {
				return beginErr
			}
			if eventErr := s.sessionEvents.Append(ctx, q, domain.SessionEvent{
				ID: id.New(), SessionID: current.ID, EventType: "session.revoke_requested",
				ActorType: "user", ActorID: stringPtr(userID), Metadata: map[string]any{"reason": "user_closed"},
			}); eventErr != nil {
				return eventErr
			}
			if auditErr := s.appendAudit(ctx, q, domain.AuditEvent{
				EventType:     "session.revoke_requested",
				ActorType:     "user",
				ActorID:       stringPtr(userID),
				SubjectUserID: stringPtr(request.ApplicantID),
				RequestID:     stringPtr(request.ID),
				SessionID:     stringPtr(sessionID),
				AssetID:       stringPtr(request.AssetID),
				TargetPort:    intPtr(request.TargetPort),
				Result:        stringPtr("queued"),
			}); auditErr != nil {
				return auditErr
			}
			_, outboxErr := s.outbox.CreateIfNoActive(ctx, q, domain.OutboxEvent{
				ID: id.New(), AggregateType: "session", AggregateID: sessionID,
				EventType: outboxSessionRevoke,
				Payload:   map[string]any{"session_id": sessionID, "reason": "user_closed"}, Status: "pending",
			})
			return outboxErr
		case domain.SessionRevoking:
			transitioned = current
			_, outboxErr := s.outbox.CreateIfNoActive(ctx, q, domain.OutboxEvent{
				ID: id.New(), AggregateType: "session", AggregateID: sessionID,
				EventType: outboxSessionRevoke,
				Payload:   map[string]any{"session_id": sessionID, "reason": "user_closed"}, Status: "pending",
			})
			return outboxErr
		default:
			return fmt.Errorf("close session is in unsupported state %q: %w", current.Status, ErrStateConflict)
		}
	})
	if err != nil {
		return domain.Session{}, fmt.Errorf("begin session close: %w", err)
	}
	// Once revocation is queued the one-time credential must no longer be
	// available, even while the gateway call is waiting in the outbox.
	s.discardSessionToken(ctx, sessionID)
	return transitioned, nil
}

// ForceCloseSession is the administrative escape hatch for a session that
// could not be reclaimed automatically.  It only changes local state and
// appends an outbox command; the gateway call is deliberately performed by
// the worker so the request remains bounded and recoverable across restarts.
func (s *AccessService) ForceCloseSession(ctx context.Context, adminID, sessionID, reason string) (domain.Session, error) {
	if err := s.Authorize(ctx, adminID, authz.PermissionSessionOverride); err != nil {
		return domain.Session{}, err
	}
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return domain.Session{}, requestValidation("请选择需要回收的开放会话")
	}
	if err := validateUUID(sessionID, "session ID"); err != nil {
		return domain.Session{}, requestValidation("会话编号无效，请刷新后重新选择会话")
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "administrator_force_close"
	}
	if len([]rune(reason)) > 4000 {
		return domain.Session{}, requestValidation("回收原因不能超过 4000 个字符")
	}
	session, err := s.sessions.GetByID(ctx, s.db, sessionID)
	if err != nil {
		return domain.Session{}, fmt.Errorf("load force-close session: %w", err)
	}
	request, err := s.requests.GetByID(ctx, s.db, session.RequestID)
	if err != nil {
		return domain.Session{}, fmt.Errorf("load force-close request: %w", err)
	}

	var transitioned domain.Session
	err = InTx(ctx, s.db, func(q repository.DBTX) error {
		// Serialize this administrative decision with provisioning completion.
		// The preflight row can be stale by the time the transaction starts,
		// especially when a worker has just claimed the provisioning lease.
		current, getErr := s.sessions.GetByIDForUpdate(ctx, q, session.ID)
		if getErr != nil {
			return getErr
		}
		queueRevoke := false
		switch current.Status {
		case domain.SessionProvisioning:
			if current.Version == 0 {
				if err := s.sessions.MarkProvisionFailed(ctx, q, current.ID, current.Version, "force-closed before provisioning"); err != nil {
					return err
				}
				transitioned, getErr = s.sessions.GetByID(ctx, q, current.ID)
				if getErr != nil {
					return getErr
				}
				if err := s.sessionEvents.Append(ctx, q, domain.SessionEvent{
					ID: id.New(), SessionID: current.ID, EventType: "session.force_closed_before_start",
					ActorType: "admin", ActorID: stringPtr(adminID), Metadata: map[string]any{"reason": reason},
				}); err != nil {
					return err
				}
				return s.appendAudit(ctx, q, domain.AuditEvent{
					EventType: "session.force_close_requested", ActorType: "admin", ActorID: stringPtr(adminID),
					SubjectUserID: stringPtr(request.ApplicantID), RequestID: stringPtr(request.ID),
					SessionID: stringPtr(current.ID), AssetID: stringPtr(request.AssetID), TargetPort: intPtr(request.TargetPort),
					Result: stringPtr("no_remote_session"), Reason: stringPtr(reason),
				})
			}

			// Version > 0 means a worker has claimed the session.  A remote
			// process may already exist, so preserve a retryable revoke state and
			// persist a command for the revoke worker.
			const revokeReason = "force-closed during provisioning"
			if err := s.sessions.MarkProvisionRevokeFailed(ctx, q, current.ID, current.Version, revokeReason); err != nil {
				return err
			}
			transitioned, getErr = s.sessions.GetByID(ctx, q, current.ID)
			if getErr != nil {
				return getErr
			}
			if err := s.sessionEvents.Append(ctx, q, domain.SessionEvent{
				ID: id.New(), SessionID: current.ID, EventType: "session.revoke_failed",
				ActorType: "admin", ActorID: stringPtr(adminID), Metadata: map[string]any{"reason": revokeReason, "operator_reason": reason},
			}); err != nil {
				return err
			}
			if err := s.appendAudit(ctx, q, domain.AuditEvent{
				EventType: "session.revoke_failed", ActorType: "admin", ActorID: stringPtr(adminID),
				SubjectUserID: stringPtr(request.ApplicantID), RequestID: stringPtr(request.ID),
				SessionID: stringPtr(current.ID), AssetID: stringPtr(request.AssetID), TargetPort: intPtr(request.TargetPort),
				Result: stringPtr("failed"), Reason: stringPtr(reason),
			}); err != nil {
				return err
			}
			_, err := s.outbox.CreateIfNoActive(ctx, q, domain.OutboxEvent{
				ID: id.New(), AggregateType: "session", AggregateID: current.ID,
				EventType: outboxSessionRevoke,
				Payload:   map[string]any{"session_id": current.ID, "reason": "admin_force_close", "operator_id": adminID, "operator_reason": reason},
				Status:    "pending",
			})
			return err
		case domain.SessionRunning, domain.SessionRevokeFailed, domain.SessionManualIntervention:
			var beginErr error
			transitioned, beginErr = s.sessions.BeginRevoke(ctx, q, current.ID)
			if beginErr != nil {
				return beginErr
			}
			queueRevoke = true
		case domain.SessionRevoking:
			// Keep repeated force-close calls idempotent, while repairing a missing
			// command if this row was left in revoking by an older process.
			transitioned = current
			_, err := s.outbox.CreateIfNoActive(ctx, q, domain.OutboxEvent{
				ID: id.New(), AggregateType: "session", AggregateID: current.ID,
				EventType: outboxSessionRevoke,
				Payload:   map[string]any{"session_id": current.ID, "reason": "admin_force_close", "operator_id": adminID, "operator_reason": reason},
				Status:    "pending",
			})
			return err
		case domain.SessionClosed, domain.SessionExpired, domain.SessionFailed:
			transitioned = current
			return nil
		default:
			return fmt.Errorf("force-close session is in unsupported state %q: %w", current.Status, ErrStateConflict)
		}
		if !queueRevoke {
			return nil
		}
		if err := s.sessionEvents.Append(ctx, q, domain.SessionEvent{
			ID: id.New(), SessionID: current.ID, EventType: "session.force_close_requested",
			ActorType: "admin", ActorID: stringPtr(adminID), Metadata: map[string]any{"reason": reason},
		}); err != nil {
			return err
		}
		if err := s.appendAudit(ctx, q, domain.AuditEvent{
			EventType: "session.force_close_requested", ActorType: "admin", ActorID: stringPtr(adminID),
			SubjectUserID: stringPtr(request.ApplicantID), RequestID: stringPtr(request.ID),
			SessionID: stringPtr(current.ID), AssetID: stringPtr(request.AssetID), TargetPort: intPtr(request.TargetPort),
			Result: stringPtr("queued"), Reason: stringPtr(reason),
		}); err != nil {
			return err
		}
		_, outboxErr := s.outbox.CreateIfNoActive(ctx, q, domain.OutboxEvent{
			ID: id.New(), AggregateType: "session", AggregateID: current.ID,
			EventType: outboxSessionRevoke,
			Payload:   map[string]any{"session_id": current.ID, "reason": "admin_force_close", "operator_id": adminID, "operator_reason": reason},
			Status:    "pending",
		})
		return outboxErr
	})
	if err != nil {
		if refreshed, getErr := s.sessions.GetByID(ctx, s.db, session.ID); getErr == nil && isTerminalSession(refreshed.Status) && refreshed.Status != domain.SessionManualIntervention {
			return refreshed, nil
		}
		return domain.Session{}, fmt.Errorf("queue force-close session: %w", err)
	}
	s.discardSessionToken(ctx, session.ID)
	return transitioned, nil
}

func (s *AccessService) RevokeSession(ctx context.Context, sessionID, reason string) (domain.Session, error) {
	if err := validateUUID(sessionID, "session ID"); err != nil {
		return domain.Session{}, err
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "requested"
	}
	if len(reason) > 128 {
		reason = reason[:128]
	}
	session, err := s.sessions.GetByID(ctx, s.db, sessionID)
	if err != nil {
		return domain.Session{}, fmt.Errorf("load revoke session: %w", err)
	}
	request, err := s.requests.GetByID(ctx, s.db, session.RequestID)
	if err != nil {
		return domain.Session{}, fmt.Errorf("load revoke request: %w", err)
	}
	if isTerminalSession(session.Status) && session.Status != domain.SessionManualIntervention {
		s.discardSessionToken(ctx, sessionID)
		return session, nil
	}

	// Resolve the state under a row lock.  This also makes a direct call to
	// RevokeSession safe for a provisioning row: an unclaimed row can be
	// failed locally, while a claimed row is converted to a retryable revoke
	// command instead of being silently ignored.
	var transitioned domain.Session
	err = InTx(ctx, s.db, func(q repository.DBTX) error {
		current, lockErr := s.sessions.GetByIDForUpdate(ctx, q, sessionID)
		if lockErr != nil {
			return lockErr
		}
		switch current.Status {
		case domain.SessionProvisioning:
			if current.Version == 0 {
				if failErr := s.sessions.MarkProvisionFailed(ctx, q, current.ID, current.Version, "revoked before provisioning"); failErr != nil {
					return failErr
				}
				transitioned, lockErr = s.sessions.GetByID(ctx, q, current.ID)
				if lockErr != nil {
					return lockErr
				}
				if eventErr := s.sessionEvents.Append(ctx, q, domain.SessionEvent{
					ID: id.New(), SessionID: current.ID, EventType: "session.cancelled_before_start",
					ActorType: "system", Metadata: map[string]any{"reason": reason},
				}); eventErr != nil {
					return eventErr
				}
				return s.appendAudit(ctx, q, domain.AuditEvent{
					EventType: "session.revoke_requested", ActorType: "system",
					SubjectUserID: stringPtr(request.ApplicantID), RequestID: stringPtr(request.ID),
					SessionID: stringPtr(current.ID), AssetID: stringPtr(request.AssetID),
					TargetPort: intPtr(request.TargetPort), Result: stringPtr("no_remote_session"), Reason: stringPtr(reason),
				})
			}
			const revokeReason = "revoke requested during provisioning"
			if failErr := s.sessions.MarkProvisionRevokeFailed(ctx, q, current.ID, current.Version, revokeReason); failErr != nil {
				return failErr
			}
			transitioned, lockErr = s.sessions.GetByID(ctx, q, current.ID)
			if lockErr != nil {
				return lockErr
			}
			if eventErr := s.sessionEvents.Append(ctx, q, domain.SessionEvent{
				ID: id.New(), SessionID: current.ID, EventType: "session.revoke_failed",
				ActorType: "system", Metadata: map[string]any{"reason": revokeReason},
			}); eventErr != nil {
				return eventErr
			}
			if auditErr := s.appendAudit(ctx, q, domain.AuditEvent{
				EventType: "session.revoke_failed", ActorType: "system",
				SubjectUserID: stringPtr(request.ApplicantID), RequestID: stringPtr(request.ID),
				SessionID: stringPtr(current.ID), AssetID: stringPtr(request.AssetID),
				TargetPort: intPtr(request.TargetPort), Result: stringPtr("failed"), Reason: stringPtr(revokeReason),
			}); auditErr != nil {
				return auditErr
			}
			_, outboxErr := s.outbox.CreateIfNoActive(ctx, q, domain.OutboxEvent{
				ID: id.New(), AggregateType: "session", AggregateID: current.ID,
				EventType: outboxSessionRevoke,
				Payload:   map[string]any{"session_id": current.ID, "reason": reason}, Status: "pending",
			})
			return outboxErr

		case domain.SessionRunning, domain.SessionRevokeFailed, domain.SessionManualIntervention:
			var beginErr error
			transitioned, beginErr = s.sessions.BeginRevoke(ctx, q, current.ID)
			if beginErr != nil {
				return beginErr
			}
			created, outboxErr := s.outbox.CreateIfNoActive(ctx, q, domain.OutboxEvent{
				ID: id.New(), AggregateType: "session", AggregateID: current.ID,
				EventType: outboxSessionRevoke,
				Payload:   map[string]any{"session_id": current.ID, "reason": reason}, Status: "pending",
			})
			if outboxErr != nil {
				return outboxErr
			}
			if created {
				if eventErr := s.sessionEvents.Append(ctx, q, domain.SessionEvent{
					ID: id.New(), SessionID: current.ID, EventType: "session.revoke_requested",
					ActorType: "system", Metadata: map[string]any{"reason": reason},
				}); eventErr != nil {
					return eventErr
				}
				if auditErr := s.appendAudit(ctx, q, domain.AuditEvent{
					EventType: "session.revoke_requested", ActorType: "system",
					SubjectUserID: stringPtr(request.ApplicantID), RequestID: stringPtr(request.ID),
					SessionID: stringPtr(current.ID), AssetID: stringPtr(request.AssetID),
					TargetPort: intPtr(request.TargetPort), Result: stringPtr("queued"), Reason: stringPtr(reason),
				}); auditErr != nil {
					return auditErr
				}
			}
			return nil
		case domain.SessionRevoking:
			transitioned = current
			_, outboxErr := s.outbox.CreateIfNoActive(ctx, q, domain.OutboxEvent{
				ID: id.New(), AggregateType: "session", AggregateID: current.ID,
				EventType: outboxSessionRevoke,
				Payload:   map[string]any{"session_id": current.ID, "reason": reason}, Status: "pending",
			})
			return outboxErr
		case domain.SessionClosed, domain.SessionExpired, domain.SessionFailed:
			transitioned = current
			return nil
		default:
			return fmt.Errorf("revoke session is in unsupported state %q: %w", current.Status, ErrStateConflict)
		}
	})
	if err != nil {
		if refreshed, getErr := s.sessions.GetByID(ctx, s.db, sessionID); getErr == nil && isTerminalSession(refreshed.Status) && refreshed.Status != domain.SessionManualIntervention {
			s.discardSessionToken(ctx, sessionID)
			return refreshed, nil
		}
		return domain.Session{}, fmt.Errorf("prepare revoke session: %w", err)
	}
	if transitioned.Status != domain.SessionRevoking {
		s.discardSessionToken(ctx, sessionID)
		return transitioned, nil
	}
	session = transitioned
	// RevokeSession can be called directly by a worker, so enforce the same
	// one-time credential invalidation that the user-facing close path performs.
	s.discardSessionToken(ctx, sessionID)
	gatewayRecord, err := s.gateways.GetByID(ctx, s.db, session.GatewayID)
	if err != nil {
		return s.persistRevokeFailure(ctx, session, request, reason, fmt.Errorf("load revoke gateway: %w", err))
	}
	response, gatewayErr := s.gateway.CloseSession(ctx, gatewayRecord.ManagementEndpoint, sessionID, "revoke-"+sessionID)
	if gatewayErr == nil && !validGatewayCloseResponse(response, sessionID) {
		gatewayErr = fmt.Errorf("gateway returned invalid close response: %w", ErrStateConflict)
	}
	if gatewayErr != nil {
		s.logger.Error().Err(gatewayErr).Str("session_id", sessionID).Str("gateway_id", gatewayRecord.ID).Bool("alert", true).Msg("close gateway session failed")
		return s.persistRevokeFailure(ctx, session, request, reason, gatewayErr)
	}
	terminalStatus := domain.SessionClosed
	if response.Status == "expired" || reason == "expired" || reason == "ttl_expired" {
		terminalStatus = domain.SessionExpired
	}
	var closed domain.Session
	err = InTx(ctx, s.db, func(q repository.DBTX) error {
		current, lockErr := s.sessions.GetByIDForUpdate(ctx, q, sessionID)
		if lockErr != nil {
			return lockErr
		}
		if current.Status != domain.SessionRevoking {
			if isTerminalSession(current.Status) && current.Status != domain.SessionManualIntervention {
				closed = current
				return nil
			}
			return fmt.Errorf("persist closed session from state %q: %w", current.Status, ErrStateConflict)
		}
		if updateErr := s.sessions.MarkClosed(ctx, q, sessionID, terminalStatus); updateErr != nil {
			return updateErr
		}
		var getErr error
		closed, getErr = s.sessions.GetByID(ctx, q, sessionID)
		if getErr != nil {
			return getErr
		}
		if eventErr := s.sessionEvents.Append(ctx, q, domain.SessionEvent{
			ID:        id.New(),
			SessionID: sessionID,
			EventType: "session.closed",
			ActorType: "system",
			Metadata:  map[string]any{"reason": reason},
		}); eventErr != nil {
			return eventErr
		}
		if auditErr := s.appendAudit(ctx, q, domain.AuditEvent{
			EventType:     "session.closed",
			ActorType:     "system",
			SubjectUserID: stringPtr(request.ApplicantID),
			RequestID:     stringPtr(request.ID),
			SessionID:     stringPtr(sessionID),
			AssetID:       stringPtr(request.AssetID),
			TargetPort:    intPtr(request.TargetPort),
			Result:        stringPtr(string(terminalStatus)),
			Reason:        stringPtr(reason),
		}); auditErr != nil {
			return auditErr
		}
		return s.appendOutbox(ctx, q, "session", sessionID, outboxNotifySessionClosed, map[string]any{"session_id": sessionID})
	})
	if err != nil {
		if refreshed, getErr := s.sessions.GetByID(ctx, s.db, sessionID); getErr == nil && isTerminalSession(refreshed.Status) {
			s.discardSessionToken(ctx, sessionID)
			return refreshed, nil
		}
		// The gateway close already succeeded, but a local audit/state write may
		// have rolled back.  Convert the row back to a retryable revoke state and
		// persist a durable command so a direct call cannot leave it stuck in
		// `revoking` forever.
		fallback, fallbackErr := s.persistRevokeFailure(ctx, session, request, reason, fmt.Errorf("persist closed session: %w", err))
		if fallbackErr == nil && fallback.ID != "" {
			return fallback, fmt.Errorf("persist closed session: %w", err)
		}
		return domain.Session{}, errors.Join(fmt.Errorf("persist closed session: %w", err), fallbackErr)
	}
	s.discardSessionToken(ctx, sessionID)
	return closed, nil
}

func (s *AccessService) ReapExpired(ctx context.Context, limit int) (int, error) {
	now := s.clock()
	if err := (repository.IdentitySecurityRepository{}).DeleteExpiredChallenges(ctx, s.db); err != nil {
		return 0, err
	}
	if err := (&repository.LoginAttemptRepository{}).DeleteExpired(ctx, s.db); err != nil {
		return 0, err
	}
	if err := (&repository.TransportRepository{}).DeleteExpired(ctx, s.db); err != nil {
		return 0, err
	}
	if _, err := s.tokenDeliveries.DeleteExpired(ctx, s.db, now, 5000); err != nil {
		return 0, fmt.Errorf("purge expired session token deliveries: %w", err)
	}
	if _, err := s.oauthStates.DeleteExpired(ctx, s.db, now, 5000); err != nil {
		return 0, fmt.Errorf("purge expired OAuth states: %w", err)
	}
	values, err := s.sessions.ListExpired(ctx, s.db, limit)
	if err != nil {
		return 0, fmt.Errorf("list expired sessions: %w", err)
	}
	queued := 0
	var queueErrors []error
	for _, session := range values {
		request, requestErr := s.requests.GetByID(ctx, s.db, session.RequestID)
		if requestErr != nil {
			queueErrors = append(queueErrors, fmt.Errorf("load expired session request %s: %w", session.ID, requestErr))
			continue
		}
		transitioned := false
		transitionErr := InTx(ctx, s.db, func(q repository.DBTX) error {
			current, getErr := s.sessions.GetByIDForUpdate(ctx, q, session.ID)
			if getErr != nil {
				return getErr
			}
			if current.Status != domain.SessionRunning || current.ExpiresAt == nil || current.ExpiresAt.After(s.clock()) {
				return nil
			}
			if _, beginErr := s.sessions.BeginRevoke(ctx, q, current.ID); beginErr != nil {
				return beginErr
			}
			transitioned = true
			if auditErr := s.appendAudit(ctx, q, domain.AuditEvent{
				EventType: "session.revoke_requested", ActorType: "system",
				SubjectUserID: stringPtr(request.ApplicantID), RequestID: stringPtr(request.ID),
				SessionID: stringPtr(current.ID), AssetID: stringPtr(request.AssetID),
				TargetPort: intPtr(request.TargetPort), Result: stringPtr("queued"), Reason: stringPtr("expired"),
			}); auditErr != nil {
				return auditErr
			}
			_, outboxErr := s.outbox.CreateIfNoActive(ctx, q, domain.OutboxEvent{
				ID: id.New(), AggregateType: "session", AggregateID: current.ID,
				EventType: outboxSessionRevoke,
				Payload:   map[string]any{"session_id": current.ID, "reason": "expired"}, Status: "pending",
			})
			return outboxErr
		})
		if transitionErr != nil {
			queueErrors = append(queueErrors, fmt.Errorf("queue expiry revoke %s: %w", session.ID, transitionErr))
			s.logger.Error().Err(transitionErr).Str("session_id", session.ID).Msg("enqueue expiry revoke failed")
			continue
		}
		if transitioned {
			s.discardSessionToken(ctx, session.ID)
			queued++
		}
	}
	return queued, errors.Join(queueErrors...)
}

// ReapApprovalExpired closes requests that have remained pending longer than
// the configured approval window.  The status update, audit event, and user
// notification are committed together so a restart cannot lose the outcome.
func (s *AccessService) ReapApprovalExpired(ctx context.Context, limit int) (int, error) {
	cutoff := s.clock().Add(-s.approvalTimeout)
	values, err := s.requests.ListApprovalExpired(ctx, s.db, cutoff, limit)
	if err != nil {
		return 0, fmt.Errorf("list expired approval requests: %w", err)
	}
	updated := 0
	var updateErrors []error
	for _, request := range values {
		transitioned := false
		err := InTx(ctx, s.db, func(q repository.DBTX) error {
			if _, transitionErr := s.requests.TransitionStatus(ctx, q, request.ID, domain.AccessRequestPendingApproval, domain.AccessRequestApprovalExpired); transitionErr != nil {
				if errors.Is(transitionErr, repository.ErrNotFound) {
					return nil
				}
				return transitionErr
			}
			transitioned = true
			if err := s.appendAudit(ctx, q, domain.AuditEvent{
				EventType: "access_request.approval_expired", ActorType: "system",
				SubjectUserID: stringPtr(request.ApplicantID), RequestID: stringPtr(request.ID),
				AssetID: stringPtr(request.AssetID), TargetPort: intPtr(request.TargetPort),
				Result: stringPtr("expired"), Reason: stringPtr("approval_timeout"),
			}); err != nil {
				return err
			}
			return s.appendOutbox(ctx, q, "access_request", request.ID, outboxNotifyRequestResult, map[string]any{"request_id": request.ID})
		})
		if err != nil {
			updateErrors = append(updateErrors, fmt.Errorf("expire approval request %s: %w", request.ID, err))
			continue
		}
		if transitioned {
			updated++
		}
	}
	return updated, errors.Join(updateErrors...)
}

// ReapProvisioning recovers provisioning commands that were committed just
// before a worker or process restart. Recovery is represented by the same
// durable outbox command used by the normal approval path; the repository
// atomically suppresses a duplicate while an earlier command is pending or
// leased for processing.
func (s *AccessService) ReapProvisioning(ctx context.Context, limit int) (int, error) {
	values, err := s.sessions.ListProvisioning(ctx, s.db, limit)
	if err != nil {
		return 0, fmt.Errorf("list provisioning sessions: %w", err)
	}
	queued := 0
	var queueErrors []error
	for _, session := range values {
		created := false
		err := InTx(ctx, s.db, func(q repository.DBTX) error {
			var createErr error
			created, createErr = s.outbox.CreateIfNoActive(ctx, q, domain.OutboxEvent{
				ID:            id.New(),
				AggregateType: "session",
				AggregateID:   session.ID,
				EventType:     outboxSessionProvision,
				Payload:       map[string]any{"session_id": session.ID, "reason": "provisioning_recovery"},
				Status:        "pending",
			})
			return createErr
		})
		if err != nil {
			queueErrors = append(queueErrors, fmt.Errorf("queue provisioning recovery %s: %w", session.ID, err))
			s.logger.Error().Err(err).Str("session_id", session.ID).Msg("queue provisioning recovery failed")
			continue
		}
		if created {
			queued++
		}
	}
	return queued, errors.Join(queueErrors...)
}

func (s *AccessService) ListAuditEvents(ctx context.Context, userID string, filter domain.AuditFilter) ([]domain.AuditEvent, error) {
	if err := s.Authorize(ctx, userID, authz.PermissionAuditRead); err != nil {
		return nil, err
	}
	if err := validateAuditFilter(filter); err != nil {
		return nil, err
	}
	if !domain.ValidAuditCategory(filter.Category) || !domain.ValidAuditAction(filter.Action) {
		return nil, fmt.Errorf("invalid audit classification: %w", ErrValidation)
	}
	filter.UserMutationsOnly = true
	filter.EventTypes = domain.UserMutationEventTypes(filter.Category, filter.Action)
	values, err := s.audits.List(ctx, s.db, filter)
	if err != nil {
		return nil, fmt.Errorf("list audit events: %w", err)
	}
	return values, nil
}

func (s *AccessService) ListOperationAuditEvents(ctx context.Context, userID string, filter domain.OperationAuditFilter) ([]domain.OperationAuditEvent, error) {
	filter, err := s.operationAuditReadFilter(ctx, userID, filter)
	if err != nil {
		return nil, err
	}
	values, err := s.accessEvidence.ListOperationEvents(ctx, s.db, filter)
	if err != nil {
		return nil, fmt.Errorf("list operation audit events: %w", err)
	}
	return values, nil
}

func (s *AccessService) RecordOperationAuditBatch(ctx context.Context, inputs []OperationAuditInput) (int, error) {
	if len(inputs) < 1 || len(inputs) > 500 {
		return 0, fmt.Errorf("operation audit batch must contain 1 to 500 events: %w", ErrValidation)
	}
	validated := make([]OperationAuditInput, len(inputs))
	for index, input := range inputs {
		value, err := validateOperationAuditInput(input, s.clock())
		if err != nil {
			return 0, fmt.Errorf("operation audit event %d: %w", index, err)
		}
		validated[index] = value
	}
	inserted := 0
	err := InTx(ctx, s.db, func(q repository.DBTX) error {
		for _, input := range validated {
			connectionID, sessionID, intendedAccount, correlationErr := s.accessEvidence.CorrelateOperation(
				ctx, q, input.AssetID, input.TargetPort, input.BackendSourceIP, input.BackendSourcePort, input.OccurredAt,
			)
			correlationStatus := "matched"
			var connectionIDPtr, sessionIDPtr *string
			metadata := input.Metadata
			metadata["source"] = "asset_collector"
			switch {
			case correlationErr == nil:
				connectionIDPtr = stringPtr(connectionID)
				sessionIDPtr = stringPtr(sessionID)
				if intendedAccount != input.ActualAccount {
					correlationStatus = "identity_mismatch"
				}
			case errors.Is(correlationErr, repository.ErrNotFound):
				correlationStatus = "unmatched"
				metadata["correlation_reason"] = "connection_not_found"
			case errors.Is(correlationErr, repository.ErrConflict):
				correlationStatus = "unmatched"
				metadata["correlation_reason"] = "ambiguous_connection"
			default:
				return correlationErr
			}
			created, appendErr := s.accessEvidence.AppendOperationEvent(ctx, q, domain.OperationAuditEvent{
				EventID: input.EventID, ConnectionID: connectionIDPtr, SessionID: sessionIDPtr,
				Protocol: input.Protocol, AssetID: input.AssetID, TargetPort: input.TargetPort,
				ActualAccount: input.ActualAccount, OperationType: input.OperationType,
				StatementFingerprint: input.StatementFingerprint, NormalizedOperation: input.NormalizedOperation,
				ObjectName: input.ObjectName, Result: input.Result, DurationMS: input.DurationMS,
				BackendSourceIP: input.BackendSourceIP, BackendSourcePort: input.BackendSourcePort,
				SourceRecordID: input.SourceRecordID, CorrelationStatus: correlationStatus,
				OccurredAt: input.OccurredAt, Metadata: metadata,
			})
			if appendErr != nil {
				return appendErr
			}
			if created {
				inserted++
			}
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("record operation audit batch: %w", err)
	}
	return inserted, nil
}

func (s *AccessService) ListSessionEvents(ctx context.Context, userID, sessionID string, limit, offset int) ([]domain.SessionEvent, error) {
	if err := s.requireActiveUser(ctx, userID); err != nil {
		return nil, err
	}
	if err := validateUUID(sessionID, "session ID"); err != nil {
		return nil, err
	}
	session, err := s.sessions.GetByID(ctx, s.db, sessionID)
	if err != nil {
		return nil, fmt.Errorf("load session events session: %w", err)
	}
	request, err := s.requests.GetByID(ctx, s.db, session.RequestID)
	if err != nil {
		return nil, fmt.Errorf("load session events request: %w", err)
	}
	if request.ApplicantID != userID && !s.isAdminUser(ctx, userID) {
		return nil, fmt.Errorf("list session events: %w", ErrForbidden)
	}
	values, err := s.sessionEvents.ListBySession(ctx, s.db, sessionID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list session events: %w", err)
	}
	return values, nil
}

func (s *AccessService) RecordGatewayEvent(ctx context.Context, input GatewayEventInput) error {
	input.EventID = strings.TrimSpace(input.EventID)
	input.GatewayID = strings.TrimSpace(input.GatewayID)
	input.ConnectionID = strings.TrimSpace(input.ConnectionID)
	input.SessionID = strings.TrimSpace(input.SessionID)
	input.EventType = strings.TrimSpace(input.EventType)
	if input.EventID == "" || input.GatewayID == "" || input.ConnectionID == "" || input.SessionID == "" || input.EventType == "" {
		return fmt.Errorf("gateway event fields are required: %w", ErrValidation)
	}
	for _, value := range []struct {
		value string
		field string
	}{{input.EventID, "event ID"}, {input.GatewayID, "gateway ID"}, {input.ConnectionID, "connection ID"}, {input.SessionID, "session ID"}} {
		if err := validateUUID(value.value, value.field); err != nil {
			return err
		}
	}
	allowed := map[string]struct{}{
		"connect_attempt": {}, "source_rejected": {}, "capacity_rejected": {}, "auth_rejected": {},
		"backend_connected": {}, "backend_failed": {}, "disconnected": {},
	}
	if _, ok := allowed[input.EventType]; !ok {
		return fmt.Errorf("unsupported gateway event type: %w", ErrValidation)
	}
	if input.OccurredAt.IsZero() || input.OccurredAt.After(s.clock().Add(5*time.Minute)) {
		return fmt.Errorf("gateway event time is invalid: %w", ErrValidation)
	}
	var err error
	if input.SourceIP, err = normalizeOptionalIP(input.SourceIP); err != nil {
		return fmt.Errorf("invalid gateway source IP: %w", ErrValidation)
	}
	if input.BackendSourceIP, err = normalizeOptionalIP(input.BackendSourceIP); err != nil {
		return fmt.Errorf("invalid gateway backend source IP: %w", ErrValidation)
	}
	if (input.BackendSourceIP == nil) != (input.BackendSourcePort == nil) {
		return fmt.Errorf("gateway backend source tuple must be complete: %w", ErrValidation)
	}
	if input.BackendSourcePort != nil && (*input.BackendSourcePort < 1 || *input.BackendSourcePort > 65535) {
		return fmt.Errorf("gateway backend source port is invalid: %w", ErrValidation)
	}
	if input.EventType == "backend_connected" && input.BackendSourceIP == nil {
		return fmt.Errorf("backend-connected event requires a backend source tuple: %w", ErrValidation)
	}
	for _, counter := range []*int64{input.BytesUp, input.BytesDown, input.DurationMS} {
		if counter != nil && *counter < 0 {
			return fmt.Errorf("gateway event counter is invalid: %w", ErrValidation)
		}
	}
	if input.EventType != "disconnected" && (input.BytesUp != nil || input.BytesDown != nil || input.DurationMS != nil) {
		return fmt.Errorf("only disconnected events may contain byte and duration counters: %w", ErrValidation)
	}
	if input.Result != nil {
		value := strings.TrimSpace(*input.Result)
		if value == "" {
			input.Result = nil
		} else if len(value) > 32 {
			return fmt.Errorf("gateway event result is too long: %w", ErrValidation)
		} else {
			input.Result = stringPtr(value)
		}
	}
	if input.Reason != nil {
		value := strings.TrimSpace(*input.Reason)
		if value == "" {
			input.Reason = nil
		} else if len(value) > 256 || strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return fmt.Errorf("gateway event reason is invalid: %w", ErrValidation)
		} else {
			input.Reason = stringPtr(value)
		}
	}
	session, err := s.sessions.GetByID(ctx, s.db, input.SessionID)
	if err != nil {
		return fmt.Errorf("load gateway event session: %w", err)
	}
	if session.GatewayID != input.GatewayID {
		return fmt.Errorf("gateway does not own session: %w", ErrForbidden)
	}
	request, err := s.requests.GetByID(ctx, s.db, session.RequestID)
	if err != nil {
		return fmt.Errorf("load gateway event request: %w", err)
	}
	asset, err := s.assets.GetIncludingDeleted(ctx, s.db, request.AssetID)
	if err != nil {
		return fmt.Errorf("load gateway event asset: %w", err)
	}
	err = InTx(ctx, s.db, func(q repository.DBTX) error {
		current, getErr := s.sessions.GetByID(ctx, q, input.SessionID)
		if getErr != nil {
			return getErr
		}
		if current.GatewayID != input.GatewayID {
			return fmt.Errorf("gateway does not own session: %w", ErrForbidden)
		}
		inserted, appendErr := s.accessEvidence.AppendConnectionEvent(ctx, q, domain.GatewayConnectionEvent{
			EventID: input.EventID, ConnectionID: input.ConnectionID, SessionID: input.SessionID,
			EventType: input.EventType, SourceIP: input.SourceIP,
			BackendSourceIP: input.BackendSourceIP, BackendSourcePort: input.BackendSourcePort,
			BytesUp: input.BytesUp, BytesDown: input.BytesDown, DurationMS: input.DurationMS,
			Result: input.Result, Reason: input.Reason, OccurredAt: input.OccurredAt,
		})
		if appendErr != nil {
			return appendErr
		}
		if !inserted {
			return nil
		}
		metadata := map[string]any{"connection_id": input.ConnectionID, "occurred_at": input.OccurredAt.UTC().Format(time.RFC3339Nano)}
		if input.BackendSourceIP != nil {
			metadata["backend_source_ip"] = *input.BackendSourceIP
			metadata["backend_source_port"] = *input.BackendSourcePort
		}
		if input.BytesUp != nil {
			metadata["bytes_up"] = *input.BytesUp
		}
		if input.BytesDown != nil {
			metadata["bytes_down"] = *input.BytesDown
		}
		if input.DurationMS != nil {
			metadata["duration_ms"] = *input.DurationMS
		}
		if eventErr := s.sessionEvents.Append(ctx, q, domain.SessionEvent{
			ID:        input.EventID,
			SessionID: input.SessionID,
			EventType: "connection." + input.EventType,
			ActorType: "gateway",
			ActorID:   stringPtr(input.GatewayID),
			Metadata:  metadata,
		}); eventErr != nil {
			return eventErr
		}
		return s.appendAudit(ctx, q, domain.AuditEvent{
			EventType:     "connection." + input.EventType,
			ActorType:     "gateway",
			ActorID:       stringPtr(input.GatewayID),
			SubjectUserID: stringPtr(request.ApplicantID),
			RequestID:     stringPtr(request.ID),
			SessionID:     stringPtr(input.SessionID),
			RegionID:      stringPtr(asset.RegionID),
			AssetID:       stringPtr(request.AssetID),
			TargetPort:    intPtr(request.TargetPort),
			SourceIP:      input.SourceIP,
			Result:        input.Result,
			Reason:        input.Reason,
			Metadata:      metadata,
		})
	})
	if err != nil {
		return fmt.Errorf("record gateway connection event: %w", err)
	}
	return nil
}

func normalizeOptionalIP(value *string) (*string, error) {
	if value == nil || strings.TrimSpace(*value) == "" {
		return nil, nil
	}
	parsed := net.ParseIP(strings.TrimSpace(*value))
	if parsed == nil || parsed.IsUnspecified() {
		return nil, ErrValidation
	}
	normalized := parsed.String()
	return &normalized, nil
}

const maxEventMetadataBytes = 64 * 1024

// sanitizeEventMetadata keeps gateway supplied diagnostics useful without
// allowing a compromised agent to persist credentials or unbounded JSON in
// the audit store. The gateway is still authenticated separately; this is a
// defense-in-depth boundary for data it sends after authentication.
func sanitizeEventMetadata(input map[string]any) (map[string]any, error) {
	if input == nil {
		return map[string]any{}, nil
	}
	value, err := sanitizeMetadataValue(input, 0)
	if err != nil {
		return nil, err
	}
	metadata, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("metadata must be an object")
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("encode metadata: %w", err)
	}
	if len(encoded) > maxEventMetadataBytes {
		return nil, fmt.Errorf("metadata exceeds %d bytes: %w", maxEventMetadataBytes, ErrValidation)
	}
	return metadata, nil
}

func sanitizeMetadataValue(value any, depth int) (any, error) {
	if depth > 5 {
		return nil, fmt.Errorf("metadata nesting is too deep: %w", ErrValidation)
	}
	switch typed := value.(type) {
	case map[string]any:
		if len(typed) > 100 {
			return nil, fmt.Errorf("metadata has too many keys: %w", ErrValidation)
		}
		result := make(map[string]any, len(typed))
		for key, child := range typed {
			if isSensitiveMetadataKey(key) {
				result[key] = "[REDACTED]"
				continue
			}
			cleaned, err := sanitizeMetadataValue(child, depth+1)
			if err != nil {
				return nil, err
			}
			result[key] = cleaned
		}
		return result, nil
	case []any:
		if len(typed) > 100 {
			return nil, fmt.Errorf("metadata array is too large: %w", ErrValidation)
		}
		result := make([]any, len(typed))
		for index, child := range typed {
			cleaned, err := sanitizeMetadataValue(child, depth+1)
			if err != nil {
				return nil, err
			}
			result[index] = cleaned
		}
		return result, nil
	case string:
		if len([]rune(typed)) > 2048 {
			return nil, fmt.Errorf("metadata string is too long: %w", ErrValidation)
		}
		return typed, nil
	case nil, bool, float64, float32, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return value, nil
	default:
		return nil, fmt.Errorf("unsupported metadata value type %T: %w", value, ErrValidation)
	}
}

func isSensitiveMetadataKey(key string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	for _, fragment := range []string{"token", "secret", "password", "credential", "private_key", "authorization"} {
		if strings.Contains(key, fragment) {
			return true
		}
	}
	return false
}

func (s *AccessService) IsAdmin(userID string) bool {
	return s.isAdmin(userID)
}

func (s *AccessService) CheckActiveUser(ctx context.Context, userID string) error {
	return s.requireActiveUser(ctx, userID)
}

func (s *AccessService) Authorize(ctx context.Context, userID string, permission authz.Permission) error {
	if !id.IsUUID(userID) || !authz.Known(permission) {
		return ErrForbidden
	}
	return s.readIAM(ctx, func(q repository.DBTX) error {
		return s.authorizeIn(ctx, q, userID, permission)
	})
}

func (s *AccessService) requireActiveUser(ctx context.Context, userID string) error {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return fmt.Errorf("user identity is required: %w", ErrForbidden)
	}
	if !id.IsUUID(userID) {
		return fmt.Errorf("user identity is invalid: %w", ErrForbidden)
	}
	user, err := s.users.GetByID(ctx, s.db, userID)
	if err != nil {
		return fmt.Errorf("load current user: %w", err)
	}
	if user.Status != domain.UserStatusActive {
		return fmt.Errorf("user is inactive: %w", ErrForbidden)
	}
	return nil
}

func validateUUID(value, field string) error {
	value = strings.TrimSpace(value)
	if !id.IsUUID(value) {
		return fmt.Errorf("%s is invalid: %w", field, ErrValidation)
	}
	return nil
}

const maxAuditPageSize = 200

func validateAuditFilter(filter domain.AuditFilter) error {
	for _, field := range []struct {
		value string
		name  string
	}{
		{filter.ActorID, "actor ID"},
		{filter.SubjectUserID, "subject user ID"},
		{filter.RequestID, "request ID"},
		{filter.SessionID, "session ID"},
		{filter.RegionID, "region ID"},
		{filter.AssetID, "asset ID"},
	} {
		if field.value != "" {
			if field.value != strings.TrimSpace(field.value) {
				return fmt.Errorf("audit %s contains surrounding whitespace: %w", field.name, ErrValidation)
			}
			if err := validateUUID(field.value, field.name); err != nil {
				return err
			}
		}
	}
	for _, field := range []struct {
		value string
		name  string
		max   int
	}{
		{filter.EventType, "event type", 64},
		{filter.SourceIP, "source IP", 128},
		{filter.Result, "result", 32},
	} {
		if len([]rune(field.value)) > field.max || strings.IndexFunc(field.value, unicode.IsControl) >= 0 {
			return fmt.Errorf("audit %s is invalid: %w", field.name, ErrValidation)
		}
	}
	if filter.SourceIP != "" {
		if filter.SourceIP != strings.TrimSpace(filter.SourceIP) || net.ParseIP(filter.SourceIP) == nil {
			return fmt.Errorf("audit source IP is invalid: %w", ErrValidation)
		}
	}
	if filter.Limit < 0 || filter.Limit > maxAuditPageSize {
		return fmt.Errorf("audit page size is invalid: %w", ErrValidation)
	}
	if filter.Offset < 0 {
		return fmt.Errorf("audit page offset is invalid: %w", ErrValidation)
	}
	if filter.From != nil && filter.To != nil && filter.From.After(*filter.To) {
		return fmt.Errorf("audit time range is invalid: %w", ErrValidation)
	}
	return nil
}

func validateOperationAuditFilter(filter domain.OperationAuditFilter) error {
	for _, field := range []struct {
		value string
		name  string
	}{{filter.SubjectUserID, "subject user ID"}, {filter.AssetID, "asset ID"}, {filter.SessionID, "session ID"}} {
		if field.value != "" {
			if field.value != strings.TrimSpace(field.value) {
				return fmt.Errorf("operation audit %s contains surrounding whitespace: %w", field.name, ErrValidation)
			}
			if err := validateUUID(field.value, field.name); err != nil {
				return err
			}
		}
	}
	if filter.Protocol != "" && !operationaudit.ValidProtocol(filter.Protocol) {
		return fmt.Errorf("operation audit protocol is invalid: %w", ErrValidation)
	}
	if filter.CorrelationStatus != "" && filter.CorrelationStatus != "matched" && filter.CorrelationStatus != "identity_mismatch" && filter.CorrelationStatus != "unmatched" {
		return fmt.Errorf("operation audit correlation status is invalid: %w", ErrValidation)
	}
	for _, value := range []struct {
		text string
		max  int
	}{{filter.ActualAccount, 128}, {filter.Result, 32}} {
		if len([]byte(value.text)) > value.max || strings.IndexFunc(value.text, unicode.IsControl) >= 0 {
			return fmt.Errorf("operation audit filter is invalid: %w", ErrValidation)
		}
	}
	if filter.Limit < 0 || filter.Limit > maxAuditPageSize || filter.Offset < 0 {
		return fmt.Errorf("operation audit pagination is invalid: %w", ErrValidation)
	}
	if filter.From != nil && filter.To != nil && filter.From.After(*filter.To) {
		return fmt.Errorf("operation audit time range is invalid: %w", ErrValidation)
	}
	return nil
}

func validateOperationAuditInput(input OperationAuditInput, now time.Time) (OperationAuditInput, error) {
	input.EventID = strings.TrimSpace(input.EventID)
	input.Protocol = strings.ToLower(strings.TrimSpace(input.Protocol))
	input.AssetID = strings.TrimSpace(input.AssetID)
	input.ActualAccount = strings.TrimSpace(input.ActualAccount)
	input.OperationType = strings.TrimSpace(input.OperationType)
	input.Result = strings.TrimSpace(input.Result)
	input.BackendSourceIP = strings.TrimSpace(input.BackendSourceIP)
	input.SourceRecordID = strings.TrimSpace(input.SourceRecordID)
	if err := validateUUID(input.EventID, "operation event ID"); err != nil {
		return OperationAuditInput{}, err
	}
	if err := validateUUID(input.AssetID, "operation asset ID"); err != nil {
		return OperationAuditInput{}, err
	}
	if !operationaudit.ValidProtocol(input.Protocol) {
		return OperationAuditInput{}, fmt.Errorf("operation protocol is invalid: %w", ErrValidation)
	}
	if input.TargetPort < 1 || input.TargetPort > 65535 || input.BackendSourcePort < 1 || input.BackendSourcePort > 65535 {
		return OperationAuditInput{}, fmt.Errorf("operation audit port is invalid: %w", ErrValidation)
	}
	parsedIP := net.ParseIP(input.BackendSourceIP)
	if parsedIP == nil || parsedIP.IsUnspecified() {
		return OperationAuditInput{}, fmt.Errorf("operation backend source IP is invalid: %w", ErrValidation)
	}
	input.BackendSourceIP = parsedIP.String()
	if input.ActualAccount == "" || len([]byte(input.ActualAccount)) > 128 || strings.IndexFunc(input.ActualAccount, unicode.IsControl) >= 0 {
		return OperationAuditInput{}, fmt.Errorf("operation account is invalid: %w", ErrValidation)
	}
	if !validAuditToken(input.OperationType, 64) || !validAuditToken(input.Result, 32) {
		return OperationAuditInput{}, fmt.Errorf("operation type or result is invalid: %w", ErrValidation)
	}
	if input.SourceRecordID == "" || len([]byte(input.SourceRecordID)) > 512 || strings.IndexFunc(input.SourceRecordID, unicode.IsControl) >= 0 {
		return OperationAuditInput{}, fmt.Errorf("operation source record ID is invalid: %w", ErrValidation)
	}
	if input.OccurredAt.IsZero() || input.OccurredAt.After(now.Add(5*time.Minute)) {
		return OperationAuditInput{}, fmt.Errorf("operation occurrence time is invalid: %w", ErrValidation)
	}
	if input.DurationMS != nil && *input.DurationMS < 0 {
		return OperationAuditInput{}, fmt.Errorf("operation duration is invalid: %w", ErrValidation)
	}
	var err error
	if input.StatementFingerprint, err = normalizeOptionalAuditText(input.StatementFingerprint, 128); err != nil {
		return OperationAuditInput{}, fmt.Errorf("operation fingerprint is invalid: %w", ErrValidation)
	}
	if input.NormalizedOperation, err = normalizeOptionalAuditText(input.NormalizedOperation, 4096); err != nil {
		return OperationAuditInput{}, fmt.Errorf("normalized operation is invalid: %w", ErrValidation)
	}
	if input.ObjectName, err = normalizeOptionalAuditText(input.ObjectName, 512); err != nil {
		return OperationAuditInput{}, fmt.Errorf("operation object name is invalid: %w", ErrValidation)
	}
	input.Metadata, err = sanitizeEventMetadata(input.Metadata)
	if err != nil {
		return OperationAuditInput{}, fmt.Errorf("operation metadata is invalid: %w", err)
	}
	return input, nil
}

func normalizeOptionalAuditText(value *string, maxBytes int) (*string, error) {
	if value == nil {
		return nil, nil
	}
	trimmed := strings.TrimSpace(*value)
	if trimmed == "" {
		return nil, nil
	}
	if len([]byte(trimmed)) > maxBytes || strings.IndexFunc(trimmed, unicode.IsControl) >= 0 {
		return nil, ErrValidation
	}
	return &trimmed, nil
}

func validAuditToken(value string, maxBytes int) bool {
	if value == "" || len(value) > maxBytes {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '_' || character == '-' || character == '.' || character == ':' {
			continue
		}
		return false
	}
	return true
}

func (s *AccessService) isAdmin(userID string) bool {
	s.adminMu.RLock()
	defer s.adminMu.RUnlock()
	_, ok := s.adminUserIDs[userID]
	return ok
}

func (s *AccessService) isAdminUser(ctx context.Context, userID string) bool {
	roles, err := s.effectiveRoles(ctx, userID)
	if err != nil {
		return false
	}
	for _, role := range roles {
		if role == authz.RoleAdmin {
			return true
		}
	}
	return false
}

func (s *AccessService) effectiveRoles(ctx context.Context, userID string) ([]authz.Role, error) {
	roles := []authz.Role{}
	err := s.readIAM(ctx, func(q repository.DBTX) error {
		user, err := s.users.GetByID(ctx, q, userID)
		if err != nil {
			return fmt.Errorf("load authorization subject: %w", err)
		}
		if user.Status != domain.UserStatusActive {
			return ErrForbidden
		}
		resolved, err := s.resolvedRoles(ctx, q, user)
		if err != nil {
			return fmt.Errorf("load user role assignments: %w", err)
		}
		for _, role := range resolved {
			roles = append(roles, authz.Role(role.Name))
		}
		return nil
	})
	return roles, err
}

func (s *AccessService) isConfiguredAdminReference(reference string) bool {
	if strings.TrimSpace(reference) == "" {
		return false
	}
	s.adminMu.RLock()
	defer s.adminMu.RUnlock()
	_, ok := s.adminUserIDs[reference]
	return ok
}

func (s *AccessService) appendAudit(ctx context.Context, q repository.DBTX, value domain.AuditEvent) error {
	// Login and read-only delivery/export do not create platform operation logs.
	if value.EventType == "user.login" || value.EventType == "gateway.catalog_exported" || value.EventType == "session.credential_downloaded" {
		return nil
	}
	if value.ID == "" {
		value.ID = id.New()
	}
	if value.CreatedAt.IsZero() {
		value.CreatedAt = s.clock()
	}
	metadata, err := sanitizeEventMetadata(value.Metadata)
	if err != nil {
		return fmt.Errorf("sanitize audit metadata: %w", err)
	}
	value.Metadata = metadata
	if err := s.audits.Append(ctx, q, value); err != nil {
		return fmt.Errorf("append audit event: %w", err)
	}
	return nil
}

func (s *AccessService) appendOutbox(ctx context.Context, q repository.DBTX, aggregateType, aggregateID, eventType string, payload map[string]any) error {
	return s.appendOutboxAt(ctx, q, aggregateType, aggregateID, eventType, payload, nil)
}

func (s *AccessService) appendOutboxAt(ctx context.Context, q repository.DBTX, aggregateType, aggregateID, eventType string, payload map[string]any, notBefore *time.Time) error {
	if err := s.appendInAppNotifications(ctx, q, eventType, aggregateID); err != nil {
		return err
	}
	return s.outbox.Create(ctx, q, domain.OutboxEvent{
		ID: id.New(), AggregateType: aggregateType, AggregateID: aggregateID,
		EventType: eventType, Payload: payload, Status: "pending", NextRetryAt: notBefore,
	})
}

// ProcessOutbox claims a short lease in a transaction, performs network or
// gateway work after that transaction has committed, and then acknowledges or
// reschedules each event. Delivery is at-least-once; handlers therefore rely
// on state conditions and stable session IDs for idempotency.
func (s *AccessService) ProcessOutbox(ctx context.Context, limit int) (int, error) {
	var events []domain.OutboxEvent
	if err := InTx(ctx, s.db, func(q repository.DBTX) error {
		var claimErr error
		events, claimErr = s.outbox.ClaimPending(ctx, q, limit, time.Minute)
		return claimErr
	}); err != nil {
		return 0, fmt.Errorf("claim outbox events: %w", err)
	}
	processed := 0
	var processingErrors []error
	for _, event := range events {
		dispatchErr := s.dispatchOutboxEvent(ctx, event)
		if dispatchErr == nil {
			if markErr := s.outbox.MarkProcessed(ctx, s.db, event.ID); markErr != nil {
				processingErrors = append(processingErrors, fmt.Errorf("acknowledge outbox event %s: %w", event.ID, markErr))
				continue
			}
			processed++
			continue
		}

		retriesExhausted := event.RetryCount >= 4
		terminal := errors.Is(dispatchErr, errUnsupportedOutboxEvent) || retriesExhausted
		nextRetryAt := s.clock().Add(outboxRetryDelay(event.RetryCount))
		var rescheduleErr error
		if retriesExhausted && event.EventType == outboxSessionRevoke {
			rescheduleErr = s.markRevokeManualIntervention(ctx, event, dispatchErr, nextRetryAt)
		} else {
			rescheduleErr = s.outbox.Reschedule(ctx, s.db, event.ID, nextRetryAt, terminal)
		}
		if rescheduleErr != nil {
			processingErrors = append(processingErrors, fmt.Errorf("reschedule outbox event %s: %w", event.ID, rescheduleErr))
		}
		logEvent := s.logger.Error().Err(dispatchErr).Str("outbox_event_id", event.ID).Str("event_type", event.EventType).Bool("terminal", terminal)
		if retriesExhausted && event.EventType == outboxSessionRevoke {
			logEvent = logEvent.Bool("alert", true).Str("severity", "critical").Str("session_id", outboxReference(event, "session_id"))
		}
		logEvent.Msg("outbox event delivery failed")
		processingErrors = append(processingErrors, fmt.Errorf("dispatch outbox event %s: %w", event.ID, dispatchErr))
	}
	return processed, errors.Join(processingErrors...)
}

func (s *AccessService) markRevokeManualIntervention(ctx context.Context, event domain.OutboxEvent, dispatchErr error, nextRetryAt time.Time) error {
	sessionID := outboxReference(event, "session_id")
	reason := "automatic revoke retries exhausted: " + dispatchErr.Error()
	return InTx(ctx, s.db, func(q repository.DBTX) error {
		session, err := s.sessions.GetByID(ctx, q, sessionID)
		if err != nil {
			return err
		}
		if isTerminalSession(session.Status) {
			return s.outbox.Reschedule(ctx, q, event.ID, nextRetryAt, true)
		}
		if session.Status != domain.SessionRevokeFailed && session.Status != domain.SessionRevoking {
			return fmt.Errorf("session %s is %s after revoke failure: %w", session.ID, session.Status, ErrStateConflict)
		}
		request, err := s.requests.GetByID(ctx, q, session.RequestID)
		if err != nil {
			return err
		}
		if err := s.sessions.MarkManualIntervention(ctx, q, session.ID, reason); err != nil {
			return err
		}
		if err := s.sessionEvents.Append(ctx, q, domain.SessionEvent{
			ID: id.New(), SessionID: session.ID, EventType: "session.manual_intervention",
			ActorType: "system", Metadata: map[string]any{"reason": reason},
		}); err != nil {
			return err
		}
		if err := s.appendAudit(ctx, q, domain.AuditEvent{
			EventType: "session.manual_intervention", ActorType: "system",
			SubjectUserID: stringPtr(request.ApplicantID), RequestID: stringPtr(request.ID),
			SessionID: stringPtr(session.ID), AssetID: stringPtr(request.AssetID),
			TargetPort: intPtr(request.TargetPort), Result: stringPtr("failed"), Reason: stringPtr(reason),
		}); err != nil {
			return err
		}
		return s.outbox.Reschedule(ctx, q, event.ID, nextRetryAt, true)
	})
}

func (s *AccessService) dispatchOutboxEvent(ctx context.Context, event domain.OutboxEvent) error {
	switch event.EventType {
	case outboxSessionProvision:
		_, err := s.ProvisionSession(ctx, outboxReference(event, "session_id"))
		return err
	case outboxSessionRevoke:
		_, err := s.RevokeSession(ctx, outboxReference(event, "session_id"), outboxString(event.Payload, "reason", "requested"))
		return err
	case outboxNotifyApproval:
		request, err := s.requests.GetByID(ctx, s.db, outboxReference(event, "request_id"))
		if err != nil {
			return fmt.Errorf("load approval notification request: %w", err)
		}
		if request.ApprovalMode == "admin_test" || request.Status != domain.AccessRequestPendingApproval {
			return nil
		}
		approvals, err := s.approvals.ListByRequest(ctx, s.db, request.ID)
		if err != nil {
			return fmt.Errorf("load notification approvals: %w", err)
		}
		level, complete := nextApprovalLevel(approvals)
		if complete {
			return nil
		}
		pending := make([]domain.Approval, 0, len(approvals))
		for _, approval := range approvals {
			if approval.ApprovalLevel == level && approval.Decision == nil {
				pending = append(pending, approval)
			}
		}
		return s.notifier.NotifyApproval(ctx, request, pending)
	case outboxNotifyRequestResult:
		request, err := s.requests.GetByID(ctx, s.db, outboxReference(event, "request_id"))
		if err != nil {
			return fmt.Errorf("load result notification request: %w", err)
		}
		if request.ApprovalMode == "admin_test" {
			return nil
		}
		return s.notifier.NotifyRequestResult(ctx, request)
	case outboxNotifySessionReady, outboxNotifySessionClosed:
		session, err := s.sessions.GetByID(ctx, s.db, outboxReference(event, "session_id"))
		if err != nil {
			return fmt.Errorf("load session notification: %w", err)
		}
		request, err := s.requests.GetByID(ctx, s.db, session.RequestID)
		if err != nil {
			return fmt.Errorf("load session notification request: %w", err)
		}
		if request.ApprovalMode == "admin_test" {
			return nil
		}
		if event.EventType == outboxNotifySessionReady {
			if session.Status != domain.SessionRunning {
				return nil
			}
			return s.notifier.NotifySessionReady(ctx, request, session)
		}
		return s.notifier.NotifySessionClosed(ctx, request, session)
	default:
		return fmt.Errorf("%w: %s", errUnsupportedOutboxEvent, event.EventType)
	}
}

func outboxReference(event domain.OutboxEvent, key string) string {
	if value := outboxString(event.Payload, key, ""); value != "" {
		return value
	}
	return event.AggregateID
}

func outboxString(payload map[string]any, key, fallback string) string {
	value, ok := payload[key].(string)
	if !ok || strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func outboxRetryDelay(retryCount int) time.Duration {
	delays := [...]time.Duration{10 * time.Second, 30 * time.Second, time.Minute, 5 * time.Minute}
	if retryCount < 0 {
		retryCount = 0
	}
	if retryCount >= len(delays) {
		return delays[len(delays)-1]
	}
	return delays[retryCount]
}

func (s *AccessService) enqueueUserRevocations(ctx context.Context, userID string) error {
	return s.enqueueRevocationBatches(ctx, func(ctx context.Context, limit int) ([]domain.Session, error) {
		return s.sessions.ListRevocationsToQueueByApplicant(ctx, s.db, userID, limit)
	}, "user_inactive")
}

func (s *AccessService) enqueueAssetRevocations(ctx context.Context, assetID, reason string) error {
	return s.enqueueRevocationBatches(ctx, func(ctx context.Context, limit int) ([]domain.Session, error) {
		return s.sessions.ListRevocationsToQueueByAsset(ctx, s.db, assetID, limit)
	}, reason)
}

func (s *AccessService) enqueueGatewayRevocations(ctx context.Context, gatewayID, reason string) error {
	return s.enqueueRevocationBatches(ctx, func(ctx context.Context, limit int) ([]domain.Session, error) {
		return s.sessions.ListRevocationsToQueueByGateway(ctx, s.db, gatewayID, limit)
	}, reason)
}

func (s *AccessService) enqueueRegionRevocations(ctx context.Context, regionID, reason string) error {
	return s.enqueueRevocationBatches(ctx, func(ctx context.Context, limit int) ([]domain.Session, error) {
		return s.sessions.ListRevocationsToQueueByRegion(ctx, s.db, regionID, limit)
	}, reason)
}

const revocationBatchSize = 100

func (s *AccessService) enqueueRevocationBatches(ctx context.Context, load func(context.Context, int) ([]domain.Session, error), reason string) error {
	for {
		sessions, err := load(ctx, revocationBatchSize)
		if err != nil {
			return fmt.Errorf("list sessions requiring revocation: %w", err)
		}
		if len(sessions) == 0 {
			return nil
		}
		if err := s.enqueueSessionRevocations(ctx, sessions, reason); err != nil {
			return err
		}
	}
}

func (s *AccessService) enqueueSessionRevocations(ctx context.Context, sessions []domain.Session, reason string) error {
	var enqueueErrors []error
	for _, session := range sessions {
		request, requestErr := s.requests.GetByID(ctx, s.db, session.RequestID)
		if requestErr != nil {
			enqueueErrors = append(enqueueErrors, fmt.Errorf("load session %s request: %w", session.ID, requestErr))
			continue
		}
		err := InTx(ctx, s.db, func(q repository.DBTX) error {
			current, getErr := s.sessions.GetByIDForUpdate(ctx, q, session.ID)
			if getErr != nil {
				return getErr
			}
			transitioned := false
			switch current.Status {
			case domain.SessionRunning, domain.SessionRevokeFailed:
				if _, beginErr := s.sessions.BeginRevoke(ctx, q, current.ID); beginErr != nil {
					return beginErr
				}
				transitioned = true
			case domain.SessionManualIntervention:
				if _, beginErr := s.sessions.BeginRevoke(ctx, q, current.ID); beginErr != nil {
					return beginErr
				}
				transitioned = true
			case domain.SessionRevoking:
			default:
				return nil
			}
			if transitioned {
				if auditErr := s.appendAudit(ctx, q, domain.AuditEvent{
					EventType: "session.revoke_requested", ActorType: "system",
					SubjectUserID: stringPtr(request.ApplicantID), RequestID: stringPtr(request.ID),
					SessionID: stringPtr(current.ID), AssetID: stringPtr(request.AssetID),
					TargetPort: intPtr(request.TargetPort), Result: stringPtr("queued"), Reason: stringPtr(reason),
				}); auditErr != nil {
					return auditErr
				}
			}
			_, outboxErr := s.outbox.CreateIfNoActive(ctx, q, domain.OutboxEvent{
				ID: id.New(), AggregateType: "session", AggregateID: current.ID,
				EventType: outboxSessionRevoke,
				Payload:   map[string]any{"session_id": current.ID, "reason": reason}, Status: "pending",
			})
			return outboxErr
		})
		if err != nil {
			enqueueErrors = append(enqueueErrors, fmt.Errorf("session %s: %w", session.ID, err))
			continue
		}
		s.discardSessionToken(ctx, session.ID)
	}
	if len(enqueueErrors) > 0 {
		return errors.Join(enqueueErrors...)
	}
	return nil
}

func (s *AccessService) failProvision(ctx context.Context, session domain.Session, request domain.AccessRequest, reason string) (domain.Session, error) {
	persistCtx := context.WithoutCancel(ctx)
	err := InTx(persistCtx, s.db, func(q repository.DBTX) error {
		if updateErr := s.sessions.MarkProvisionFailed(persistCtx, q, session.ID, session.Version, reason); updateErr != nil {
			return updateErr
		}
		return s.appendAudit(persistCtx, q, domain.AuditEvent{
			EventType:     "session.provision_failed",
			ActorType:     "system",
			SubjectUserID: stringPtr(request.ApplicantID),
			RequestID:     stringPtr(request.ID),
			SessionID:     stringPtr(session.ID),
			AssetID:       stringPtr(request.AssetID),
			TargetPort:    intPtr(request.TargetPort),
			Result:        stringPtr("failed"),
			Reason:        stringPtr(reason),
		})
	})
	if err != nil {
		return domain.Session{}, fmt.Errorf("mark provisioning failure: %w", err)
	}
	failed, getErr := s.sessions.GetByID(persistCtx, s.db, session.ID)
	if getErr != nil {
		return domain.Session{}, fmt.Errorf("read failed session: %w", getErr)
	}
	return failed, fmt.Errorf("provision session: %s", reason)
}

func (s *AccessService) failProvisionRevokeFailed(ctx context.Context, session domain.Session, request domain.AccessRequest, reason string, cleanupErr error) (domain.Session, error) {
	markedReason := reason
	if cleanupErr != nil {
		markedReason += ": compensation unavailable"
	}
	persistCtx := context.WithoutCancel(ctx)
	err := InTx(persistCtx, s.db, func(q repository.DBTX) error {
		if updateErr := s.sessions.MarkProvisionRevokeFailed(persistCtx, q, session.ID, session.Version, markedReason); updateErr != nil {
			return updateErr
		}
		if eventErr := s.sessionEvents.Append(persistCtx, q, domain.SessionEvent{
			ID: id.New(), SessionID: session.ID, EventType: "session.revoke_failed",
			ActorType: "system", Metadata: map[string]any{"reason": markedReason},
		}); eventErr != nil {
			return eventErr
		}
		if auditErr := s.appendAudit(persistCtx, q, domain.AuditEvent{
			EventType: "session.revoke_failed", ActorType: "system",
			SubjectUserID: stringPtr(request.ApplicantID), RequestID: stringPtr(request.ID),
			SessionID: stringPtr(session.ID), AssetID: stringPtr(request.AssetID),
			TargetPort: intPtr(request.TargetPort), Result: stringPtr("failed"),
			Reason: stringPtr(markedReason),
		}); auditErr != nil {
			return auditErr
		}
		return s.appendOutbox(persistCtx, q, "session", session.ID, outboxSessionRevoke,
			map[string]any{"session_id": session.ID, "reason": "provision_compensation"})
	})
	if err != nil {
		return domain.Session{}, fmt.Errorf("record provisioning compensation failure: %w", err)
	}
	failed, getErr := s.sessions.GetByID(persistCtx, s.db, session.ID)
	if getErr != nil {
		return domain.Session{}, fmt.Errorf("read provisioning compensation failure: %w", getErr)
	}
	return failed, errors.Join(fmt.Errorf("provision compensation failed: %w", cleanupErr), fmt.Errorf("provision session: %s", reason))
}

// persistRevokeFailure records every failed gateway close and leaves a
// deduplicated durable command behind.  RevokeSession is also callable
// directly (outside ProcessOutbox), so relying on an already-existing outbox
// event would leave a crash or a transient gateway error unrecoverable.
func (s *AccessService) persistRevokeFailure(ctx context.Context, session domain.Session, request domain.AccessRequest, reason string, cause error) (domain.Session, error) {
	persistCtx := context.WithoutCancel(ctx)
	const failureReason = "gateway_session_revoke_failed"
	var failed domain.Session
	resolved := false
	persistErr := InTx(persistCtx, s.db, func(q repository.DBTX) error {
		current, err := s.sessions.GetByIDForUpdate(persistCtx, q, session.ID)
		if err != nil {
			return err
		}
		if isTerminalSession(current.Status) && current.Status != domain.SessionManualIntervention {
			failed = current
			resolved = true
			return nil
		}
		if current.Status == domain.SessionRunning || current.Status == domain.SessionRevokeFailed || current.Status == domain.SessionManualIntervention {
			current, err = s.sessions.BeginRevoke(persistCtx, q, current.ID)
			if err != nil {
				return err
			}
		}
		if current.Status != domain.SessionRevoking {
			return fmt.Errorf("persist revoke failure from state %q: %w", current.Status, ErrStateConflict)
		}
		if err := s.sessions.MarkRevokeFailed(persistCtx, q, current.ID, failureReason); err != nil {
			return err
		}
		failed, err = s.sessions.GetByID(persistCtx, q, current.ID)
		if err != nil {
			return err
		}
		if err := s.sessionEvents.Append(persistCtx, q, domain.SessionEvent{
			ID: id.New(), SessionID: current.ID, EventType: "session.revoke_failed",
			ActorType: "system", Metadata: map[string]any{"reason": reason},
		}); err != nil {
			return err
		}
		if err := s.appendAudit(persistCtx, q, domain.AuditEvent{
			EventType: "session.revoke_failed", ActorType: "system",
			SubjectUserID: stringPtr(request.ApplicantID), RequestID: stringPtr(request.ID),
			SessionID: stringPtr(current.ID), AssetID: stringPtr(request.AssetID),
			TargetPort: intPtr(request.TargetPort), Result: stringPtr("failed"), Reason: stringPtr(reason),
		}); err != nil {
			return err
		}
		_, err = s.outbox.CreateIfNoActive(persistCtx, q, domain.OutboxEvent{
			ID: id.New(), AggregateType: "session", AggregateID: current.ID,
			EventType: outboxSessionRevoke,
			Payload:   map[string]any{"session_id": current.ID, "reason": reason}, Status: "pending",
		})
		return err
	})
	if resolved && persistErr == nil {
		s.discardSessionToken(ctx, session.ID)
		return failed, nil
	}
	if persistErr != nil {
		s.logger.Error().Err(persistErr).Str("session_id", session.ID).Bool("alert", true).Msg("persist gateway revoke failure failed")
	}
	if cause == nil {
		cause = fmt.Errorf("gateway revoke failed")
	}
	resultErr := fmt.Errorf("revoke gateway session: %w", cause)
	if persistErr != nil {
		resultErr = errors.Join(resultErr, fmt.Errorf("persist revoke failure: %w", persistErr))
	}
	return failed, resultErr
}

const maxGatewayProcessIDBytes = 128

// validGatewayCreateResponse checks the fields that are security-sensitive at
// the control-plane boundary. The gateway client performs the same checks for
// its HTTP implementation, but the service also accepts alternate clients in
// tests and in deployments that use another transport.
func validGatewayCreateResponse(response gateway.CreateSessionResponse, sessionID, mode string) bool {
	if gateway.ValidateConnectionResponse(mode, response) != nil {
		return false
	}
	if response.SessionID != sessionID || !validGatewayProcessID(response.ProcessID) ||
		response.ListenerPort < 1 || response.ListenerPort > 65535 ||
		response.ExternalPort < 1 || response.ExternalPort > 65535 {
		return false
	}
	if response.ExposureMode != "direct" && response.ExposureMode != "kubernetes_nodeport" {
		return false
	}
	if strings.TrimSpace(response.ExposureRef) == "" || strings.TrimSpace(response.ExposureRef) != response.ExposureRef || len(response.ExposureRef) > 253 {
		return false
	}
	return response.Status == "" || response.Status == string(domain.SessionRunning)
}

func validGatewayProcessID(value string) bool {
	if value == "" || len(value) > maxGatewayProcessIDBytes {
		return false
	}
	for _, character := range []byte(value) {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.' || character == ':' {
			continue
		}
		return false
	}
	return true
}

// validGatewayCloseResponse is checked in the service as well as by the HTTP
// client because callers may provide another gateway.Client implementation.
// An empty status or a response for another session must never be interpreted
// as a successful revoke.
func validGatewayCloseResponse(response gateway.CloseSessionResponse, sessionID string) bool {
	if response.SessionID != sessionID {
		return false
	}
	switch response.Status {
	case "closed", "expired", "not_found":
		return true
	default:
		return false
	}
}

func (s *AccessService) compensateGatewaySession(ctx context.Context, managementEndpoint, sessionID string) error {
	response, err := s.gateway.CloseSession(context.WithoutCancel(ctx), managementEndpoint, sessionID, "compensate-"+sessionID)
	if err == nil && !validGatewayCloseResponse(response, sessionID) {
		err = fmt.Errorf("gateway returned invalid compensation response: %w", ErrStateConflict)
	}
	if err != nil {
		s.logger.Error().Err(err).Str("session_id", sessionID).Bool("alert", true).Msg("compensate gateway session failed")
		return fmt.Errorf("compensate gateway session: %w", err)
	}
	return nil
}

// provisioningLeaseState returns the current row and whether this worker still
// owns the optimistic provisioning lease.  A changed version means another
// worker may be talking to the same gateway session ID; callers must not issue
// a compensating close in that case.
func (s *AccessService) provisioningLeaseState(ctx context.Context, session domain.Session) (domain.Session, bool, error) {
	current, err := s.sessions.GetByID(ctx, s.db, session.ID)
	if err != nil {
		return domain.Session{}, false, err
	}
	return current, current.Status == domain.SessionProvisioning && current.Version == session.Version, nil
}

// startProvisioningLeaseHeartbeat keeps a long-running gateway call from
// becoming stale while the worker is still alive. The child context is
// cancelled if the conditional renewal fails, preventing the worker from
// completing an attempt after another replica has taken ownership.
func (s *AccessService) startProvisioningLeaseHeartbeat(parent context.Context, session domain.Session) (context.Context, func(), <-chan error) {
	leaseCtx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	failures := make(chan error, 1)
	interval := provisioningLease / 3
	if interval < time.Second {
		interval = time.Second
	}
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-leaseCtx.Done():
				return
			case <-ticker.C:
				err := s.sessions.RenewProvisioningLease(leaseCtx, s.db, session.ID, session.Version)
				if err == nil {
					continue
				}
				// Cancellation caused by normal shutdown is not a lease failure.
				if leaseCtx.Err() != nil {
					return
				}
				select {
				case failures <- err:
				default:
				}
				cancel()
				return
			}
		}
	}()
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			cancel()
			<-done
		})
	}
	return leaseCtx, stop, failures
}

func readProvisioningLeaseFailure(failures <-chan error) error {
	select {
	case err := <-failures:
		return err
	default:
		return nil
	}
}

func sessionTokenAssociatedData(sessionID string) []byte {
	return []byte("access-gateway/session-token/v1/" + sessionID)
}

func (s *AccessService) discardSessionToken(ctx context.Context, sessionID string) {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if _, err := s.tokenDeliveries.Delete(cleanupCtx, s.db, sessionID); err != nil {
		s.logger.Error().Err(err).Str("session_id", sessionID).Bool("alert", true).Msg("delete session token delivery failed")
	}
}

func isTerminalGatewayStatus(status string) bool {
	switch status {
	case "closed", "expired", "failed", "not_found":
		return true
	default:
		return false
	}
}

func validateCreateInput(input CreateRequestInput) error {
	if input.RequestedStartAt != nil {
		return requestValidation("不支持预约开始时间，会话将在审批通过后按有效期开始计时")
	}
	if input.TTLSeconds < 0 || input.TTLSeconds > int(maxAccessRequestTTL/time.Second) {
		return requestValidation("会话有效期不能超过 5 小时")
	}
	for _, item := range []struct {
		value   string
		message string
	}{
		{input.ApplicantID, "申请人身份无效，请重新登录"},
		{input.RegionID, "请选择有效区域，或刷新页面后重试"},
		{input.AssetID, "请选择有效资产，或刷新页面后重试"},
	} {
		if err := validateUUID(item.value, "request field"); err != nil {
			return requestValidation(item.message)
		}
	}
	if input.TargetPort < 1 || input.TargetPort > 65535 {
		return requestValidation("请选择已配置的目标端口，端口范围为 1–65535")
	}
	sourceIP := net.ParseIP(strings.TrimSpace(input.SourceIP))
	if input.SourceIP != "" && (sourceIP == nil || sourceIP.IsUnspecified() || sourceIP.IsMulticast()) {
		return requestValidation("来源 IP 需填写网关看到的客户端 IPv4 或 IPv6 地址，不能填写 localhost、网址、端口或网段")
	}
	if len([]byte(input.TargetAccount)) > 128 || strings.IndexFunc(input.TargetAccount, unicode.IsControl) >= 0 {
		return requestValidation("目标服务登录账号不能超过 128 字节或包含控制字符")
	}
	if strings.TrimSpace(input.Reason) == "" || len([]rune(input.Reason)) > 4000 {
		return requestValidation("请填写申请原因，最多 4000 个字符")
	}
	if len(input.IdempotencyKey) < 8 || len(input.IdempotencyKey) > 128 {
		return requestValidation("申请提交标识无效，请刷新页面后重试")
	}
	if input.TicketNo != nil && len(*input.TicketNo) > 128 {
		return requestValidation("关联工单不能超过 128 字节")
	}
	return nil
}

func sameRequestPayload(existing domain.AccessRequest, input CreateRequestInput) bool {
	if existing.ApplicantID != input.ApplicantID || existing.AssetID != input.AssetID || existing.TargetPort != input.TargetPort || existing.Reason != input.Reason || existing.Emergency != input.Emergency {
		return false
	}
	if !sameOptionalString(existing.SourceIP, optionalString(input.SourceIP)) || !sameOptionalString(existing.TargetAccount, optionalString(input.TargetAccount)) {
		return false
	}
	if input.TTLSeconds != 0 && existing.TTLSeconds != input.TTLSeconds {
		return false
	}
	if !sameOptionalString(existing.TicketNo, input.TicketNo) {
		return false
	}
	if existing.RequestedStartAt == nil || input.RequestedStartAt == nil {
		return existing.RequestedStartAt == nil && input.RequestedStartAt == nil
	}
	return existing.RequestedStartAt.Equal(*input.RequestedStartAt)
}

func sameOptionalString(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func directGatewayHost(value string) (string, error) {
	value = strings.TrimSpace(value)
	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Hostname() == "" {
			return "", fmt.Errorf("gateway public endpoint is invalid")
		}
		return parsed.Hostname(), nil
	}
	if host, _, err := net.SplitHostPort(value); err == nil && host != "" {
		return host, nil
	}
	if net.ParseIP(value) != nil || (value != "" && !strings.ContainsAny(value, "/?#@[]")) {
		return value, nil
	}
	return "", fmt.Errorf("gateway public endpoint is invalid")
}

func isTerminalSession(status domain.SessionStatus) bool {
	switch status {
	case domain.SessionExpired, domain.SessionClosed, domain.SessionFailed, domain.SessionManualIntervention:
		return true
	default:
		return false
	}
}

// nextApprovalLevel evaluates the immutable threshold of each configured node.
func nextApprovalLevel(approvals []domain.Approval) (int, bool) {
	counts, required := map[int]int{}, map[int]int{}
	for _, a := range approvals {
		if a.ApprovalLevel < 1 {
			continue
		}
		required[a.ApprovalLevel] = max(required[a.ApprovalLevel], max(1, a.RequiredApprovals))
		if a.Decision != nil && *a.Decision == domain.ApprovalApproved {
			counts[a.ApprovalLevel]++
		}
	}
	current := 0
	for level, threshold := range required {
		if counts[level] >= threshold {
			continue
		}
		if current == 0 || level < current {
			current = level
		}
	}
	return current, current == 0
}

func stringPtr(value string) *string { return &value }

func cancellationActorType(admin bool) string {
	if admin {
		return "admin"
	}
	return "user"
}

func intPtr(value int) *int { return &value }
