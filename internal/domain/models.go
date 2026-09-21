package domain

import (
	"github.com/srex-run/access-gateway/internal/approvalflow"
	"github.com/srex-run/access-gateway/internal/label"
	"github.com/srex-run/access-gateway/internal/operationaudit"
	"time"
)

type UserStatus string

const (
	UserStatusActive   UserStatus = "active"
	UserStatusInactive UserStatus = "inactive"
)

type ResourceStatus string

const (
	ResourceStatusEnabled  ResourceStatus = "enabled"
	ResourceStatusDisabled ResourceStatus = "disabled"
	ResourceStatusMaint    ResourceStatus = "maintenance"
)

type RiskLevel string

const (
	RiskLevelNormal    RiskLevel = "normal"
	RiskLevelSensitive RiskLevel = "sensitive"
	RiskLevelCritical  RiskLevel = "critical"
)

type AccessRequestStatus string

const (
	AccessRequestPendingApproval AccessRequestStatus = "pending_approval"
	AccessRequestApproved        AccessRequestStatus = "approved"
	AccessRequestRejected        AccessRequestStatus = "rejected"
	AccessRequestCancelled       AccessRequestStatus = "cancelled"
	AccessRequestApprovalExpired AccessRequestStatus = "approval_expired"
)

type SessionStatus string

const (
	SessionProvisioning       SessionStatus = "provisioning"
	SessionRunning            SessionStatus = "running"
	SessionRevoking           SessionStatus = "revoking"
	SessionExpired            SessionStatus = "expired"
	SessionClosed             SessionStatus = "closed"
	SessionFailed             SessionStatus = "failed"
	SessionRevokeFailed       SessionStatus = "revoke_failed"
	SessionManualIntervention SessionStatus = "manual_intervention"
)

type ApprovalDecision string

const (
	ApprovalApproved ApprovalDecision = "approved"
	ApprovalRejected ApprovalDecision = "rejected"
)

type User struct {
	Labels        label.Labels
	Revision      int64
	ID            string
	AuthVersion   int64
	FeishuOpenID  string
	FeishuUnionID *string
	Nickname      string
	Username      string
	Email         *string
	Department    *string
	Status        UserStatus
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type Region struct {
	ID        string
	Code      string
	Name      string
	Status    ResourceStatus
	CreatedAt time.Time
	UpdatedAt time.Time
}

type Gateway struct {
	ID                 string
	RegionID           string
	Name               string
	ManagementEndpoint string
	PublicEndpoint     string
	AuthSecretRef      *string
	Status             ResourceStatus
	MaxSessions        int
	LastHeartbeatAt    *time.Time
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

type Asset struct {
	ID                 string
	ApprovalWorkflowID *string
	RegionID           string
	GatewayID          string
	Name               string
	AssetType          string
	TargetCiphertext   string
	RiskLevel          RiskLevel
	MaxTTLSeconds      int
	Status             ResourceStatus
	ExternalSource     *string
	ExternalID         *string
	SyncGeneration     *string
	LastSyncedAt       *time.Time
	DeletedAt          *time.Time
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

type AssetPort struct {
	ID        string
	AssetID   string
	Port      int
	Protocol  string
	Enabled   bool
	CreatedAt time.Time
	// TargetAccountRequired is derived from the port's current audit policy.
	TargetAccountRequired bool
}

type AssetApprover struct {
	ID            string
	AssetID       string
	UserID        string
	ApprovalLevel int
	Role          string
	Enabled       bool
	CreatedAt     time.Time
}

type AssetGatewayBinding struct {
	AssetID   string
	GatewayID string
	Priority  int
	Enabled   bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

// GatewayCatalogEntry is the non-secret identity and port mapping used to
// publish an enabled control-plane asset into a Gateway Agent catalog.
type GatewayCatalogEntry struct {
	TargetID       string
	ExternalSource *string
	ExternalID     *string
	Ports          []int
}

type AccessRequest struct {
	WorkflowSnapshot  *approvalflow.Snapshot
	ApprovalExpiresAt *time.Time
	ApprovalMode      string
	ID                string
	ApplicantID       string
	AssetID           string
	TargetPort        int
	Reason            string
	TicketNo          *string
	Emergency         bool
	RequestedStartAt  *time.Time
	TTLSeconds        int
	Status            AccessRequestStatus
	IdempotencyKey    string
	SourceIP          *string
	TargetAccount     *string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

type Approval struct {
	Emergency         bool
	RequiredApprovals int
	StepName          string
	ID                string
	RequestID         string
	ApproverID        string
	ApprovalLevel     int
	Decision          *ApprovalDecision
	Comment           *string
	DecidedAt         *time.Time
	CreatedAt         time.Time
}

type Session struct {
	AuditPolicy             operationaudit.Policy
	ConnectionMode          string
	TunnelClientPublicKey   string
	TunnelServerCertificate string
	ID                      string
	RequestID               string
	GatewayID               string
	TokenHash               *string
	RemoteProcessID         *string
	Status                  SessionStatus
	StartedAt               *time.Time
	ExpiresAt               *time.Time
	ClosedAt                *time.Time
	FailureReason           *string
	Version                 int
	ListenerPort            *int
	ExternalPort            *int
	ExposureMode            *string
	ExposureRef             *string
	CreatedAt               time.Time
	UpdatedAt               time.Time
}

type GatewayConnectionEvent struct {
	EventID           string
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
	CreatedAt         time.Time
}

type OperationAuditEvent struct {
	EventID              string
	ConnectionID         *string
	SessionID            *string
	Protocol             string
	AssetID              string
	TargetPort           int
	ActualAccount        string
	OperationType        string
	StatementFingerprint *string
	NormalizedOperation  *string
	ObjectName           *string
	Result               string
	DurationMS           *int64
	BackendSourceIP      string
	BackendSourcePort    int
	SourceRecordID       string
	CorrelationStatus    string
	OccurredAt           time.Time
	Metadata             map[string]any
	CreatedAt            time.Time
}

type OperationAuditFilter struct {
	SubjectUserID     string
	ActualAccount     string
	AssetID           string
	SessionID         string
	Protocol          string
	Result            string
	CorrelationStatus string
	From              *time.Time
	To                *time.Time
	Limit             int
	Offset            int
}

// SessionTokenDelivery contains only authenticated ciphertext. Plaintext
// session tokens never cross the repository boundary.
type SessionTokenDelivery struct {
	SessionID       string
	TokenCiphertext string
	ExpiresAt       time.Time
	CreatedAt       time.Time
}

type OAuthState struct {
	StateHash string
	ExpiresAt time.Time
	CreatedAt time.Time
}

type SessionEvent struct {
	ID        string
	SessionID string
	EventType string
	ActorType string
	ActorID   *string
	Metadata  map[string]any
	CreatedAt time.Time
}

type OutboxEvent struct {
	ID            string
	AggregateType string
	AggregateID   string
	EventType     string
	Payload       map[string]any
	Status        string
	RetryCount    int
	NextRetryAt   *time.Time
	CreatedAt     time.Time
	ProcessedAt   *time.Time
}

type AuditEvent struct {
	ID            string
	EventType     string
	ActorType     string
	ActorID       *string
	ActorName     string // Current user directory value, populated when reading.
	ActorUsername string // Current local username, populated when reading.
	SubjectUserID *string
	RequestID     *string
	SessionID     *string
	RegionID      *string
	AssetID       *string
	TargetPort    *int
	SourceIP      *string
	ClientVersion *string
	Result        *string
	Reason        *string
	Metadata      map[string]any
	CreatedAt     time.Time
}

type AuditFilter struct {
	Category          string
	Action            string
	UserMutationsOnly bool
	EventTypes        []string
	EventType         string
	ActorID           string
	SubjectUserID     string
	RequestID         string
	SessionID         string
	RegionID          string
	AssetID           string
	SourceIP          string
	Result            string
	From              *time.Time
	To                *time.Time
	Limit             int
	Offset            int
}

type RoleAssignment struct {
	ID        string
	UserID    string
	Role      string
	GrantedBy string
	CreatedAt time.Time
	RevokedAt *time.Time
}
