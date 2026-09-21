package domain

import "time"

// SessionRecord contains display fields only; target addresses and credentials
// must never be selected into this read model.
type SessionRecord struct {
	ID            string        `json:"id"`
	RequestID     string        `json:"request_id"`
	ApplicantID   string        `json:"applicant_id"`
	ApplicantName string        `json:"applicant_name"`
	AssetID       string        `json:"asset_id"`
	AssetName     string        `json:"asset_name"`
	AssetType     string        `json:"asset_type"`
	TargetAccount string        `json:"target_account"`
	TargetPort    int           `json:"target_port"`
	Status        SessionStatus `json:"status"`
	CreatedAt     time.Time     `json:"created_at"`
	StartedAt     *time.Time    `json:"started_at,omitempty"`
	ExpiresAt     *time.Time    `json:"expires_at,omitempty"`
}

type SessionRecordFilter struct {
	ActorID string
	ReadAll bool
	Search  string
	Status  string
	Limit   int
	Offset  int
}

type SessionTraceDetails struct {
	ActorID           string `json:"actor_id,omitempty"`
	ActorName         string `json:"actor_name,omitempty"`
	Result            string `json:"result,omitempty"`
	Reason            string `json:"reason,omitempty"`
	ActualAccount     string `json:"actual_account,omitempty"`
	AccountVerified   bool   `json:"account_verified"`
	ConnectionID      string `json:"connection_id,omitempty"`
	SourceIP          string `json:"source_ip,omitempty"`
	BackendSourceIP   string `json:"backend_source_ip,omitempty"`
	BackendSourcePort *int   `json:"backend_source_port,omitempty"`
	DurationMS        *int64 `json:"duration_ms,omitempty"`
	Operation         string `json:"operation,omitempty"`
	ObjectName        string `json:"object_name,omitempty"`
	Protocol          string `json:"protocol,omitempty"`
	TerminalChannelID string `json:"terminal_channel_id,omitempty"`
	TerminalCols      int    `json:"terminal_cols,omitempty"`
}

type TerminalRecordingFrame struct {
	ID         string    `json:"id"`
	OccurredAt time.Time `json:"occurred_at"`
	Stream     string    `json:"stream"`
	Data       string    `json:"data"`
}

type SessionTraceEvent struct {
	ID         string    `json:"id"`
	Stage      string    `json:"stage"`
	EventType  string    `json:"event_type"`
	OccurredAt time.Time `json:"occurred_at"`
	SessionTraceDetails
}

type SessionEvidenceSummary struct {
	VerifiedAccounts  []string               `json:"verified_accounts"`
	OperationCount    int64                  `json:"operation_count"`
	ConnectionCount   int64                  `json:"connection_count"`
	FailedConnections int64                  `json:"failed_connections"`
	Context           SessionEvidenceContext `json:"context"`
}

type SessionAccountEvidence struct {
	Name     string `json:"name"`
	Verified bool   `json:"verified"`
}

type SessionSourceEvidence struct {
	IP   string `json:"ip"`
	Port *int   `json:"port,omitempty"`
}

// Context contains unique session-level identity and network evidence. It is
// independent of the current trace page and stage filter.
type SessionEvidenceContext struct {
	Accounts       []SessionAccountEvidence `json:"accounts"`
	Protocols      []string                 `json:"protocols"`
	BackendSources []SessionSourceEvidence  `json:"backend_sources"`
	ClientSources  []string                 `json:"client_sources"`
}
