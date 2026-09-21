package domain

import "time"

type CloudAccount struct {
	ID                    string    `json:"id"`
	Name                  string    `json:"name"`
	Provider              string    `json:"provider"`
	Enabled               bool      `json:"enabled"`
	Revision              int64     `json:"revision"`
	CredentialsCiphertext string    `json:"-"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
}

type CloudSyncInput struct {
	RegionID      string    `json:"region_id"`
	GatewayID     string    `json:"gateway_id"`
	CloudRegion   string    `json:"cloud_region"`
	InstanceIDs   []string  `json:"instance_ids"`
	Ports         []int     `json:"ports"`
	ApproverID    string    `json:"approver_id"`
	RiskLevel     RiskLevel `json:"risk_level"`
	MaxTTLSeconds int       `json:"max_ttl_seconds"`
}

type CloudSyncResult struct {
	Discovered int      `json:"discovered"`
	Created    int      `json:"created"`
	Updated    int      `json:"updated"`
	Skipped    int      `json:"skipped"`
	MissingIDs []string `json:"missing_ids"`
}

type CloudSyncJob struct {
	ID              string          `json:"id"`
	AccountID       string          `json:"account_id"`
	AccountRevision int64           `json:"-"`
	ActorID         string          `json:"actor_id"`
	Input           CloudSyncInput  `json:"input"`
	Status          string          `json:"status"`
	Result          CloudSyncResult `json:"result"`
	Error           string          `json:"error"`
	LeaseToken      *string         `json:"-"`
	LeaseUntil      *time.Time      `json:"-"`
	CreatedAt       time.Time       `json:"created_at"`
	StartedAt       *time.Time      `json:"started_at"`
	FinishedAt      *time.Time      `json:"finished_at"`
}
