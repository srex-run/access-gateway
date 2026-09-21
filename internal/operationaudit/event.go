// Package operationaudit owns the asset-side operation audit ingestion contract.
package operationaudit

import "time"

type Event struct {
	EventID              string         `json:"event_id"`
	Protocol             string         `json:"protocol"`
	AssetID              string         `json:"asset_id"`
	TargetPort           int            `json:"target_port"`
	ActualAccount        string         `json:"actual_account"`
	OperationType        string         `json:"operation_type"`
	StatementFingerprint *string        `json:"statement_fingerprint"`
	NormalizedOperation  *string        `json:"normalized_operation"`
	ObjectName           *string        `json:"object_name"`
	Result               string         `json:"result"`
	DurationMS           *int64         `json:"duration_ms"`
	BackendSourceIP      string         `json:"backend_source_ip"`
	BackendSourcePort    int            `json:"backend_source_port"`
	SourceRecordID       string         `json:"source_record_id"`
	OccurredAt           time.Time      `json:"occurred_at"`
	Metadata             map[string]any `json:"metadata"`
}
