package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/srex-run/access-gateway/internal/domain"
)

type AccessEvidenceRepository struct{}

func NewAccessEvidenceRepository() *AccessEvidenceRepository {
	return &AccessEvidenceRepository{}
}

// AppendConnectionEvent is idempotent by the Agent-generated event ID.
func (r *AccessEvidenceRepository) AppendConnectionEvent(ctx context.Context, q DBTX, value domain.GatewayConnectionEvent) (bool, error) {
	const query = `
		INSERT INTO gateway_connection_events (
			event_id, connection_id, session_id, event_type, source_ip,
			backend_source_ip, backend_source_port, bytes_up, bytes_down,
			duration_ms, result, reason, occurred_at
		) VALUES ($1, $2, $3, $4, $5::inet, $6::inet, $7, $8, $9, $10, $11, $12, $13)
		ON CONFLICT (event_id) DO NOTHING`
	result, err := q.ExecContext(ctx, query,
		value.EventID, value.ConnectionID, value.SessionID, value.EventType,
		value.SourceIP, value.BackendSourceIP, value.BackendSourcePort,
		value.BytesUp, value.BytesDown, value.DurationMS, value.Result,
		value.Reason, value.OccurredAt,
	)
	if err != nil {
		return false, opError("append gateway connection event", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return false, opError("append gateway connection event rows affected", err)
	}
	return count == 1, nil
}

func (r *AccessEvidenceRepository) CorrelateOperation(ctx context.Context, q DBTX, assetID string, targetPort int, backendSourceIP string, backendSourcePort int, occurredAt time.Time) (connectionID, sessionID, targetAccount string, err error) {
	const query = `
		SELECT ` + operationCorrelationColumns + `
		FROM (
				SELECT connected.connection_id, connected.session_id, COALESCE(request.target_account, '') AS target_account
			FROM gateway_connection_events AS connected
			JOIN sessions AS session ON session.id = connected.session_id
			JOIN access_requests AS request ON request.id = session.request_id
			WHERE connected.event_type = 'backend_connected'
			  AND request.asset_id = $1
			  AND request.target_port = $2
			  AND connected.backend_source_ip = $3::inet
			  AND connected.backend_source_port = $4
				  AND connected.occurred_at <= $5
				  AND connected.occurred_at >= $5 - INTERVAL '25 hours'
			  AND NOT EXISTS (
				SELECT 1 FROM gateway_connection_events AS finished
				WHERE finished.connection_id = connected.connection_id
				  AND finished.event_type = 'disconnected'
				  AND finished.occurred_at < $5
			  )
			ORDER BY connected.occurred_at DESC, connected.event_id DESC
			LIMIT 2
		) AS candidates`
	rows, queryErr := q.QueryContext(ctx, query, assetID, targetPort, backendSourceIP, backendSourcePort, occurredAt)
	if queryErr != nil {
		return "", "", "", opError("correlate operation audit", queryErr)
	}
	values, collectErr := CollectRows(rows, scanOperationCorrelation)
	if collectErr != nil {
		return "", "", "", opError("correlate operation audit", collectErr)
	}
	if len(values) == 0 {
		return "", "", "", opError("correlate operation audit", ErrNotFound)
	}
	if len(values) != 1 {
		return "", "", "", opError("correlate operation audit", ErrConflict)
	}
	return values[0].ConnectionID, values[0].SessionID, values[0].TargetAccount, nil
}

// AppendOperationEvent is idempotent by the collector's stable event ID.
func (r *AccessEvidenceRepository) AppendOperationEvent(ctx context.Context, q DBTX, value domain.OperationAuditEvent) (bool, error) {
	const query = `
		INSERT INTO operation_audit_events (
			event_id, connection_id, session_id, protocol, asset_id, target_port,
			actual_account, operation_type, statement_fingerprint, normalized_operation,
			object_name, result, duration_ms, backend_source_ip, backend_source_port,
			source_record_id, correlation_status, occurred_at, metadata
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14::inet, $15, $16, $17, $18, $19)
		ON CONFLICT (event_id) DO NOTHING`
	metadata, err := json.Marshal(value.Metadata)
	if err != nil {
		return false, opError("encode operation audit metadata", err)
	}
	result, err := q.ExecContext(ctx, query,
		value.EventID, value.ConnectionID, value.SessionID, value.Protocol,
		value.AssetID, value.TargetPort, value.ActualAccount, value.OperationType,
		value.StatementFingerprint, value.NormalizedOperation, value.ObjectName,
		value.Result, value.DurationMS, value.BackendSourceIP, value.BackendSourcePort,
		value.SourceRecordID, value.CorrelationStatus, value.OccurredAt, metadata,
	)
	if err != nil {
		return false, opError("append operation audit event", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return false, opError("append operation audit event rows affected", err)
	}
	return count == 1, nil
}

func (r *AccessEvidenceRepository) ListOperationEvents(ctx context.Context, q DBTX, filter domain.OperationAuditFilter) ([]domain.OperationAuditEvent, error) {
	const maxPageSize = 200
	if filter.Limit < 1 || filter.Limit > maxPageSize {
		filter.Limit = maxPageSize
	}
	if filter.Offset < 0 {
		filter.Offset = 0
	}
	query := `SELECT ` + operationAuditEventColumnsQualified + ` FROM operation_audit_events AS o`
	if filter.SubjectUserID != "" {
		query += ` JOIN sessions AS s ON s.id = o.session_id JOIN access_requests AS r ON r.id = s.request_id`
	}
	where, args := operationAuditWhere(filter)
	query += where + " ORDER BY o.occurred_at DESC, o.event_id DESC LIMIT $" + itoa(len(args)+1) + " OFFSET $" + itoa(len(args)+2)
	args = append(args, filter.Limit, filter.Offset)
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, opError("list operation audit events", err)
	}
	values, err := CollectRows(rows, scanOperationAuditEvent)
	if err != nil {
		return nil, opError("list operation audit events", err)
	}
	return values, nil
}

// Both session counts and expanded commands must apply filters after removing
// superseded start events, so a completed command cannot appear twice.
func operationAuditWhere(filter domain.OperationAuditFilter) (string, []any) {
	query := ` WHERE ` + visibleOperationPredicate
	args := make([]any, 0, 11)
	add := func(fragment string, value any) {
		args = append(args, value)
		query += " " + fragment
	}
	if filter.SubjectUserID != "" {
		add("AND r.applicant_id = $"+itoa(len(args)+1), filter.SubjectUserID)
	}
	if filter.ActualAccount != "" {
		add("AND o.actual_account = $"+itoa(len(args)+1), filter.ActualAccount)
	}
	if filter.AssetID != "" {
		add("AND o.asset_id = $"+itoa(len(args)+1), filter.AssetID)
	}
	if filter.SessionID != "" {
		add("AND o.session_id = $"+itoa(len(args)+1), filter.SessionID)
	}
	if filter.Protocol != "" {
		add("AND o.protocol = $"+itoa(len(args)+1), filter.Protocol)
	}
	if filter.Result != "" {
		add("AND o.result = $"+itoa(len(args)+1), filter.Result)
	}
	if filter.CorrelationStatus != "" {
		add("AND o.correlation_status = $"+itoa(len(args)+1), filter.CorrelationStatus)
	}
	if filter.From != nil {
		add("AND o.occurred_at >= $"+itoa(len(args)+1), *filter.From)
	}
	if filter.To != nil {
		add("AND o.occurred_at < $"+itoa(len(args)+1), *filter.To)
	}
	return query, args
}

func (r *AccessEvidenceRepository) GetConnectionEvent(ctx context.Context, q DBTX, eventID string) (domain.GatewayConnectionEvent, error) {
	const query = `SELECT ` + gatewayConnectionEventColumns + ` FROM gateway_connection_events WHERE event_id = $1`
	value, err := scanGatewayConnectionEvent(q.QueryRowContext(ctx, query, eventID))
	if err != nil {
		return domain.GatewayConnectionEvent{}, opError("get gateway connection event", err)
	}
	return value, nil
}

func (r *AccessEvidenceRepository) GetOperationEvent(ctx context.Context, q DBTX, eventID string) (domain.OperationAuditEvent, error) {
	const query = `SELECT ` + operationAuditEventColumns + ` FROM operation_audit_events WHERE event_id = $1`
	value, err := scanOperationAuditEvent(q.QueryRowContext(ctx, query, eventID))
	if err != nil {
		return domain.OperationAuditEvent{}, opError("get operation audit event", err)
	}
	return value, nil
}

func validateEvidenceTime(value time.Time) error {
	if value.IsZero() {
		return fmt.Errorf("evidence time is required")
	}
	return nil
}
