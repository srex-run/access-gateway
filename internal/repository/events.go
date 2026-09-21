package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/srex-run/access-gateway/internal/domain"
)

type SessionEventRepository struct{}

func NewSessionEventRepository() *SessionEventRepository {
	return &SessionEventRepository{}
}

func (r *SessionEventRepository) Append(ctx context.Context, q DBTX, value domain.SessionEvent) error {
	const query = `
		INSERT INTO session_events (id, session_id, event_type, actor_type, actor_id, metadata)
		VALUES ($1, $2, $3, $4, $5, $6)`
	metadata, err := json.Marshal(value.Metadata)
	if err != nil {
		return opError("encode session event metadata", err)
	}
	result, err := q.ExecContext(ctx, query, value.ID, value.SessionID, value.EventType, value.ActorType, value.ActorID, metadata)
	if err != nil {
		return opError("append session event", err)
	}
	return affected("append session event", result)
}

func (r *SessionEventRepository) ListBySession(ctx context.Context, q DBTX, sessionID string, limit, offset int) ([]domain.SessionEvent, error) {
	const maxPageSize = 500
	if limit < 1 || limit > maxPageSize {
		limit = maxPageSize
	}
	if offset < 0 {
		offset = 0
	}
	const query = `
		SELECT ` + sessionEventColumns + `
		FROM session_events
		WHERE session_id = $1
		ORDER BY created_at, id
		LIMIT $2 OFFSET $3`
	rows, err := q.QueryContext(ctx, query, sessionID, limit, offset)
	if err != nil {
		return nil, opError("list session events", err)
	}
	values, err := CollectRows(rows, scanSessionEvent)
	if err != nil {
		return nil, opError("list session events", err)
	}
	return values, nil
}

type AuditEventRepository struct{}

func NewAuditEventRepository() *AuditEventRepository {
	return &AuditEventRepository{}
}

func (r *AuditEventRepository) Append(ctx context.Context, q DBTX, value domain.AuditEvent) error {
	const query = `
		INSERT INTO audit_events (
			id, event_type, actor_type, actor_id, subject_user_id, request_id,
			session_id, region_id, asset_id, target_port, source_ip, client_version,
			result, reason, metadata
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`
	metadata, err := json.Marshal(value.Metadata)
	if err != nil {
		return opError("encode audit event metadata", err)
	}
	result, err := q.ExecContext(ctx, query,
		value.ID,
		value.EventType,
		value.ActorType,
		value.ActorID,
		value.SubjectUserID,
		value.RequestID,
		value.SessionID,
		value.RegionID,
		value.AssetID,
		value.TargetPort,
		value.SourceIP,
		value.ClientVersion,
		value.Result,
		value.Reason,
		metadata,
	)
	if err != nil {
		return opError("append audit event", err)
	}
	return affected("append audit event", result)
}

func (r *AuditEventRepository) List(ctx context.Context, q DBTX, filter domain.AuditFilter) ([]domain.AuditEvent, error) {
	const maxPageSize = 200
	if filter.Limit < 1 || filter.Limit > maxPageSize {
		filter.Limit = maxPageSize
	}
	if filter.Offset < 0 {
		filter.Offset = 0
	}

	query := `SELECT ` + auditEventColumns + ` FROM audit_events WHERE 1 = 1`
	args := make([]any, 0, 12)
	add := func(fragment string, value any) {
		args = append(args, value)
		query += " " + fragment
	}
	if filter.UserMutationsOnly {
		query += " AND actor_type IN ('user', 'admin')"
		add("AND event_type = ANY($"+itoa(len(args)+1)+")", filter.EventTypes)
	}
	if filter.EventType != "" {
		add("AND event_type = $"+itoa(len(args)+1), filter.EventType)
	}
	if filter.ActorID != "" {
		add("AND actor_id = $"+itoa(len(args)+1), filter.ActorID)
	}
	if filter.SubjectUserID != "" {
		add("AND subject_user_id = $"+itoa(len(args)+1), filter.SubjectUserID)
	}
	if filter.RequestID != "" {
		add("AND request_id = $"+itoa(len(args)+1), filter.RequestID)
	}
	if filter.SessionID != "" {
		add("AND session_id = $"+itoa(len(args)+1), filter.SessionID)
	}
	if filter.RegionID != "" {
		add("AND region_id = $"+itoa(len(args)+1), filter.RegionID)
	}
	if filter.AssetID != "" {
		add("AND asset_id = $"+itoa(len(args)+1), filter.AssetID)
	}
	if filter.SourceIP != "" {
		add("AND source_ip = $"+itoa(len(args)+1), filter.SourceIP)
	}
	if filter.Result != "" {
		add("AND result = $"+itoa(len(args)+1), filter.Result)
	}
	if filter.From != nil {
		add("AND created_at >= $"+itoa(len(args)+1), *filter.From)
	}
	if filter.To != nil {
		add("AND created_at < $"+itoa(len(args)+1), *filter.To)
	}
	limitPlaceholder := itoa(len(args) + 1)
	offsetPlaceholder := itoa(len(args) + 2)
	query += " ORDER BY created_at DESC, id DESC LIMIT $" + limitPlaceholder + " OFFSET $" + offsetPlaceholder
	args = append(args, filter.Limit, filter.Offset)

	// Resolve display fields after filtering and pagination. LEFT JOIN retains
	// historical events whose actor is absent, and never rewrites audit evidence.
	query = `SELECT events.*, COALESCE(u.nickname, ''), COALESCE(u.username, '')
		FROM (` + query + `) events
		LEFT JOIN users u ON u.id = events.actor_id AND events.actor_type IN ('user', 'admin')
		ORDER BY events.created_at DESC, events.id DESC`

	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, opError("list audit events", err)
	}
	values, err := CollectRows(rows, scanAuditEvent)
	if err != nil {
		return nil, opError("list audit events", err)
	}
	return values, nil
}

func itoa(value int) string {
	// The value is a locally generated placeholder index, never request input.
	if value == 0 {
		return "0"
	}
	digits := [20]byte{}
	pos := len(digits)
	for value > 0 {
		pos--
		digits[pos] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[pos:])
}

type OutboxEventRepository struct{}

type OutboxQueueStats struct {
	PendingCount     int64
	OldestAgeSeconds float64
}

func NewOutboxEventRepository() *OutboxEventRepository {
	return &OutboxEventRepository{}
}

func (r *OutboxEventRepository) QueueStats(ctx context.Context, q DBTX) (OutboxQueueStats, error) {
	const query = `
		SELECT ` + outboxQueueStatsColumns + `
		FROM (
			SELECT
				COUNT(*)::bigint AS pending_count,
				COALESCE(EXTRACT(EPOCH FROM (NOW() - MIN(created_at))), 0)::double precision AS oldest_age_seconds
			FROM outbox_events
			WHERE status IN ('pending', 'processing')
		) AS queue_stats`
	value, err := scanOutboxQueueStats(q.QueryRowContext(ctx, query))
	if err != nil {
		return OutboxQueueStats{}, opError("read outbox queue stats", err)
	}
	return value, nil
}

func (r *OutboxEventRepository) GetByID(ctx context.Context, q DBTX, id string) (domain.OutboxEvent, error) {
	const query = `SELECT ` + outboxEventColumns + ` FROM outbox_events WHERE id = $1`
	value, err := scanOutboxEvent(q.QueryRowContext(ctx, query, id))
	if err != nil {
		return domain.OutboxEvent{}, opError("get outbox event by id", err)
	}
	return value, nil
}

func (r *OutboxEventRepository) Create(ctx context.Context, q DBTX, value domain.OutboxEvent) error {
	if value.Status == "" {
		value.Status = "pending"
	}
	if value.RetryCount < 0 {
		value.RetryCount = 0
	}
	const query = `
		INSERT INTO outbox_events (
			id, aggregate_type, aggregate_id, event_type, payload, status,
			retry_count, next_retry_at, processed_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	payload, err := json.Marshal(value.Payload)
	if err != nil {
		return opError("encode outbox payload", err)
	}
	result, err := q.ExecContext(ctx, query,
		value.ID,
		value.AggregateType,
		value.AggregateID,
		value.EventType,
		payload,
		value.Status,
		value.RetryCount,
		value.NextRetryAt,
		value.ProcessedAt,
	)
	if err != nil {
		return opError("create outbox event", err)
	}
	return affected("create outbox event", result)
}

// CreateIfNoActive inserts a command only when the same aggregate/event does
// not already have a pending or leased processing record.  The transaction
// scoped advisory lock closes the check-then-insert race across service
// replicas without adding a second durable queue implementation.
func (r *OutboxEventRepository) CreateIfNoActive(ctx context.Context, q DBTX, value domain.OutboxEvent) (bool, error) {
	if value.Status == "" {
		value.Status = "pending"
	}
	if value.RetryCount < 0 {
		value.RetryCount = 0
	}
	payload, err := json.Marshal(value.Payload)
	if err != nil {
		return false, opError("encode deduplicated outbox payload", err)
	}
	const query = `
		WITH command_lock AS (
			SELECT pg_advisory_xact_lock(
				hashtextextended($2::varchar::text || ':' || $3::uuid::text || ':' || $4::varchar::text, 0)
			)
		)
		INSERT INTO outbox_events (
			id, aggregate_type, aggregate_id, event_type, payload, status,
			retry_count, next_retry_at, processed_at
		)
		SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9
		FROM command_lock
		WHERE NOT EXISTS (
			SELECT 1
			FROM outbox_events
			WHERE aggregate_type = $2
			  AND aggregate_id = $3
			  AND event_type = $4
			  AND status IN ('pending', 'processing')
		)`
	result, err := q.ExecContext(ctx, query,
		value.ID,
		value.AggregateType,
		value.AggregateID,
		value.EventType,
		payload,
		value.Status,
		value.RetryCount,
		value.NextRetryAt,
		value.ProcessedAt,
	)
	if err != nil {
		return false, opError("create deduplicated outbox event", err)
	}
	if result == nil {
		return false, opError("create deduplicated outbox event", fmt.Errorf("nil SQL result"))
	}
	count, err := result.RowsAffected()
	if err != nil {
		return false, opError("create deduplicated outbox event rows affected", err)
	}
	return count > 0, nil
}

func (r *OutboxEventRepository) ClaimPending(ctx context.Context, q DBTX, limit int, lease time.Duration) ([]domain.OutboxEvent, error) {
	const maxPageSize = 100
	if limit < 1 || limit > maxPageSize {
		limit = maxPageSize
	}
	leaseSeconds := int(lease / time.Second)
	if leaseSeconds < 1 {
		leaseSeconds = 30
	}
	const query = `
		WITH candidates AS (
			SELECT id
			FROM outbox_events
			WHERE (status = 'pending' AND (next_retry_at IS NULL OR next_retry_at <= NOW()))
			   OR (status = 'processing' AND (next_retry_at IS NULL OR next_retry_at <= NOW()))
			ORDER BY created_at, id
			FOR UPDATE SKIP LOCKED
			LIMIT $1
		)
		UPDATE outbox_events AS e
		SET status = 'processing',
			next_retry_at = NOW() + ($2 * INTERVAL '1 second'),
			processed_at = NULL
		FROM candidates
		WHERE e.id = candidates.id
		RETURNING ` + outboxEventColumnsQualified
	rows, err := q.QueryContext(ctx, query, limit, leaseSeconds)
	if err != nil {
		return nil, opError("claim pending outbox events", err)
	}
	values, err := CollectRows(rows, scanOutboxEvent)
	if err != nil {
		return nil, opError("claim pending outbox events", err)
	}
	return values, nil
}

func (r *OutboxEventRepository) MarkProcessed(ctx context.Context, q DBTX, id string) error {
	const query = `
		UPDATE outbox_events
		SET status = 'processed', processed_at = COALESCE(processed_at, NOW()), next_retry_at = NULL
		WHERE id = $1 AND status IN ('processing', 'processed')`
	result, err := q.ExecContext(ctx, query, id)
	if err != nil {
		return opError("mark outbox event processed", err)
	}
	return affected("mark outbox event processed", result)
}

func (r *OutboxEventRepository) Reschedule(ctx context.Context, q DBTX, id string, nextRetryAt time.Time, terminal bool) error {
	status := "pending"
	if terminal {
		status = "failed"
	}
	const query = `
		UPDATE outbox_events
		SET status = $2::varchar,
			retry_count = retry_count + 1,
			next_retry_at = CASE WHEN $2::varchar = 'failed' THEN NULL ELSE $3::timestamptz END,
			processed_at = NULL
		WHERE id = $1 AND status = 'processing'`
	result, err := q.ExecContext(ctx, query, id, status, nextRetryAt)
	if err != nil {
		return opError("reschedule outbox event", err)
	}
	return affected("reschedule outbox event", result)
}
