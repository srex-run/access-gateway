package repository

import (
	"context"

	"github.com/srex-run/access-gateway/internal/domain"
)

const sessionRecordFrom = ` FROM sessions s
	JOIN access_requests r ON r.id=s.request_id
	JOIN users u ON u.id=r.applicant_id
	JOIN assets a ON a.id=r.asset_id`

const sessionRecordVisibility = ` ($2::boolean OR r.applicant_id=$1::uuid OR EXISTS (
	SELECT 1 FROM approvals p WHERE p.request_id=r.id AND p.approver_id=$1::uuid))`

func (r *SessionRepository) ListRecords(ctx context.Context, q DBTX, filter domain.SessionRecordFilter) ([]domain.SessionRecord, error) {
	limit, offset := sessionRecordPage(filter.Limit, filter.Offset)
	const query = `SELECT ` + sessionRecordColumns + sessionRecordFrom + ` WHERE ` + sessionRecordVisibility + `
		AND ($3='' OR s.status=$3 OR ($3='open' AND s.status IN ('provisioning','running','revoking','revoke_failed','manual_intervention')))
		AND ($4='' OR strpos(lower(concat_ws(' ', s.id::text, r.id::text, u.nickname, a.name, r.target_account)), lower($4))>0)
		ORDER BY s.created_at DESC, s.id DESC LIMIT $5 OFFSET $6`
	rows, err := q.QueryContext(ctx, query, filter.ActorID, filter.ReadAll, filter.Status, filter.Search, limit, offset)
	if err != nil {
		return nil, opError("list session records", err)
	}
	values, err := CollectRows(rows, scanSessionRecord)
	return values, opError("list session records", err)
}

func (r *SessionRepository) GetRecord(ctx context.Context, q DBTX, actor string, readAll bool, sessionID string) (domain.SessionRecord, error) {
	const query = `SELECT ` + sessionRecordColumns + sessionRecordFrom + ` WHERE ` + sessionRecordVisibility + ` AND s.id=$3`
	value, err := scanSessionRecord(q.QueryRowContext(ctx, query, actor, readAll, sessionID))
	return value, opError("get session record", err)
}

// Keep operation start/completion deduplication identical across the global
// audit list, record summaries, and the session trace.
const deduplicatedOperationPredicate = `(o.metadata->>'source' = 'session_proxy' AND o.metadata->>'phase' = 'started' AND EXISTS (
	SELECT 1 FROM operation_audit_events completed WHERE completed.session_id=o.session_id
	AND completed.metadata->>'source'='session_proxy' AND completed.metadata->>'operation_id'=o.metadata->>'operation_id'
	AND completed.metadata->>'phase'='completed')) IS NOT TRUE`

// Native client startup probes remain audit evidence, but do not appear as
// user operations or affect command counts. Transport frames stay in their
// recording; preserve orphaned legacy frames with no parent recording.
const visibleOperationPredicate = deduplicatedOperationPredicate + `
	AND o.operation_type NOT IN ('client_version_probe','client_syntax_probe')
	AND NOT (o.operation_type='terminal_output' AND EXISTS (
	SELECT 1 FROM operation_audit_events parent WHERE parent.session_id=o.session_id
	AND parent.operation_type IN ('client','shell','exec') AND parent.metadata->>'source'='session_proxy'
	AND parent.metadata->>'operation_id'=o.metadata->>'channel_id'))`

// Explicit JSON fields prevent arbitrary event metadata from exposing secrets.
const sessionTraceQuery = `WITH request AS (SELECT r.id, r.applicant_id, r.approval_mode, r.reason, r.created_at FROM access_requests r JOIN sessions s ON s.request_id=r.id WHERE s.id=$1),
terminal_channels AS (
	SELECT DISTINCT ON (connection_id) connection_id, metadata->>'operation_id' AS channel_id,
		CASE WHEN metadata->>'cols' ~ '^[0-9]{1,3}$' THEN (metadata->>'cols')::int ELSE 120 END AS cols
	FROM operation_audit_events WHERE session_id=$1 AND operation_type='client' AND metadata->>'source'='session_proxy'
	ORDER BY connection_id, occurred_at, event_id
),
trace AS (
	SELECT 'request:'||r.id AS id, 'request' AS stage,
		CASE WHEN r.approval_mode='admin_test' THEN 'access_request.admin_test_started' ELSE 'request.created' END AS event_type, r.created_at AS occurred_at,
		jsonb_build_object('actor_id', r.applicant_id, 'actor_name', u.nickname, 'reason', r.reason) AS details
	FROM request r JOIN users u ON u.id=r.applicant_id
	UNION ALL
	SELECT 'request-event:'||e.id, 'request', e.event_type, e.created_at,
		jsonb_build_object('actor_id', e.actor_id, 'actor_name', COALESCE(u.nickname,e.actor_type), 'result', e.result, 'reason', e.reason)
	FROM audit_events e JOIN request r ON r.id=e.request_id LEFT JOIN users u ON u.id=e.actor_id
	WHERE e.event_type = 'access_request.cancelled'
	UNION ALL
	SELECT 'approval:'||p.id, 'approval', 'approval.'||p.decision, p.decided_at,
		jsonb_build_object('actor_id', p.approver_id, 'actor_name', u.nickname, 'result', p.decision, 'reason', p.comment)
	FROM approvals p JOIN request r ON r.id=p.request_id JOIN users u ON u.id=p.approver_id WHERE p.decided_at IS NOT NULL
	UNION ALL
	SELECT 'session:'||e.id, 'session', e.event_type, e.created_at,
		jsonb_build_object('actor_id', e.actor_id, 'actor_name', COALESCE(u.nickname,e.actor_type), 'result', e.metadata->>'result', 'reason', e.metadata->>'reason')
	FROM session_events e LEFT JOIN users u ON u.id=e.actor_id
	WHERE e.session_id=$1 AND e.event_type NOT LIKE 'connection.%'
	UNION ALL
	SELECT 'connection:'||e.event_id, 'connection', e.event_type, e.occurred_at,
		jsonb_build_object('connection_id', e.connection_id, 'source_ip', host(e.source_ip),
		'backend_source_ip', host(e.backend_source_ip), 'backend_source_port', e.backend_source_port,
		'result', e.result, 'reason', e.reason, 'duration_ms', e.duration_ms)
	FROM gateway_connection_events e WHERE e.session_id=$1
	UNION ALL
	SELECT 'operation:'||o.event_id, 'operation', o.operation_type, o.occurred_at,
		jsonb_build_object('connection_id', o.connection_id, 'actual_account', o.actual_account,
		'account_verified', COALESCE(o.metadata->'account_verified'='true'::jsonb,false),
		'operation', o.normalized_operation, 'object_name', o.object_name, 'protocol', o.protocol,
		'terminal_channel_id', CASE WHEN o.operation_type IN ('client','shell','exec') AND o.metadata->>'source'='session_proxy'
			THEN o.metadata->>'operation_id' ELSE tc.channel_id END,
		'terminal_cols', COALESCE(tc.cols,120),
		'result', o.result, 'duration_ms', o.duration_ms, 'backend_source_ip', host(o.backend_source_ip), 'backend_source_port', o.backend_source_port)
	FROM operation_audit_events o LEFT JOIN terminal_channels tc ON tc.connection_id=o.connection_id
	WHERE o.session_id=$1 AND ` + visibleOperationPredicate + `
)
SELECT id, stage, event_type, occurred_at, details FROM trace WHERE ($2='' OR stage=$2)
ORDER BY occurred_at DESC, id DESC LIMIT $3 OFFSET $4`

func (r *SessionRepository) ListTrace(ctx context.Context, q DBTX, sessionID, stage string, limit, offset int) ([]domain.SessionTraceEvent, error) {
	limit, offset = sessionRecordPage(limit, offset)
	rows, err := q.QueryContext(ctx, sessionTraceQuery, sessionID, stage, limit, offset)
	if err != nil {
		return nil, opError("list session trace", err)
	}
	values, err := CollectRows(rows, scanSessionTrace)
	return values, opError("list session trace", err)
}

func (r *SessionRepository) ListTerminalRecording(ctx context.Context, q DBTX, sessionID, channelID string, limit, offset int) ([]domain.TerminalRecordingFrame, error) {
	limit, offset = sessionRecordPage(limit, offset)
	const query = `SELECT o.event_id, o.occurred_at, COALESCE(o.metadata->>'stream',''), o.metadata->>'data'
		FROM operation_audit_events o WHERE o.session_id=$1 AND o.operation_type='terminal_output'
		AND o.metadata->>'source'='session_proxy' AND o.metadata->>'channel_id'=$2
		AND o.metadata->>'phase'='completed'
		AND o.metadata->>'encoding'='base64' AND jsonb_typeof(o.metadata->'data')='string'
		AND ` + deduplicatedOperationPredicate + ` ORDER BY o.occurred_at, o.event_id LIMIT $3 OFFSET $4`
	rows, err := q.QueryContext(ctx, query, sessionID, channelID, limit, offset)
	if err != nil {
		return nil, opError("list terminal recording", err)
	}
	values, err := CollectRows(rows, func(row RowScanner) (domain.TerminalRecordingFrame, error) {
		var frame domain.TerminalRecordingFrame
		err := row.Scan(&frame.ID, &frame.OccurredAt, &frame.Stream, &frame.Data)
		return frame, err
	})
	return values, opError("list terminal recording", err)
}

func (r *SessionRepository) EvidenceSummary(ctx context.Context, q DBTX, sessionID string) (domain.SessionEvidenceSummary, error) {
	const query = `WITH operations AS (
		SELECT o.actual_account, o.protocol, o.metadata, o.backend_source_ip, o.backend_source_port
		FROM operation_audit_events o WHERE o.session_id=$1 AND ` + visibleOperationPredicate + `
	), connections AS (
		SELECT connection_id, event_type, result, source_ip, backend_source_ip, backend_source_port
		FROM gateway_connection_events WHERE session_id=$1
	), sources AS (
		SELECT host(backend_source_ip) AS ip, backend_source_port AS port FROM operations
		UNION SELECT host(backend_source_ip), backend_source_port FROM connections
	), summary AS (
	SELECT COALESCE((SELECT jsonb_agg(account ORDER BY account) FROM (
		SELECT DISTINCT actual_account AS account FROM operations WHERE metadata->'account_verified'='true'::jsonb AND actual_account<>''
	) accounts),'[]'::jsonb) AS verified_accounts,
	(SELECT COUNT(*) FROM operations) AS operation_count,
	(SELECT COUNT(DISTINCT connection_id) FROM connections) AS connection_count,
	(SELECT COUNT(DISTINCT connection_id) FROM connections WHERE event_type IN ('source_rejected','capacity_rejected','auth_rejected','backend_failed') OR result IN ('failed','failure','error','denied','rejected')) AS failed_connections,
	jsonb_build_object(
		'accounts', COALESCE((SELECT jsonb_agg(jsonb_build_object('name', name, 'verified', verified) ORDER BY name, verified) FROM (
			SELECT DISTINCT actual_account AS name, COALESCE(metadata->'account_verified'='true'::jsonb, false) AS verified
			FROM operations WHERE actual_account<>''
		) accounts),'[]'::jsonb),
		'protocols', COALESCE((SELECT jsonb_agg(protocol ORDER BY protocol) FROM (SELECT DISTINCT protocol FROM operations WHERE protocol<>'') protocols),'[]'::jsonb),
		'backend_sources', COALESCE((SELECT jsonb_agg(jsonb_build_object('ip', ip, 'port', port) ORDER BY ip, port)
			FROM sources s WHERE ip IS NOT NULL AND (port IS NOT NULL OR NOT EXISTS (SELECT 1 FROM sources known WHERE known.ip=s.ip AND known.port IS NOT NULL))),'[]'::jsonb),
		'client_sources', COALESCE((SELECT jsonb_agg(ip ORDER BY ip) FROM (SELECT DISTINCT host(source_ip) AS ip FROM connections WHERE source_ip IS NOT NULL) clients),'[]'::jsonb)
	) AS context
	) SELECT ` + sessionEvidenceSummaryColumns + ` FROM summary`
	value, err := scanSessionEvidenceSummary(q.QueryRowContext(ctx, query, sessionID))
	return value, opError("get session evidence summary", err)
}

func sessionRecordPage(limit, offset int) (int, int) {
	if limit < 1 || limit > 200 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}
