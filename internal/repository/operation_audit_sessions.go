package repository

import (
	"context"

	"github.com/srex-run/access-gateway/internal/domain"
)

func (r *AccessEvidenceRepository) ListOperationSessions(ctx context.Context, q DBTX, filter domain.OperationAuditFilter) ([]domain.OperationAuditSession, error) {
	limit, offset := sessionRecordPage(filter.Limit, filter.Offset)
	where, args := operationAuditWhere(filter)
	// Group before pagination; a session with many commands still occupies one row.
	query := `WITH grouped AS (
		SELECT o.session_id, COUNT(*) AS command_count,
			COUNT(*) FILTER (WHERE o.result IN ('success','ok','succeeded') OR o.result ~ '^http_[23]') AS success_count,
			COUNT(*) FILTER (WHERE o.result IN ('failure','failed','denied','error','rejected') OR o.result ~ '^http_[45]') AS failed_count,
			jsonb_agg(DISTINCT o.actual_account ORDER BY o.actual_account) AS accounts,
			jsonb_agg(DISTINCT o.protocol ORDER BY o.protocol) AS protocols,
			MAX(o.occurred_at) AS last_occurred_at
		FROM operation_audit_events o JOIN sessions s ON s.id=o.session_id JOIN access_requests r ON r.id=s.request_id` + where + `
		GROUP BY o.session_id ORDER BY last_occurred_at DESC, o.session_id DESC
		LIMIT $` + itoa(len(args)+1) + ` OFFSET $` + itoa(len(args)+2) + `
	)
	SELECT ` + sessionRecordColumns + `, g.command_count, g.success_count, g.failed_count, g.accounts, g.protocols, g.last_occurred_at` + sessionRecordFrom + `
	JOIN grouped g ON g.session_id=s.id ORDER BY g.last_occurred_at DESC, s.id DESC`
	args = append(args, limit, offset)
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, opError("list operation audit sessions", err)
	}
	values, err := CollectRows(rows, scanOperationAuditSession)
	return values, opError("list operation audit sessions", err)
}
