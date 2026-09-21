package repository

import (
	"context"
	"encoding/json"
	"time"

	"github.com/srex-run/access-gateway/internal/domain"
)

type AccessRequestRepository struct{}

func NewAccessRequestRepository() *AccessRequestRepository {
	return &AccessRequestRepository{}
}

func (r *AccessRequestRepository) Create(ctx context.Context, q DBTX, value domain.AccessRequest) (domain.AccessRequest, error) {
	var snapshot []byte
	if value.WorkflowSnapshot != nil {
		var err error
		snapshot, err = json.Marshal(value.WorkflowSnapshot)
		if err != nil {
			return value, opError("encode approval snapshot", err)
		}
	}
	if value.ApprovalMode == "" {
		value.ApprovalMode = "required"
	}
	const query = `
		INSERT INTO access_requests (
			id, applicant_id, asset_id, target_port, reason, ticket_no, emergency,
			requested_start_at, ttl_seconds, status, idempotency_key, source_ip, target_account, approval_mode, workflow_snapshot, approval_expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
		RETURNING ` + accessRequestColumns
	created, err := scanAccessRequest(q.QueryRowContext(ctx, query,
		value.ID,
		value.ApplicantID,
		value.AssetID,
		value.TargetPort,
		value.Reason,
		value.TicketNo,
		value.Emergency,
		value.RequestedStartAt,
		value.TTLSeconds,
		value.Status,
		value.IdempotencyKey,
		value.SourceIP,
		value.TargetAccount,
		value.ApprovalMode,
		snapshot,
		value.ApprovalExpiresAt,
	))
	if err != nil {
		return domain.AccessRequest{}, opError("create access request", err)
	}
	return created, nil
}

func (r *AccessRequestRepository) GetByID(ctx context.Context, q DBTX, id string) (domain.AccessRequest, error) {
	const query = `SELECT ` + accessRequestColumns + ` FROM access_requests WHERE id = $1`
	value, err := scanAccessRequest(q.QueryRowContext(ctx, query, id))
	if err != nil {
		return domain.AccessRequest{}, opError("get access request by id", err)
	}
	return value, nil
}

// GetByIDForUpdate reads and locks an access request row for a state-machine
// decision. Service transactions use this before inspecting the linked
// session so cancellation and final approval serialize on the request row.
func (r *AccessRequestRepository) GetByIDForUpdate(ctx context.Context, q DBTX, id string) (domain.AccessRequest, error) {
	const query = `SELECT ` + accessRequestColumns + ` FROM access_requests WHERE id = $1 FOR UPDATE`
	value, err := scanAccessRequest(q.QueryRowContext(ctx, query, id))
	if err != nil {
		return domain.AccessRequest{}, opError("lock access request by id", err)
	}
	return value, nil
}

func (r *AccessRequestRepository) GetByIdempotencyKey(ctx context.Context, q DBTX, key string) (domain.AccessRequest, error) {
	const query = `SELECT ` + accessRequestColumns + ` FROM access_requests WHERE idempotency_key = $1`
	value, err := scanAccessRequest(q.QueryRowContext(ctx, query, key))
	if err != nil {
		return domain.AccessRequest{}, opError("get access request by idempotency key", err)
	}
	return value, nil
}

func (r *AccessRequestRepository) ListByApplicant(ctx context.Context, q DBTX, applicantID string, limit, offset int) ([]domain.AccessRequest, error) {
	const maxPageSize = 100
	if limit < 1 || limit > maxPageSize {
		limit = maxPageSize
	}
	if offset < 0 {
		offset = 0
	}
	const query = `
		SELECT ` + accessRequestColumns + `
		FROM access_requests
		WHERE applicant_id = $1
		ORDER BY created_at DESC, id DESC
		LIMIT $2 OFFSET $3`
	rows, err := q.QueryContext(ctx, query, applicantID, limit, offset)
	if err != nil {
		return nil, opError("list applicant access requests", err)
	}
	values, err := CollectRows(rows, scanAccessRequest)
	if err != nil {
		return nil, opError("list applicant access requests", err)
	}
	return values, nil
}

// ListApprovalExpired returns pending requests older than the caller's
// approval deadline.  The caller must re-check the status inside a transaction
// before changing it because multiple workers may scan the same page.
func (r *AccessRequestRepository) ListApprovalExpired(ctx context.Context, q DBTX, before time.Time, limit int) ([]domain.AccessRequest, error) {
	const maxPageSize = 500
	if limit < 1 || limit > maxPageSize {
		limit = maxPageSize
	}
	const query = `
		SELECT ` + accessRequestColumns + `
		FROM access_requests
		WHERE status = 'pending_approval' AND ((approval_expires_at IS NULL AND created_at <= $1) OR approval_expires_at <= NOW())
		ORDER BY created_at, id
		LIMIT $2`
	rows, err := q.QueryContext(ctx, query, before, limit)
	if err != nil {
		return nil, opError("list expired approval requests", err)
	}
	values, err := CollectRows(rows, scanAccessRequest)
	if err != nil {
		return nil, opError("list expired approval requests", err)
	}
	return values, nil
}

func (r *AccessRequestRepository) TransitionStatus(ctx context.Context, q DBTX, id string, from, to domain.AccessRequestStatus) (domain.AccessRequest, error) {
	const query = `
		UPDATE access_requests
		SET status = $2, updated_at = NOW()
		WHERE id = $1 AND status = $3`
	result, err := q.ExecContext(ctx, query, id, to, from)
	if err != nil {
		return domain.AccessRequest{}, opError("transition access request status", err)
	}
	if err := affected("transition access request status", result); err != nil {
		return domain.AccessRequest{}, err
	}
	value, err := r.GetByID(ctx, q, id)
	if err != nil {
		return domain.AccessRequest{}, opError("read transitioned access request", err)
	}
	return value, nil
}

func (r *AccessRequestRepository) Cancel(ctx context.Context, q DBTX, id string) (domain.AccessRequest, error) {
	const query = `
		UPDATE access_requests
		SET status = 'cancelled', updated_at = NOW()
		WHERE id = $1 AND status IN ('pending_approval', 'approved')`
	result, err := q.ExecContext(ctx, query, id)
	if err != nil {
		return domain.AccessRequest{}, opError("cancel access request", err)
	}
	if err := affected("cancel access request", result); err != nil {
		return domain.AccessRequest{}, err
	}
	value, err := r.GetByID(ctx, q, id)
	if err != nil {
		return domain.AccessRequest{}, opError("read cancelled access request", err)
	}
	return value, nil
}
