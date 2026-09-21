package repository

import (
	"context"

	"github.com/srex-run/access-gateway/internal/domain"
)

type ApprovalRepository struct{}

func NewApprovalRepository() *ApprovalRepository {
	return &ApprovalRepository{}
}

func (r *ApprovalRepository) Create(ctx context.Context, q DBTX, value domain.Approval) (domain.Approval, error) {
	if value.RequiredApprovals == 0 {
		value.RequiredApprovals = 1
	}
	const query = `
		INSERT INTO approvals (id, request_id, approver_id, approval_level, required_approvals, step_name)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING ` + approvalColumns
	created, err := scanApproval(q.QueryRowContext(ctx, query,
		value.ID,
		value.RequestID,
		value.ApproverID,
		value.ApprovalLevel,
		value.RequiredApprovals,
		value.StepName,
	))
	if err != nil {
		return domain.Approval{}, opError("create approval", err)
	}
	return created, nil
}

func (r *ApprovalRepository) GetByID(ctx context.Context, q DBTX, id string) (domain.Approval, error) {
	const query = `SELECT ` + approvalColumns + ` FROM approvals WHERE id = $1`
	value, err := scanApproval(q.QueryRowContext(ctx, query, id))
	if err != nil {
		return domain.Approval{}, opError("get approval by id", err)
	}
	return value, nil
}

func (r *ApprovalRepository) ListByRequest(ctx context.Context, q DBTX, requestID string) ([]domain.Approval, error) {
	const query = `
		SELECT ` + approvalColumns + `
		FROM approvals
		WHERE request_id = $1
		ORDER BY approval_level, created_at, id`
	rows, err := q.QueryContext(ctx, query, requestID)
	if err != nil {
		return nil, opError("list approvals", err)
	}
	values, err := CollectRows(rows, scanApproval)
	if err != nil {
		return nil, opError("list approvals", err)
	}
	return values, nil
}

func (r *ApprovalRepository) ListPendingByApprover(ctx context.Context, q DBTX, approverID string, limit, offset int) ([]domain.Approval, error) {
	const maxPageSize = 100
	if limit < 1 || limit > maxPageSize {
		limit = maxPageSize
	}
	if offset < 0 {
		offset = 0
	}
	const query = `
		SELECT ` + approvalColumnsQualified + `, r.emergency
		FROM approvals a
		JOIN access_requests r ON r.id = a.request_id
		WHERE a.approver_id = $1 AND a.decision IS NULL AND r.status = 'pending_approval'
          AND (r.approval_expires_at IS NULL OR r.approval_expires_at > NOW())
          AND (SELECT count(*) FROM approvals done
               WHERE done.request_id=a.request_id AND done.approval_level=a.approval_level AND done.decision='approved') < a.required_approvals
          AND NOT EXISTS (
              SELECT 1 FROM approvals prior
              WHERE prior.request_id=a.request_id AND prior.approval_level<a.approval_level
                AND (SELECT count(*) FROM approvals done
                     WHERE done.request_id=prior.request_id AND done.approval_level=prior.approval_level AND done.decision='approved') < prior.required_approvals
          )
		ORDER BY r.emergency DESC, a.created_at, a.id
		LIMIT $2 OFFSET $3`
	rows, err := q.QueryContext(ctx, query, approverID, limit, offset)
	if err != nil {
		return nil, opError("list pending approvals", err)
	}
	values, err := CollectRows(rows, scanPendingApproval)
	if err != nil {
		return nil, opError("list pending approvals", err)
	}
	return values, nil
}

func (r *ApprovalRepository) Decide(ctx context.Context, q DBTX, id string, approverID string, decision domain.ApprovalDecision, comment *string) (domain.Approval, error) {
	const query = `
		UPDATE approvals
		SET decision = $2, comment = $3, decided_at = NOW()
		WHERE id = $1 AND approver_id = $4 AND decision IS NULL`
	result, err := q.ExecContext(ctx, query, id, decision, comment, approverID)
	if err != nil {
		return domain.Approval{}, opError("decide approval", err)
	}
	if err := affected("decide approval", result); err != nil {
		return domain.Approval{}, err
	}
	value, err := r.GetByID(ctx, q, id)
	if err != nil {
		return domain.Approval{}, opError("read decided approval", err)
	}
	return value, nil
}
