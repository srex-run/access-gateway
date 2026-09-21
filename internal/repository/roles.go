package repository

import (
	"context"

	"github.com/srex-run/access-gateway/internal/domain"
)

type RoleRepository struct{}

func NewRoleRepository() *RoleRepository {
	return &RoleRepository{}
}

func (r *RoleRepository) Create(ctx context.Context, q DBTX, value domain.RoleAssignment) (domain.RoleAssignment, error) {
	const query = `
		INSERT INTO role_assignments (id, user_id, role, granted_by)
		VALUES ($1, $2, $3, $4)
		RETURNING ` + roleAssignmentColumns
	created, err := scanRoleAssignment(q.QueryRowContext(ctx, query, value.ID, value.UserID, value.Role, value.GrantedBy))
	if err != nil {
		return domain.RoleAssignment{}, opError("create role assignment", err)
	}
	return created, nil
}

func (r *RoleRepository) GetByID(ctx context.Context, q DBTX, id string) (domain.RoleAssignment, error) {
	const query = `SELECT ` + roleAssignmentColumns + ` FROM role_assignments WHERE id = $1`
	value, err := scanRoleAssignment(q.QueryRowContext(ctx, query, id))
	if err != nil {
		return domain.RoleAssignment{}, opError("get role assignment", err)
	}
	return value, nil
}

func (r *RoleRepository) ListActiveByUser(ctx context.Context, q DBTX, userID string) ([]domain.RoleAssignment, error) {
	const query = `
		SELECT ` + roleAssignmentColumns + `
		FROM role_assignments
		WHERE user_id = $1 AND revoked_at IS NULL
		ORDER BY created_at, id`
	rows, err := q.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, opError("list active user role assignments", err)
	}
	values, err := CollectRows(rows, scanRoleAssignment)
	if err != nil {
		return nil, opError("list active user role assignments", err)
	}
	return values, nil
}

func (r *RoleRepository) Revoke(ctx context.Context, q DBTX, id string) (domain.RoleAssignment, error) {
	const query = `
		UPDATE role_assignments
		SET revoked_at = NOW()
		WHERE id = $1 AND revoked_at IS NULL
		RETURNING ` + roleAssignmentColumns
	value, err := scanRoleAssignment(q.QueryRowContext(ctx, query, id))
	if err != nil {
		return domain.RoleAssignment{}, opError("revoke role assignment", err)
	}
	return value, nil
}
