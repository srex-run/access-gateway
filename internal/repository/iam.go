package repository

import (
	"context"
	"encoding/json"

	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/iam"
)

type IAMRepository struct{}

// Lock serializes changes that can alter effective administrator membership.
// Shared readers use the same lock during approval snapshot/decision transactions.
func (r IAMRepository) Lock(ctx context.Context, q DBTX, shared bool) error {
	const exclusiveQuery = `SELECT pg_advisory_xact_lock(742095120)`
	const sharedQuery = `SELECT pg_advisory_xact_lock_shared(742095120)`
	query := exclusiveQuery
	if shared {
		query = sharedQuery
	}
	_, err := q.ExecContext(ctx, query)
	return opError("lock IAM configuration", err)
}

func (r IAMRepository) ListRoles(ctx context.Context, q DBTX) ([]iam.Role, error) {
	const query = `SELECT ` + iamRoleColumns + ` FROM iam_roles ORDER BY name LIMIT 1001`
	rows, err := q.QueryContext(ctx, query)
	if err != nil {
		return nil, opError("list IAM roles", err)
	}
	values, err := CollectRows(rows, scanIAMRole)
	return values, opError("list IAM roles", err)
}

func (r IAMRepository) SaveRole(ctx context.Context, q DBTX, v iam.Role) (iam.Role, error) {
	permissions, err := json.Marshal(v.Permissions)
	if err != nil {
		return iam.Role{}, opError("encode role permissions", err)
	}
	labels, err := json.Marshal(v.Labels)
	if err != nil {
		return iam.Role{}, opError("encode role labels", err)
	}
	const query = `INSERT INTO iam_roles (name, description, permissions, labels, enabled)
		SELECT $1, $2, $3, $4, $5 WHERE $6::bigint = 0
		ON CONFLICT (name) DO NOTHING RETURNING ` + iamRoleColumns
	const update = `UPDATE iam_roles SET description=$2, permissions=$3, labels=$4, enabled=$5, revision=revision+1, updated_at=NOW()
		WHERE name=$1 AND revision=$6 RETURNING ` + iamRoleColumns
	statement := query
	if v.Revision > 0 {
		statement = update
	}
	value, err := scanIAMRole(q.QueryRowContext(ctx, statement, v.Name, v.Description, permissions, labels, v.Enabled, v.Revision))
	return value, opError("save IAM role", err)
}

func (r IAMRepository) ListBindings(ctx context.Context, q DBTX) ([]iam.Binding, error) {
	const query = `SELECT ` + iamBindingColumns + ` FROM iam_bindings ORDER BY created_at, id LIMIT 1001`
	rows, err := q.QueryContext(ctx, query)
	if err != nil {
		return nil, opError("list IAM bindings", err)
	}
	values, err := CollectRows(rows, scanIAMBinding)
	return values, opError("list IAM bindings", err)
}

func (r IAMRepository) SaveBinding(ctx context.Context, q DBTX, v iam.Binding) (iam.Binding, error) {
	const create = `INSERT INTO iam_bindings (id, name, user_selector, role_selector, enabled)
		SELECT $1, $2, $3, $4, $5 WHERE $6::bigint = 0 ON CONFLICT DO NOTHING RETURNING ` + iamBindingColumns
	const update = `UPDATE iam_bindings SET name=$2, user_selector=$3, role_selector=$4, enabled=$5, revision=revision+1, updated_at=NOW()
		WHERE id=$1 AND revision=$6 RETURNING ` + iamBindingColumns
	query := create
	if v.Revision > 0 {
		query = update
	}
	value, err := scanIAMBinding(q.QueryRowContext(ctx, query, v.ID, v.Name, v.UserSelector, v.RoleSelector, v.Enabled, v.Revision))
	return value, opError("save IAM binding", err)
}

// These bounded reads form a consistent subject/role snapshot under Lock.
// The extra row allows the service to reject overflow instead of dropping members.
func (r IAMRepository) ListSubjects(ctx context.Context, q DBTX) ([]domain.User, error) {
	const query = `SELECT ` + userColumns + ` FROM users WHERE status='active' ORDER BY id LIMIT 10001`
	rows, err := q.QueryContext(ctx, query)
	if err != nil {
		return nil, opError("list IAM subjects", err)
	}
	values, err := CollectRows(rows, scanUser)
	return values, opError("list IAM subjects", err)
}

func (r IAMRepository) ListAssignments(ctx context.Context, q DBTX) ([]domain.RoleAssignment, error) {
	const query = `SELECT ` + roleAssignmentColumns + ` FROM role_assignments WHERE revoked_at IS NULL ORDER BY user_id, id LIMIT 100001`
	rows, err := q.QueryContext(ctx, query)
	if err != nil {
		return nil, opError("list IAM assignments", err)
	}
	values, err := CollectRows(rows, scanRoleAssignment)
	return values, opError("list IAM assignments", err)
}
