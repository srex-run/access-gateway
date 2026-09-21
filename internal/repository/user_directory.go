package repository

import (
	"context"
	"encoding/json"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/label"
	"time"
)

// UserSummary excludes password hashes, external subject IDs and credentials.
type UserSummary struct {
	Labels      label.Labels `json:"labels"`
	Department  string       `json:"department"`
	Revision    int64        `json:"revision"`
	ID          string       `json:"id"`
	Nickname    string       `json:"nickname"`
	Username    string       `json:"username"`
	Email       string       `json:"email"`
	Status      string       `json:"status"`
	FeishuBound bool         `json:"feishu_bound"`
	CreatedAt   time.Time    `json:"created_at"`
}

func (r *UserRepository) ListDirectory(ctx context.Context, q DBTX, search string, activeOnly bool, limit, offset int) ([]UserSummary, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+userSummaryColumns+`
		FROM users u
		WHERE (NOT $2 OR u.status = 'active') AND ($1 = '' OR
			strpos(lower(u.nickname || ' ' || u.username || ' ' || COALESCE(u.email, '') || ' ' || u.id::text), lower($1)) > 0)
		ORDER BY u.created_at DESC, u.id DESC LIMIT $3 OFFSET $4`, search, activeOnly, limit, offset)
	if err != nil {
		return nil, opError("list user directory", err)
	}
	values, err := CollectRows(rows, scanUserSummary)
	return values, opError("list user directory", err)
}

func (r *UserRepository) DirectoryByID(ctx context.Context, q DBTX, userID string) (UserSummary, error) {
	const query = `SELECT ` + userSummaryColumns + ` FROM users u WHERE u.id=$1`
	value, err := scanUserSummary(q.QueryRowContext(ctx, query, userID))
	return value, opError("read user profile", err)
}

func (r *UserRepository) UpdateProfile(ctx context.Context, q DBTX, v domain.User) error {
	labels, err := json.Marshal(v.Labels)
	if err != nil {
		return opError("encode user labels", err)
	}
	const query = `UPDATE users SET nickname=$2, email=$3, department=$4, status=$5, labels=$6, revision=revision+1,
		auth_version=auth_version+CASE WHEN status<>$5 THEN 1 ELSE 0 END, updated_at=NOW() WHERE id=$1 AND revision=$7`
	result, err := q.ExecContext(ctx, query, v.ID, v.Nickname, v.Email, v.Department, v.Status, labels, v.Revision)
	if err != nil {
		return opError("update user profile", err)
	}
	return affected("update user profile", result)
}

type AssetApproverSummary struct {
	ID            string `json:"id"`
	UserID        string `json:"user_id"`
	Name          string `json:"name"`
	Username      string `json:"username"`
	Status        string `json:"status"`
	FeishuBound   bool   `json:"feishu_bound"`
	ApprovalLevel int    `json:"approval_level"`
	Role          string `json:"role"`
}

func (r *AssetRepository) ListApproverDirectory(ctx context.Context, q DBTX, assetID string) ([]AssetApproverSummary, error) {
	rows, err := q.QueryContext(ctx, `SELECT ap.id, ap.user_id, u.nickname, u.username, u.status,
		COALESCE(u.feishu_open_id, '') <> '', ap.approval_level, ap.role
		FROM asset_approvers ap JOIN users u ON u.id = ap.user_id
		WHERE ap.asset_id = $1 AND ap.enabled = TRUE ORDER BY ap.approval_level, ap.id`, assetID)
	if err != nil {
		return nil, opError("list asset approver directory", err)
	}
	values, err := CollectRows(rows, scanAssetApproverSummary)
	return values, opError("list asset approver directory", err)
}
