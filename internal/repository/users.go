package repository

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/security"
)

type UserRepository struct{}

func NewUserRepository() *UserRepository {
	return &UserRepository{}
}

func (r *UserRepository) Create(ctx context.Context, q DBTX, value domain.User) (domain.User, error) {
	if value.Username == "" {
		value.Username = security.ExternalUsername("", "", "user", value.ID)
	}
	const query = `INSERT INTO users
        (id, feishu_open_id, feishu_union_id, username, nickname, email, department, status)
        VALUES ($1, NULLIF($2, ''), $3, $4, $5, $6, $7, $8)
        ON CONFLICT DO NOTHING RETURNING ` + userColumns
	created, err := scanUser(q.QueryRowContext(ctx, query, value.ID, value.FeishuOpenID, value.FeishuUnionID,
		value.Username, strings.TrimSpace(value.Nickname), value.Email, value.Department, value.Status))
	if errors.Is(err, ErrNotFound) {
		err = ErrConflict
	}
	return created, opError("create user", err)
}

// Provider subjects identify accounts. A matching username never links two users.
func (r *UserRepository) CreateExternal(ctx context.Context, q DBTX, value domain.User) (domain.User, error) {
	if value.Username == "" {
		value.Username = security.ExternalUsername("", "", "user", value.ID)
	}
	base := value.Username
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			suffix := fmt.Sprintf("_%s_%d", strings.ReplaceAll(value.ID, "-", ""), attempt)
			prefix := base
			if len(prefix) > 64-len(suffix) {
				prefix = prefix[:64-len(suffix)]
			}
			value.Username = prefix + suffix
		}
		created, err := r.Create(ctx, q, value)
		if !errors.Is(err, ErrConflict) {
			return created, err
		}
	}
	return domain.User{}, opError("allocate external username", ErrConflict)
}

func (r *UserRepository) UpsertByFeishu(ctx context.Context, q DBTX, value domain.User) (domain.User, error) {
	existing, err := r.updateFeishuProfile(ctx, q, value)
	if !errors.Is(err, ErrNotFound) {
		return existing, err
	}
	created, err := r.CreateExternal(ctx, q, value)
	if errors.Is(err, ErrConflict) {
		// A concurrent first login may have inserted the same immutable open ID.
		existing, updateErr := r.updateFeishuProfile(ctx, q, value)
		if !errors.Is(updateErr, ErrNotFound) {
			return existing, updateErr
		}
	}
	return created, err
}

func (r *UserRepository) updateFeishuProfile(ctx context.Context, q DBTX, value domain.User) (domain.User, error) {
	const query = `UPDATE users SET
        feishu_union_id=$2, nickname=COALESCE(NULLIF(btrim($3), ''), username), email=$4, department=$5,
        status=CASE WHEN status='inactive' THEN status ELSE $6 END,
        auth_version=auth_version+CASE WHEN status<>$6 AND $6='inactive' THEN 1 ELSE 0 END,
        revision=revision+1, updated_at=NOW()
        WHERE feishu_open_id=$1 RETURNING ` + userColumns
	updated, err := scanUser(q.QueryRowContext(ctx, query, value.FeishuOpenID, value.FeishuUnionID,
		value.Nickname, value.Email, value.Department, value.Status))
	return updated, opError("sync Feishu profile", err)
}

func (r *UserRepository) GetByID(ctx context.Context, q DBTX, id string) (domain.User, error) {
	const query = `SELECT ` + userColumns + ` FROM users WHERE id = $1`
	value, err := scanUser(q.QueryRowContext(ctx, query, id))
	if err != nil {
		return domain.User{}, opError("get user by id", err)
	}
	return value, nil
}

func (r *UserRepository) GetByIDForUpdate(ctx context.Context, q DBTX, id string) (domain.User, error) {
	const query = `SELECT ` + userColumns + ` FROM users WHERE id = $1 FOR UPDATE`
	value, err := scanUser(q.QueryRowContext(ctx, query, id))
	if err != nil {
		return domain.User{}, opError("get user by id for update", err)
	}
	return value, nil
}

func (r *UserRepository) GetByFeishuOpenID(ctx context.Context, q DBTX, openID string) (domain.User, error) {
	const query = `SELECT ` + userColumns + ` FROM users WHERE feishu_open_id = $1`
	value, err := scanUser(q.QueryRowContext(ctx, query, openID))
	if err != nil {
		return domain.User{}, opError("get user by feishu open id", err)
	}
	return value, nil
}

func (r *UserRepository) GetByFeishuUnionID(ctx context.Context, q DBTX, unionID string) (domain.User, error) {
	const query = `SELECT ` + userColumns + ` FROM users WHERE feishu_union_id = $1`
	value, err := scanUser(q.QueryRowContext(ctx, query, unionID))
	if err != nil {
		return domain.User{}, opError("get user by Feishu union id", err)
	}
	return value, nil
}

func (r *UserRepository) UpdateStatus(ctx context.Context, q DBTX, id string, status domain.UserStatus) error {
	const query = `UPDATE users SET status = $2, auth_version = auth_version + CASE WHEN status <> $2 THEN 1 ELSE 0 END, revision = revision + 1, updated_at = NOW() WHERE id = $1`
	result, err := q.ExecContext(ctx, query, id, status)
	if err != nil {
		return opError("update user status", err)
	}
	return affected("update user status", result)
}
