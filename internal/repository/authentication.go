package repository

import (
	"context"
	"fmt"

	"github.com/srex-run/access-gateway/internal/domain"
)

type LocalCredential struct {
	UserID       string
	Username     string
	PasswordHash string
	AuthVersion  int64
}

func (r *UserRepository) CreateLocalCredential(ctx context.Context, q DBTX, value LocalCredential) error {
	result, err := q.ExecContext(ctx, `WITH account AS (
		UPDATE users SET nickname=CASE WHEN nickname=username THEN $2 ELSE nickname END,
			username=$2, updated_at=NOW() WHERE id=$1 RETURNING id)
		INSERT INTO local_accounts(user_id, password_hash) SELECT id,$3 FROM account`, value.UserID, value.Username, value.PasswordHash)
	if err != nil {
		return opError("create local account", err)
	}
	return affected("create local account", result)
}

func (r *UserRepository) LocalCredential(ctx context.Context, q DBTX, username string) (LocalCredential, error) {
	var value LocalCredential
	err := q.QueryRowContext(ctx, `SELECT a.user_id, u.username, a.password_hash, u.auth_version FROM local_accounts a JOIN users u ON u.id = a.user_id WHERE u.username = $1`, username).Scan(&value.UserID, &value.Username, &value.PasswordHash, &value.AuthVersion)
	return value, opError("get local credentials", err)
}

func (r *UserRepository) LocalCredentialByUser(ctx context.Context, q DBTX, userID string) (LocalCredential, error) {
	var value LocalCredential
	err := q.QueryRowContext(ctx, `SELECT a.user_id, u.username, a.password_hash FROM local_accounts a JOIN users u ON u.id=a.user_id WHERE a.user_id=$1`, userID).Scan(&value.UserID, &value.Username, &value.PasswordHash)
	return value, opError("get user local credentials", err)
}

func (r *UserRepository) UpdateLocalPassword(ctx context.Context, q DBTX, userID, hash string) error {
	result, err := q.ExecContext(ctx, `UPDATE local_accounts SET password_hash = $2, updated_at = NOW() WHERE user_id = $1`, userID, hash)
	if err != nil {
		return opError("update local password", err)
	}
	if err := affected("update local password", result); err != nil {
		return err
	}
	_, err = q.ExecContext(ctx, `UPDATE users SET auth_version = auth_version + 1, updated_at = NOW() WHERE id = $1`, userID)
	return opError("invalidate browser sessions", err)
}

func (r *UserRepository) LockIdentity(ctx context.Context, q DBTX, key string) error {
	_, err := q.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, key)
	return opError("lock external identity", err)
}

func (r *UserRepository) GetByIdentity(ctx context.Context, q DBTX, provider, issuer, subject string) (domain.User, error) {
	value, err := scanUser(q.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE id = (
		SELECT user_id FROM external_identities WHERE provider = $1 AND issuer = $2 AND subject = $3)`, provider, issuer, subject))
	return value, opError("get external identity", err)
}

func (r *UserRepository) CreateIdentity(ctx context.Context, q DBTX, provider, issuer, subject, userID string) error {
	_, err := q.ExecContext(ctx, `INSERT INTO external_identities(provider, issuer, subject, user_id) VALUES ($1, $2, $3, $4)`, provider, issuer, subject, userID)
	return opError("create external identity", err)
}

func (r *UserRepository) IdentityProviders(ctx context.Context, q DBTX, userID string) ([]string, error) {
	rows, err := q.QueryContext(ctx, `SELECT DISTINCT provider FROM external_identities WHERE user_id = $1 ORDER BY provider`, userID)
	if err != nil {
		return nil, opError("list identity providers", err)
	}
	defer rows.Close()
	values := []string{}
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (r *UserRepository) HasIdentityIssuer(ctx context.Context, q DBTX, userID, provider, issuer string) (bool, error) {
	var exists bool
	err := q.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM external_identities WHERE user_id = $1 AND provider = $2 AND issuer = $3)`, userID, provider, issuer).Scan(&exists)
	return exists, opError("check enabled identity issuer", err)
}

func (r *UserRepository) BindFeishu(ctx context.Context, q DBTX, userID, openID, unionID string) (domain.User, error) {
	value, err := scanUser(q.QueryRowContext(ctx, `UPDATE users SET feishu_open_id = $2, feishu_union_id = NULLIF($3, ''), revision = revision + 1, updated_at = NOW()
		WHERE id = $1 AND (feishu_open_id IS NULL OR feishu_open_id = $2)
		AND NOT EXISTS (SELECT 1 FROM users WHERE id <> $1 AND ($3 <> '' AND feishu_union_id = $3)) RETURNING `+userColumns, userID, openID, unionID))
	return value, opError("bind Feishu account", err)
}

func (r *UserRepository) UnbindFeishu(ctx context.Context, q DBTX, userID string) error {
	_, err := q.ExecContext(ctx, `UPDATE users SET feishu_open_id = NULL, feishu_union_id = NULL, auth_version = auth_version + 1, revision = revision + 1, updated_at = NOW() WHERE id = $1`, userID)
	return opError("unbind Feishu account", err)
}

type LoginAttemptRepository struct{}

func (*LoginAttemptRepository) Allow(ctx context.Context, q DBTX, hash string, limit int) (bool, error) {
	if len(hash) != 64 || limit <= 0 {
		return false, fmt.Errorf("invalid login attempt bucket")
	}
	var count int
	err := q.QueryRowContext(ctx, `INSERT INTO login_attempts(bucket_hash, attempts, expires_at) VALUES ($1, 1, NOW() + INTERVAL '5 minutes')
		ON CONFLICT (bucket_hash) DO UPDATE SET
		 attempts = CASE WHEN login_attempts.expires_at <= NOW() THEN 1 ELSE LEAST(login_attempts.attempts + 1, $2 + 1) END,
		 expires_at = CASE WHEN login_attempts.expires_at <= NOW() THEN NOW() + INTERVAL '5 minutes' ELSE login_attempts.expires_at END
		RETURNING attempts`, hash, limit).Scan(&count)
	return count <= limit, opError("limit login attempts", err)
}

func (*LoginAttemptRepository) DeleteExpired(ctx context.Context, q DBTX) error {
	_, err := q.ExecContext(ctx, `DELETE FROM login_attempts WHERE bucket_hash IN (SELECT bucket_hash FROM login_attempts WHERE expires_at <= NOW() ORDER BY expires_at LIMIT 5000)`)
	return opError("purge expired login attempts", err)
}
