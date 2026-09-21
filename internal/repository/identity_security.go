package repository

import (
	"context"
	"time"

	"github.com/srex-run/access-gateway/internal/domain"
)

type IdentitySecurityRepository struct{}

type Invitation struct {
	ID         string     `json:"id"`
	UserID     string     `json:"user_id"`
	InvitedBy  string     `json:"invited_by"`
	ExpiresAt  time.Time  `json:"expires_at"`
	AcceptedAt *time.Time `json:"accepted_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	SentAt     *time.Time `json:"sent_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

type InvitationView struct {
	Invitation
	Username    string `json:"username"`
	Nickname    string `json:"nickname"`
	InviterName string `json:"inviter_name"`
	Status      string `json:"status"`
}

func (IdentitySecurityRepository) CreateInvitation(ctx context.Context, q DBTX, value Invitation, hash string, ttlHours int) (Invitation, error) {
	const query = `INSERT INTO user_invitations(id, user_id, invited_by, token_hash, expires_at)
		VALUES ($1, $2, $3, $4, NOW() + $5 * INTERVAL '1 hour') RETURNING ` + invitationColumns
	value, err := scanInvitation(q.QueryRowContext(ctx, query, value.ID, value.UserID, value.InvitedBy, hash, ttlHours))
	return value, opError("create invitation", err)
}

func (IdentitySecurityRepository) GetInvitation(ctx context.Context, q DBTX, id string) (Invitation, error) {
	const query = `SELECT ` + invitationColumns + ` FROM user_invitations WHERE id = $1`
	value, err := scanInvitation(q.QueryRowContext(ctx, query, id))
	return value, opError("get invitation", err)
}

func (IdentitySecurityRepository) LiveInvitation(ctx context.Context, q DBTX, hash string) (Invitation, error) {
	const query = `SELECT ` + invitationColumns + ` FROM user_invitations
		WHERE token_hash = $1 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > NOW()`
	value, err := scanInvitation(q.QueryRowContext(ctx, query, hash))
	return value, opError("get live invitation", err)
}

func (IdentitySecurityRepository) ConsumeInvitation(ctx context.Context, q DBTX, hash string) (Invitation, error) {
	const query = `UPDATE user_invitations SET accepted_at = NOW()
		WHERE token_hash = $1 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > NOW() RETURNING ` + invitationColumns
	value, err := scanInvitation(q.QueryRowContext(ctx, query, hash))
	return value, opError("consume invitation", err)
}

func (IdentitySecurityRepository) ListInvitations(ctx context.Context, q DBTX, limit, offset int) ([]InvitationView, error) {
	const query = `SELECT ` + invitationViewColumns + ` FROM user_invitations i
		JOIN users u ON u.id = i.user_id JOIN local_accounts a ON a.user_id = u.id JOIN users inviter ON inviter.id = i.invited_by
		ORDER BY i.created_at DESC, i.id LIMIT $1 OFFSET $2`
	rows, err := q.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, opError("list invitations", err)
	}
	values, err := CollectRows(rows, scanInvitationView)
	return values, opError("list invitations", err)
}

func (IdentitySecurityRepository) RevokeInvitation(ctx context.Context, q DBTX, id string) error {
	const query = `UPDATE user_invitations SET revoked_at = NOW() WHERE id = $1 AND accepted_at IS NULL AND revoked_at IS NULL`
	result, err := q.ExecContext(ctx, query, id)
	if err != nil {
		return opError("revoke invitation", err)
	}
	return affected("revoke invitation", result)
}

func (IdentitySecurityRepository) RevokeUserInvitations(ctx context.Context, q DBTX, userID string) (int64, error) {
	const query = `UPDATE user_invitations SET revoked_at = NOW() WHERE user_id = $1 AND accepted_at IS NULL AND revoked_at IS NULL`
	result, err := q.ExecContext(ctx, query, userID)
	if err != nil {
		return 0, opError("supersede invitations", err)
	}
	count, err := result.RowsAffected() // No live invitation is a valid resend of an expired/revoked invitation.
	return count, opError("supersede invitations", err)
}

func (IdentitySecurityRepository) MarkInvitationDelivery(ctx context.Context, q DBTX, id string, sent bool) error {
	const query = `UPDATE user_invitations SET sent_at = CASE WHEN $2 THEN NOW() ELSE sent_at END,
		send_failures = send_failures + CASE WHEN $2 THEN 0 ELSE 1 END WHERE id = $1`
	result, err := q.ExecContext(ctx, query, id, sent)
	if err != nil {
		return opError("record invitation delivery", err)
	}
	return affected("record invitation delivery", result)
}

func (IdentitySecurityRepository) ActivateInvitedUser(ctx context.Context, q DBTX, userID string) (domain.User, error) {
	const query = `UPDATE users SET status = 'active', revision = revision + 1, updated_at = NOW() WHERE id = $1 AND status = 'inactive' RETURNING ` + userColumns
	value, err := scanUser(q.QueryRowContext(ctx, query, userID))
	return value, opError("activate invited user", err)
}

func (IdentitySecurityRepository) BumpAuthVersion(ctx context.Context, q DBTX, userID string) (domain.User, error) {
	const query = `UPDATE users SET auth_version = auth_version + 1, updated_at = NOW() WHERE id = $1 RETURNING ` + userColumns
	value, err := scanUser(q.QueryRowContext(ctx, query, userID))
	return value, opError("invalidate user sessions", err)
}

type MFABinding struct {
	UserID           string
	SecretCiphertext []byte
	LastStep         int64
	CreatedAt        time.Time
}

type MFAChallenge struct {
	UserID           string
	AuthVersion      int64
	Kind             string
	SecretCiphertext []byte
	Attempts         int
	ExpiresAt        time.Time
	Now              time.Time
}

func (IdentitySecurityRepository) MFA(ctx context.Context, q DBTX, userID string) (MFABinding, error) {
	const query = `SELECT ` + mfaColumns + ` FROM user_mfa WHERE user_id = $1`
	value, err := scanMFA(q.QueryRowContext(ctx, query, userID))
	return value, opError("get MFA binding", err)
}

func (IdentitySecurityRepository) CreateMFAChallenge(ctx context.Context, q DBTX, hash, userID string, version int64, kind string) (MFAChallenge, error) {
	const query = `INSERT INTO mfa_challenges(token_hash, user_id, auth_version, kind) VALUES ($1, $2, $3, $4) RETURNING ` + mfaChallengeColumns
	value, err := scanMFAChallenge(q.QueryRowContext(ctx, query, hash, userID, version, kind))
	return value, opError("create MFA challenge", err)
}

func (IdentitySecurityRepository) MFAChallenge(ctx context.Context, q DBTX, hash string) (MFAChallenge, error) {
	const query = `SELECT ` + mfaChallengeColumns + ` FROM mfa_challenges WHERE token_hash = $1 AND expires_at > NOW() AND attempts < 5`
	value, err := scanMFAChallenge(q.QueryRowContext(ctx, query, hash))
	return value, opError("get MFA challenge", err)
}

func (IdentitySecurityRepository) LockMFAChallenge(ctx context.Context, q DBTX, hash string) (MFAChallenge, error) {
	const query = `SELECT ` + mfaChallengeColumns + ` FROM mfa_challenges WHERE token_hash = $1 AND expires_at > NOW() FOR UPDATE`
	value, err := scanMFAChallenge(q.QueryRowContext(ctx, query, hash))
	return value, opError("lock MFA challenge", err)
}

func (IdentitySecurityRepository) AttemptMFAChallenge(ctx context.Context, q DBTX, hash string) (MFAChallenge, error) {
	const query = `UPDATE mfa_challenges SET attempts = attempts + 1 WHERE token_hash = $1 AND expires_at > NOW() AND attempts < 5 RETURNING ` + mfaChallengeColumns
	value, err := scanMFAChallenge(q.QueryRowContext(ctx, query, hash))
	return value, opError("attempt MFA challenge", err)
}

func (IdentitySecurityRepository) SetMFAEnrollment(ctx context.Context, q DBTX, hash string, secret []byte) error {
	const query = `UPDATE mfa_challenges SET secret_ciphertext = $2 WHERE token_hash = $1 AND kind = 'enroll' AND expires_at > NOW() AND attempts < 5`
	result, err := q.ExecContext(ctx, query, hash, secret)
	if err != nil {
		return opError("set MFA enrollment", err)
	}
	return affected("set MFA enrollment", result)
}

func (IdentitySecurityRepository) ConsumeMFAChallenge(ctx context.Context, q DBTX, hash string) error {
	const query = `DELETE FROM mfa_challenges WHERE token_hash = $1 AND expires_at > NOW()`
	result, err := q.ExecContext(ctx, query, hash)
	if err != nil {
		return opError("consume MFA challenge", err)
	}
	return affected("consume MFA challenge", result)
}

func (IdentitySecurityRepository) BindMFA(ctx context.Context, q DBTX, userID string, ciphertext []byte, step int64) error {
	const query = `INSERT INTO user_mfa(user_id, secret_ciphertext, last_step) VALUES ($1, $2, $3)`
	_, err := q.ExecContext(ctx, query, userID, ciphertext, step)
	return opError("bind MFA", err)
}

func (IdentitySecurityRepository) AdvanceMFAStep(ctx context.Context, q DBTX, userID string, step int64) error {
	const query = `UPDATE user_mfa SET last_step = $2 WHERE user_id = $1 AND last_step < $2`
	result, err := q.ExecContext(ctx, query, userID, step)
	if err != nil {
		return opError("advance MFA step", err)
	}
	return affected("advance MFA step", result)
}

func (IdentitySecurityRepository) DeleteMFA(ctx context.Context, q DBTX, userID string) error {
	const query = `DELETE FROM user_mfa WHERE user_id = $1`
	result, err := q.ExecContext(ctx, query, userID)
	if err != nil {
		return opError("delete MFA", err)
	}
	return affected("delete MFA", result)
}

func (IdentitySecurityRepository) ReplaceRecoveryCodes(ctx context.Context, q DBTX, userID string, hashes []string) error {
	const remove = `DELETE FROM user_mfa_recovery_codes WHERE user_id = $1`
	result, err := q.ExecContext(ctx, remove, userID)
	if err != nil {
		return opError("remove recovery codes", err)
	}
	if _, err = result.RowsAffected(); err != nil {
		return opError("remove recovery codes", err)
	}
	const insert = `INSERT INTO user_mfa_recovery_codes(user_id, code_hash) SELECT $1, unnest($2::text[])`
	_, err = q.ExecContext(ctx, insert, userID, hashes)
	return opError("replace recovery codes", err)
}

func (IdentitySecurityRepository) ConsumeRecoveryCode(ctx context.Context, q DBTX, userID, hash string) error {
	const query = `DELETE FROM user_mfa_recovery_codes WHERE user_id = $1 AND code_hash = $2`
	result, err := q.ExecContext(ctx, query, userID, hash)
	if err != nil {
		return opError("consume recovery code", err)
	}
	return affected("consume recovery code", result)
}

func (IdentitySecurityRepository) RecoveryCodeCount(ctx context.Context, q DBTX, userID string) (int, error) {
	const query = `SELECT COUNT(*) FROM user_mfa_recovery_codes WHERE user_id = $1`
	value, err := scanIdentityCount(q.QueryRowContext(ctx, query, userID))
	return value, opError("count recovery codes", err)
}

func (IdentitySecurityRepository) Now(ctx context.Context, q DBTX) (time.Time, error) {
	const query = `SELECT NOW()`
	value, err := scanIdentityTime(q.QueryRowContext(ctx, query))
	return value, opError("read authentication time", err)
}

func (IdentitySecurityRepository) DeleteExpiredChallenges(ctx context.Context, q DBTX) error {
	const query = `DELETE FROM mfa_challenges WHERE token_hash IN (SELECT token_hash FROM mfa_challenges WHERE expires_at <= NOW() ORDER BY expires_at LIMIT 5000)`
	result, err := q.ExecContext(ctx, query)
	if err != nil {
		return opError("purge MFA challenges", err)
	}
	_, err = result.RowsAffected()
	return opError("purge MFA challenges", err)
}
