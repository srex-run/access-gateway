package repository

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/srex-run/access-gateway/internal/domain"
)

type SessionTokenDeliveryRepository struct{}

func NewSessionTokenDeliveryRepository() *SessionTokenDeliveryRepository {
	return &SessionTokenDeliveryRepository{}
}

func (r *SessionTokenDeliveryRepository) Create(ctx context.Context, q DBTX, delivery domain.SessionTokenDelivery) (domain.SessionTokenDelivery, error) {
	const query = `
		INSERT INTO session_token_deliveries (session_id, token_ciphertext, expires_at)
		VALUES ($1, $2, $3)
		RETURNING ` + sessionTokenDeliveryColumns
	value, err := scanSessionTokenDelivery(q.QueryRowContext(ctx, query, delivery.SessionID, delivery.TokenCiphertext, delivery.ExpiresAt))
	if err != nil {
		return domain.SessionTokenDelivery{}, opError("create session token delivery", err)
	}
	return value, nil
}

func (r *SessionTokenDeliveryRepository) GetAvailable(ctx context.Context, q DBTX, sessionID string, now time.Time) (domain.SessionTokenDelivery, error) {
	const query = `
		SELECT ` + sessionTokenDeliveryColumns + `
		FROM session_token_deliveries
		WHERE session_id = $1 AND expires_at > $2`
	value, err := scanSessionTokenDelivery(q.QueryRowContext(ctx, query, sessionID, now))
	if err != nil {
		return domain.SessionTokenDelivery{}, opError("get available session token delivery", err)
	}
	return value, nil
}

// Consume removes and returns a delivery in one statement. PostgreSQL's row
// lock makes concurrent consumers across control-plane replicas deterministic:
// exactly one transaction can receive the ciphertext.
func (r *SessionTokenDeliveryRepository) Consume(ctx context.Context, q DBTX, sessionID string, now time.Time) (domain.SessionTokenDelivery, error) {
	const query = `
		DELETE FROM session_token_deliveries
		WHERE session_id = $1 AND expires_at > $2
		RETURNING ` + sessionTokenDeliveryColumns
	value, err := scanSessionTokenDelivery(q.QueryRowContext(ctx, query, sessionID, now))
	if err != nil {
		return domain.SessionTokenDelivery{}, opError("consume session token delivery", err)
	}
	return value, nil
}

func (r *SessionTokenDeliveryRepository) Delete(ctx context.Context, q DBTX, sessionID string) (bool, error) {
	const query = `DELETE FROM session_token_deliveries WHERE session_id = $1`
	result, err := q.ExecContext(ctx, query, sessionID)
	if err != nil {
		return false, opError("delete session token delivery", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return false, opError("delete session token delivery rows affected", err)
	}
	return count > 0, nil
}

func (r *SessionTokenDeliveryRepository) DeleteExpired(ctx context.Context, q DBTX, now time.Time, limit int) (int, error) {
	if limit < 1 || limit > 10000 {
		return 0, fmt.Errorf("delete expired session token deliveries: invalid limit: %w", ErrConstraint)
	}
	const query = `
			DELETE FROM session_token_deliveries
			WHERE session_id = ANY(ARRAY(
				SELECT session_id
				FROM session_token_deliveries
				WHERE expires_at <= $1
				ORDER BY expires_at, session_id
				LIMIT $2
				FOR UPDATE SKIP LOCKED
			))`
	result, err := q.ExecContext(ctx, query, now, limit)
	if err != nil {
		return 0, opError("delete expired session token deliveries", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, opError("delete expired session token deliveries rows affected", err)
	}
	return int(count), nil
}

type OAuthStateRepository struct{}

func NewOAuthStateRepository() *OAuthStateRepository {
	return &OAuthStateRepository{}
}

func (r *OAuthStateRepository) Create(ctx context.Context, q DBTX, state domain.OAuthState) (domain.OAuthState, error) {
	state.StateHash = strings.TrimSpace(state.StateHash)
	if !validSHA256Hex(state.StateHash) {
		return domain.OAuthState{}, fmt.Errorf("create OAuth state: invalid state hash: %w", ErrConstraint)
	}
	const query = `
			INSERT INTO oauth_states (state_hash, expires_at)
			VALUES ($1, $2)
			RETURNING ` + oauthStateColumns
	value, err := scanOAuthState(q.QueryRowContext(ctx, query, state.StateHash, state.ExpiresAt))
	if err != nil {
		return domain.OAuthState{}, opError("create OAuth state", err)
	}
	return value, nil
}

func (r *OAuthStateRepository) Consume(ctx context.Context, q DBTX, stateHash string) (bool, error) {
	stateHash = strings.TrimSpace(stateHash)
	if !validSHA256Hex(stateHash) {
		return false, fmt.Errorf("consume OAuth state: invalid state hash: %w", ErrConstraint)
	}
	const query = `DELETE FROM oauth_states WHERE state_hash = $1 AND expires_at > NOW()`
	result, err := q.ExecContext(ctx, query, stateHash)
	if err != nil {
		return false, opError("consume OAuth state", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return false, opError("consume OAuth state rows affected", err)
	}
	return count == 1, nil
}

func (r *OAuthStateRepository) DeleteExpired(ctx context.Context, q DBTX, now time.Time, limit int) (int, error) {
	if limit < 1 || limit > 10000 {
		return 0, fmt.Errorf("delete expired OAuth states: invalid limit: %w", ErrConstraint)
	}
	const query = `
			DELETE FROM oauth_states
			WHERE state_hash = ANY(ARRAY(
				SELECT state_hash
				FROM oauth_states
				WHERE expires_at <= $1
				ORDER BY expires_at, state_hash
				LIMIT $2
				FOR UPDATE SKIP LOCKED
			))`
	result, err := q.ExecContext(ctx, query, now, limit)
	if err != nil {
		return 0, opError("delete expired OAuth states", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, opError("delete expired OAuth states rows affected", err)
	}
	return int(count), nil
}

func validSHA256Hex(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') {
			continue
		}
		return false
	}
	return true
}
