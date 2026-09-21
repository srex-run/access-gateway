package repository

import (
	"context"

	"github.com/srex-run/access-gateway/internal/securetransport"
)

type TransportKey struct {
	ID                   string
	PublicKey            string
	PrivateKeyCiphertext string
}

type TransportRepository struct{}

func (*TransportRepository) LockKeyRotation(ctx context.Context, q DBTX) error {
	_, err := q.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "browser-transport-key-rotation")
	return opError("lock browser transport key rotation", err)
}

func (*TransportRepository) ActiveKey(ctx context.Context, q DBTX) (TransportKey, error) {
	value, err := scanTransportKey(q.QueryRowContext(ctx, `SELECT id, public_key, private_key_ciphertext
		FROM browser_transport_keys WHERE expires_at > NOW() + INTERVAL '5 minutes'
		ORDER BY expires_at DESC, id LIMIT 1`))
	return value, opError("get browser transport key", err)
}

func (*TransportRepository) CreateKey(ctx context.Context, q DBTX, key TransportKey) error {
	_, err := q.ExecContext(ctx, `INSERT INTO browser_transport_keys (id, public_key, private_key_ciphertext)
		VALUES ($1, $2, $3)`, key.ID, key.PublicKey, key.PrivateKeyCiphertext)
	return opError("create browser transport key", err)
}

func (*TransportRepository) CreateChallenge(ctx context.Context, q DBTX, c securetransport.Challenge) (securetransport.Challenge, error) {
	value, err := scanTransportChallenge(q.QueryRowContext(ctx, `INSERT INTO browser_transport_challenges (id, key_id, method, path, subject)
		SELECT $1, id, $3, $4, $5 FROM browser_transport_keys WHERE id = $2 AND expires_at > NOW() + INTERVAL '2 minutes'
		RETURNING id, key_id, method, path, subject, expires_at`, c.ID, c.KeyID, c.Method, c.Path, c.Subject))
	return value, opError("create browser transport challenge", err)
}

// Binding checks and consumption are one statement, shared by all replicas.
func (*TransportRepository) Consume(ctx context.Context, q DBTX, id string, binding securetransport.Binding) (securetransport.Challenge, TransportKey, error) {
	c, key, err := scanConsumedTransport(q.QueryRowContext(ctx, `WITH consumed AS (
		DELETE FROM browser_transport_challenges WHERE id = $1 AND method = $2 AND path = $3 AND subject = $4 AND expires_at > NOW()
		RETURNING id, key_id, method, path, subject, expires_at
	) SELECT c.id, c.key_id, c.method, c.path, c.subject, c.expires_at, k.private_key_ciphertext
	FROM consumed c JOIN browser_transport_keys k ON k.id = c.key_id`, id, binding.Method, binding.Path, binding.Subject))
	return c, key, opError("consume browser transport challenge", err)
}

func (*TransportRepository) DeleteExpired(ctx context.Context, q DBTX) error {
	_, err := q.ExecContext(ctx, `DELETE FROM browser_transport_challenges WHERE id IN (
		SELECT id FROM browser_transport_challenges WHERE expires_at <= NOW() ORDER BY expires_at, id LIMIT 5000 FOR UPDATE SKIP LOCKED)`)
	if err != nil {
		return opError("purge browser transport challenges", err)
	}
	_, err = q.ExecContext(ctx, `DELETE FROM browser_transport_keys WHERE id IN (
		SELECT k.id FROM browser_transport_keys k WHERE k.expires_at <= NOW()
		AND NOT EXISTS (SELECT 1 FROM browser_transport_challenges c WHERE c.key_id = k.id)
		ORDER BY k.expires_at, k.id LIMIT 100 FOR UPDATE SKIP LOCKED)`)
	return opError("purge browser transport keys", err)
}
