package repository

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// CallbackEventRepository stores Feishu callback identities. It deliberately
// exposes a boolean claim result instead of leaking SQL unique-violation
// details to the HTTP layer.
type CallbackEventRepository struct{}

func NewCallbackEventRepository() *CallbackEventRepository {
	return &CallbackEventRepository{}
}

// Claim reserves eventID for processing. A fresh processing or processed row
// returns false. A processing row whose lease expired can be reclaimed after
// a worker crash.
func (r *CallbackEventRepository) Claim(ctx context.Context, q DBTX, eventID string, lease time.Duration) (bool, error) {
	eventID = strings.TrimSpace(eventID)
	if eventID == "" || len(eventID) > 256 {
		return false, fmt.Errorf("claim callback event: event ID is invalid: %w", ErrConstraint)
	}
	if lease <= 0 {
		lease = 10 * time.Minute
	}
	leaseSeconds := int(lease / time.Second)
	if leaseSeconds < 1 {
		leaseSeconds = 1
	}

	// INSERT and stale-lease reclamation must be one statement. PostgreSQL takes
	// the unique-row lock while evaluating the ON CONFLICT update, so concurrent
	// replicas cannot both observe an expired lease and claim the same callback.
	const query = `
		INSERT INTO callback_events (event_id, status, claimed_at)
		VALUES ($1, 'processing', NOW())
		ON CONFLICT (event_id) DO UPDATE
		SET status = 'processing', claimed_at = NOW(), processed_at = NULL
		WHERE callback_events.status = 'processing'
		  AND callback_events.claimed_at <= NOW() - ($2 * INTERVAL '1 second')`
	result, err := q.ExecContext(ctx, query, eventID, leaseSeconds)
	if err != nil {
		return false, opError("claim callback event", err)
	}
	claimed, err := result.RowsAffected()
	if err != nil {
		return false, opError("claim callback event rows affected", err)
	}
	return claimed > 0, nil
}

// MarkProcessed is idempotent. Updating an already processed row still
// affects one row, which keeps the repository's UPDATE/RowsAffected contract
// explicit without treating a callback retry as an error.
func (r *CallbackEventRepository) MarkProcessed(ctx context.Context, q DBTX, eventID string) error {
	const query = `
		UPDATE callback_events
		SET status = 'processed', processed_at = COALESCE(processed_at, NOW())
		WHERE event_id = $1 AND status IN ('processing', 'processed')`
	result, err := q.ExecContext(ctx, query, strings.TrimSpace(eventID))
	if err != nil {
		return opError("mark callback event processed", err)
	}
	return affected("mark callback event processed", result)
}

// Release lets a transient processing failure be retried immediately. It is
// intentionally a no-op when another replica has already completed the row.
func (r *CallbackEventRepository) Release(ctx context.Context, q DBTX, eventID string) error {
	const query = `DELETE FROM callback_events WHERE event_id = $1 AND status = 'processing'`
	result, err := q.ExecContext(ctx, query, strings.TrimSpace(eventID))
	if err != nil {
		return opError("release callback event", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return opError("release callback event rows affected", err)
	}
	if count == 0 {
		// A processed row or an already released row is an idempotent outcome.
		return nil
	}
	return nil
}
