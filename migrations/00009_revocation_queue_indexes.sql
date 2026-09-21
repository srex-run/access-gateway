-- +goose Up
CREATE INDEX idx_outbox_active_session_revoke
    ON outbox_events (aggregate_id)
    WHERE aggregate_type = 'session'
      AND event_type = 'session.revoke'
      AND status IN ('pending', 'processing');

CREATE INDEX idx_sessions_gateway_revocable
    ON sessions (gateway_id, created_at, id)
    WHERE status IN ('running', 'revoking', 'revoke_failed', 'manual_intervention');

-- +goose Down
DROP INDEX IF EXISTS idx_sessions_gateway_revocable;
DROP INDEX IF EXISTS idx_outbox_active_session_revoke;
