-- +goose Up

-- Feishu can retry callbacks and the API runs with multiple replicas. Keep
-- the event identity in PostgreSQL so only one replica executes an approval
-- side effect at a time. A stale processing lease can be claimed again after
-- a process crash.
CREATE TABLE callback_events (
    event_id VARCHAR(256) PRIMARY KEY,
    status VARCHAR(32) NOT NULL CHECK (status IN ('processing', 'processed')),
    claimed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at TIMESTAMPTZ
);

CREATE INDEX idx_callback_events_processing_lease
    ON callback_events (status, claimed_at);

-- +goose Down
DROP TABLE IF EXISTS callback_events;
