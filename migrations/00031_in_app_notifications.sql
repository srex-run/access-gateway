-- +goose Up
CREATE TABLE user_notifications (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    event_type VARCHAR(64) NOT NULL CHECK (event_type IN ('approval_requested', 'request_result', 'session_ready', 'session_closed')),
    dedupe_key VARCHAR(160) NOT NULL,
    title VARCHAR(160) NOT NULL,
    content VARCHAR(512) NOT NULL,
    request_id UUID NOT NULL REFERENCES access_requests(id),
    session_id UUID REFERENCES sessions(id),
    read_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (user_id, dedupe_key)
);
CREATE INDEX idx_user_notifications_inbox ON user_notifications (user_id, created_at DESC, id DESC);
CREATE INDEX idx_user_notifications_unread ON user_notifications (user_id) WHERE read_at IS NULL;

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
    RAISE EXCEPTION 'notification history must be retained; use a forward migration';
END $$;
-- +goose StatementEnd
