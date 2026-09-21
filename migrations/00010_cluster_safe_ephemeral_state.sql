-- +goose Up
CREATE TABLE session_token_deliveries (
    session_id UUID PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
    token_ciphertext TEXT NOT NULL CHECK (length(token_ciphertext) BETWEEN 32 AND 8192),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_session_token_deliveries_expires
    ON session_token_deliveries (expires_at, session_id);

CREATE TABLE oauth_states (
    state_hash VARCHAR(64) PRIMARY KEY CHECK (length(state_hash) = 64),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_oauth_states_expires
    ON oauth_states (expires_at, state_hash);

-- +goose Down
DROP TABLE IF EXISTS oauth_states;
DROP TABLE IF EXISTS session_token_deliveries;
