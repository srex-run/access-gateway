-- +goose Up
CREATE TABLE browser_transport_keys (
    id UUID PRIMARY KEY,
    public_key TEXT NOT NULL,
    private_key_ciphertext TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '24 hours'
);
CREATE INDEX idx_browser_transport_keys_expiry ON browser_transport_keys (expires_at, id);

CREATE TABLE browser_transport_challenges (
    id UUID PRIMARY KEY,
    key_id UUID NOT NULL REFERENCES browser_transport_keys(id),
    method VARCHAR(8) NOT NULL,
    path VARCHAR(512) NOT NULL,
    subject VARCHAR(256) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '2 minutes'
);
CREATE INDEX idx_browser_transport_challenges_expiry ON browser_transport_challenges (expires_at, id);
CREATE INDEX idx_browser_transport_challenges_key ON browser_transport_challenges (key_id);

-- +goose Down
DROP TABLE browser_transport_challenges;
DROP TABLE browser_transport_keys;
