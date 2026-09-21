-- +goose Up
CREATE TABLE installation_state (
    id BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
    initialized_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Existing installations keep their accounts and credentials unchanged.
INSERT INTO installation_state (id)
SELECT TRUE WHERE EXISTS (SELECT 1 FROM users);

-- +goose Down
DROP TABLE installation_state;
