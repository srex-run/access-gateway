-- +goose Up
CREATE TABLE user_invitations (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash CHAR(64) NOT NULL UNIQUE,
    invited_by UUID NOT NULL REFERENCES users(id),
    expires_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    sent_at TIMESTAMPTZ,
    send_failures INTEGER NOT NULL DEFAULT 0 CHECK (send_failures >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX user_invitation_pending_idx ON user_invitations(user_id) WHERE accepted_at IS NULL AND revoked_at IS NULL;
CREATE INDEX user_invitations_created_idx ON user_invitations(created_at DESC, id);

CREATE TABLE user_mfa (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    secret_ciphertext BYTEA NOT NULL,
    last_step BIGINT NOT NULL CHECK (last_step >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE user_mfa_recovery_codes (
    user_id UUID NOT NULL REFERENCES user_mfa(user_id) ON DELETE CASCADE,
    code_hash CHAR(64) NOT NULL,
    PRIMARY KEY(user_id, code_hash)
);
CREATE TABLE mfa_challenges (
    token_hash CHAR(64) PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    auth_version BIGINT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('enroll', 'verify')),
    secret_ciphertext BYTEA,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '5 minutes',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX mfa_challenges_user_idx ON mfa_challenges(user_id);
CREATE INDEX mfa_challenges_expiry_idx ON mfa_challenges(expires_at);

-- +goose Down
DROP TABLE mfa_challenges;
DROP TABLE user_mfa_recovery_codes;
DROP TABLE user_mfa;
DROP TABLE user_invitations;
