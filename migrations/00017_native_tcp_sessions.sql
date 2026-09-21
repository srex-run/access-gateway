-- +goose Up
-- Preserve the wire protocol of existing sessions during rolling upgrades.
ALTER TABLE sessions ADD COLUMN connection_mode TEXT NOT NULL DEFAULT 'tunnel';
ALTER TABLE sessions ADD CONSTRAINT sessions_connection_mode_check
    CHECK (connection_mode IN ('direct', 'tunnel'));
ALTER TABLE sessions ADD CONSTRAINT sessions_direct_identity_check
    CHECK (connection_mode <> 'direct' OR (tunnel_client_public_key = '' AND tunnel_server_certificate = ''));

-- +goose Down
ALTER TABLE sessions DROP CONSTRAINT sessions_direct_identity_check,
    DROP CONSTRAINT sessions_connection_mode_check, DROP COLUMN connection_mode;
