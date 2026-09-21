-- +goose Up
ALTER TABLE sessions DROP CONSTRAINT sessions_connection_mode_check;
ALTER TABLE sessions ADD CONSTRAINT sessions_connection_mode_check
    CHECK (connection_mode IN ('direct', 'tunnel', 'native'));
ALTER TABLE sessions ADD CONSTRAINT sessions_native_identity_check
    CHECK (connection_mode <> 'native' OR (tunnel_client_public_key = '' AND tunnel_server_certificate = ''));

-- +goose Down
ALTER TABLE sessions DROP CONSTRAINT sessions_native_identity_check;
ALTER TABLE sessions DROP CONSTRAINT sessions_connection_mode_check;
-- Deliberately fails while native session records exist; never downgrade them.
ALTER TABLE sessions ADD CONSTRAINT sessions_connection_mode_check
    CHECK (connection_mode IN ('direct', 'tunnel'));
