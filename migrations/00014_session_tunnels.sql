-- +goose Up
-- Only public identity material is stored; private keys are derived in memory
-- from purpose-separated control-plane / Agent bootstrap keys.
ALTER TABLE sessions
    ADD COLUMN tunnel_client_public_key TEXT NOT NULL DEFAULT '',
    ADD COLUMN tunnel_server_certificate TEXT NOT NULL DEFAULT '',
    ADD CONSTRAINT sessions_tunnel_identity_pair CHECK (
        (tunnel_client_public_key = '' AND tunnel_server_certificate = '') OR
        (length(tunnel_client_public_key) = 44 AND length(tunnel_server_certificate) BETWEEN 1 AND 4096)
    );

ALTER TABLE gateway_connection_events DROP CONSTRAINT gateway_connection_events_event_type_check;
ALTER TABLE gateway_connection_events ADD CONSTRAINT gateway_connection_events_event_type_check
    CHECK (event_type IN ('connect_attempt', 'source_rejected', 'capacity_rejected', 'auth_rejected', 'backend_connected', 'backend_failed', 'disconnected'));

-- +goose Down
-- Retain the auth_rejected audit type so rollback never deletes audit history.
ALTER TABLE sessions DROP CONSTRAINT sessions_tunnel_identity_pair,
    DROP COLUMN tunnel_client_public_key, DROP COLUMN tunnel_server_certificate;
