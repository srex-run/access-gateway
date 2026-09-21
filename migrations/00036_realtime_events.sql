-- +goose Up
-- Notifications are delivered only after COMMIT. Payloads contain routing
-- metadata, never row contents, SQL, credentials or notification bodies.
-- +goose StatementBegin
CREATE FUNCTION access_gateway_emit(topic TEXT, recipient UUID DEFAULT NULL, permission TEXT DEFAULT NULL)
RETURNS VOID LANGUAGE SQL SET search_path FROM CURRENT AS $$
    SELECT pg_notify('access_gateway_changes', json_build_object(
        'schema', current_schema(), 'topic', topic, 'user_id', recipient, 'permission', permission
    )::text);
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION access_gateway_global_change() RETURNS TRIGGER
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    PERFORM access_gateway_emit(TG_ARGV[0], NULL, NULLIF(TG_ARGV[1], ''));
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION access_gateway_user_change() RETURNS TRIGGER
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE row_data JSONB;
BEGIN
    row_data := CASE WHEN TG_OP = 'DELETE' THEN to_jsonb(OLD) ELSE to_jsonb(NEW) END;
    PERFORM access_gateway_emit(TG_ARGV[0], (row_data ->> TG_ARGV[1])::uuid);
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION access_gateway_request_change() RETURNS TRIGGER
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE row_data JSONB; request_key UUID; recipient UUID;
BEGIN
    row_data := CASE WHEN TG_OP = 'DELETE' THEN to_jsonb(OLD) ELSE to_jsonb(NEW) END;
    IF TG_TABLE_NAME = 'access_requests' THEN
        request_key := (row_data ->> 'id')::uuid;
        PERFORM access_gateway_emit(TG_ARGV[0], (row_data ->> 'applicant_id')::uuid);
    ELSIF TG_TABLE_NAME IN ('approvals', 'sessions') THEN
        request_key := (row_data ->> 'request_id')::uuid;
        IF TG_TABLE_NAME = 'approvals' THEN
            PERFORM access_gateway_emit(TG_ARGV[0], (row_data ->> 'approver_id')::uuid);
        END IF;
    ELSE
        SELECT request_id INTO request_key FROM sessions WHERE id = (row_data ->> 'session_id')::uuid;
    END IF;
    FOR recipient IN
        SELECT applicant_id FROM access_requests WHERE id = request_key
        UNION SELECT approver_id FROM approvals WHERE request_id = request_key
    LOOP
        PERFORM access_gateway_emit(TG_ARGV[0], recipient);
    END LOOP;
    PERFORM access_gateway_emit(TG_ARGV[0], NULL, 'audit:read');
    IF TG_ARGV[0] = 'sessions' THEN
        PERFORM access_gateway_emit('sessions', NULL, 'session:override');
    END IF;
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER realtime_notifications AFTER INSERT OR UPDATE OR DELETE ON user_notifications
    FOR EACH ROW EXECUTE FUNCTION access_gateway_user_change('notifications', 'user_id');
CREATE TRIGGER realtime_requests AFTER INSERT OR UPDATE OR DELETE ON access_requests
    FOR EACH ROW EXECUTE FUNCTION access_gateway_request_change('requests');
CREATE TRIGGER realtime_approvals AFTER INSERT OR UPDATE OR DELETE ON approvals
    FOR EACH ROW EXECUTE FUNCTION access_gateway_request_change('requests');
CREATE TRIGGER realtime_sessions AFTER INSERT OR UPDATE OR DELETE ON sessions
    FOR EACH ROW EXECUTE FUNCTION access_gateway_request_change('sessions');
CREATE TRIGGER realtime_session_events AFTER INSERT OR UPDATE OR DELETE ON session_events
    FOR EACH ROW EXECUTE FUNCTION access_gateway_request_change('sessions');
CREATE TRIGGER realtime_connections AFTER INSERT OR UPDATE OR DELETE ON gateway_connection_events
    FOR EACH ROW EXECUTE FUNCTION access_gateway_request_change('sessions');
CREATE TRIGGER realtime_operations AFTER INSERT OR UPDATE OR DELETE ON operation_audit_events
    FOR EACH ROW EXECUTE FUNCTION access_gateway_request_change('sessions');

CREATE TRIGGER realtime_cloud_jobs AFTER INSERT OR UPDATE OR DELETE ON cloud_sync_jobs
    FOR EACH STATEMENT EXECUTE FUNCTION access_gateway_global_change('cloud', 'catalog:manage');
CREATE TRIGGER realtime_cloud_accounts AFTER INSERT OR UPDATE OR DELETE ON cloud_accounts
    FOR EACH STATEMENT EXECUTE FUNCTION access_gateway_global_change('cloud', 'catalog:manage');
CREATE TRIGGER realtime_settings AFTER INSERT OR UPDATE OR DELETE ON system_settings
    FOR EACH STATEMENT EXECUTE FUNCTION access_gateway_global_change('settings', '');
CREATE TRIGGER realtime_audit AFTER INSERT ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION access_gateway_global_change('audit', 'audit:read');
CREATE TRIGGER realtime_users AFTER UPDATE OR DELETE ON users
    FOR EACH ROW EXECUTE FUNCTION access_gateway_user_change('identity', 'id');
CREATE TRIGGER realtime_mfa AFTER INSERT OR UPDATE OR DELETE ON user_mfa
    FOR EACH ROW EXECUTE FUNCTION access_gateway_user_change('identity', 'user_id');

-- Catalog and policy changes also invalidate cached form options and permissions.
-- +goose StatementBegin
DO $$
DECLARE table_name TEXT;
BEGIN
    FOREACH table_name IN ARRAY ARRAY['regions', 'assets', 'asset_ports', 'asset_approvers', 'asset_gateway_bindings', 'asset_audit_configs', 'asset_labels', 'asset_ownerships', 'approval_workflows'] LOOP
        EXECUTE format('CREATE TRIGGER realtime_catalog AFTER INSERT OR UPDATE OR DELETE ON %I FOR EACH STATEMENT EXECUTE FUNCTION access_gateway_global_change(''catalog'', '''')', table_name);
    END LOOP;
    FOREACH table_name IN ARRAY ARRAY['iam_roles', 'iam_bindings', 'role_assignments'] LOOP
        EXECUTE format('CREATE TRIGGER realtime_identity AFTER INSERT OR UPDATE OR DELETE ON %I FOR EACH STATEMENT EXECUTE FUNCTION access_gateway_global_change(''identity'', '''')', table_name);
    END LOOP;
END;
$$;
-- +goose StatementEnd

-- +goose Down
DROP FUNCTION access_gateway_request_change() CASCADE;
DROP FUNCTION access_gateway_user_change() CASCADE;
DROP FUNCTION access_gateway_global_change() CASCADE;
DROP FUNCTION access_gateway_emit(TEXT, UUID, TEXT);
