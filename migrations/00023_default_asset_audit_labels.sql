-- +goose Up
-- Every asset creation path (manual, CMDB and cloud import) uses this default.
-- Track generated defaults separately from explicit approval configuration.
ALTER TABLE asset_labels ADD COLUMN defaults_only BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE asset_labels ALTER COLUMN labels SET DEFAULT
    '{"security.access-gateway.io/audit-profile":"auto"}'::jsonb;

-- Empty / deleted references mean automatic selection, never disabling audit.
-- +goose StatementBegin
CREATE FUNCTION ensure_asset_audit_profile() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF COALESCE(NEW.labels->>'security.access-gateway.io/audit-profile', '') = '' THEN
        NEW.labels := jsonb_set(COALESCE(NEW.labels, '{}'::jsonb),
            '{security.access-gateway.io/audit-profile}', '"auto"'::jsonb);
    END IF;
    IF NEW.labels <> '{"security.access-gateway.io/audit-profile":"auto"}'::jsonb THEN
        NEW.defaults_only := FALSE;
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER asset_labels_default_audit_profile
    BEFORE INSERT OR UPDATE OF labels ON asset_labels
    FOR EACH ROW EXECUTE FUNCTION ensure_asset_audit_profile();

INSERT INTO asset_labels (asset_id, defaults_only)
    SELECT id, TRUE FROM assets
    ON CONFLICT (asset_id) DO UPDATE
    SET labels = jsonb_set(asset_labels.labels,
            '{security.access-gateway.io/audit-profile}', '"auto"'::jsonb),
        revision = asset_labels.revision + 1, updated_at = NOW()
    WHERE COALESCE(asset_labels.labels->>'security.access-gateway.io/audit-profile', '') = '';

-- +goose StatementBegin
CREATE FUNCTION initialize_asset_audit_profile() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO asset_labels (asset_id, defaults_only) VALUES (NEW.id, TRUE) ON CONFLICT DO NOTHING;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER assets_default_audit_profile
    AFTER INSERT ON assets
    FOR EACH ROW EXECUTE FUNCTION initialize_asset_audit_profile();

-- +goose Down
DROP TRIGGER assets_default_audit_profile ON assets;
DROP FUNCTION initialize_asset_audit_profile();
DROP TRIGGER asset_labels_default_audit_profile ON asset_labels;
DROP FUNCTION ensure_asset_audit_profile();
ALTER TABLE asset_labels ALTER COLUMN labels SET DEFAULT '{}'::jsonb;
ALTER TABLE asset_labels DROP COLUMN defaults_only;
-- Keep existing labels and policy revisions, including explicitly selected profiles.
