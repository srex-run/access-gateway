-- +goose Up
-- Keep grants, selectors and role names intact while reducing built-in roles
-- to the administrator and the baseline user. The removed force-close key was
-- already ineffective for every role except the built-in administrator.
UPDATE iam_roles
SET built_in = FALSE,
    permissions = permissions - 'session:override',
    revision = revision + 1,
    updated_at = NOW()
WHERE built_in AND name NOT IN ('admin', 'user');

UPDATE iam_roles
SET permissions = permissions - 'session:override',
    revision = revision + 1,
    updated_at = NOW()
WHERE name <> 'admin' AND permissions ? 'session:override';

ALTER TABLE iam_roles ADD CONSTRAINT iam_roles_core_identity
    CHECK (built_in = (name IN ('admin', 'user')) AND (NOT built_in OR enabled));
ALTER TABLE iam_roles ADD CONSTRAINT iam_roles_admin_management
    CHECK (name <> 'admin' OR permissions @> '["role:manage"]'::jsonb);

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
    RAISE EXCEPTION 'editable built-in roles require a forward migration; saved permissions must be retained';
END $$;
-- +goose StatementEnd
