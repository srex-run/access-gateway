-- +goose Up
-- Serialize role classification and cleanup with normal IAM updates.
SELECT pg_advisory_xact_lock(742095120);

ALTER TABLE iam_roles DROP CONSTRAINT iam_roles_core_identity;

-- Keep the auditor's saved permissions, labels and enabled state. A previously
-- disabled custom auditor must not regain access merely by becoming built-in.
UPDATE iam_roles
SET built_in = (name IN ('admin', 'auditor', 'user')),
    revision = revision + 1,
    updated_at = NOW()
WHERE built_in IS DISTINCT FROM (name IN ('admin', 'auditor', 'user'));

INSERT INTO iam_roles (name, description, permissions, labels, built_in)
VALUES ('auditor', '审计员', '["directory:read","request:manage","approval:manage","session:manage","audit:read"]',
    '{"access-gateway.io/role":"auditor"}', TRUE)
ON CONFLICT (name) DO NOTHING;

ALTER TABLE iam_roles ADD CONSTRAINT iam_roles_core_identity
    CHECK (built_in = (name IN ('admin', 'auditor', 'user'))
        AND (name NOT IN ('admin', 'user') OR enabled));

-- Remove only untouched legacy defaults. Preserve even revoked direct grants
-- (their foreign keys are historical evidence), edited roles and disabled roles.
-- Existing bindings or custom/snapshotted workflows may refer to roles through
-- selectors, so conservatively retain legacy roles when those records exist.
WITH legacy_defaults (name, description, permissions, labels) AS (VALUES
    ('sre', '运维工程师',
        '["directory:read","request:manage","approval:manage","session:manage","catalog:manage","audit:read","user:read","workflow:manage"]'::jsonb,
        '{"access-gateway.io/role":"sre","access-gateway.io/approval":"platform"}'::jsonb),
    ('catalog_admin', '目录管理员',
        '["directory:read","request:manage","approval:manage","session:manage","catalog:manage","user:read"]'::jsonb,
        '{"access-gateway.io/role":"catalog_admin"}'::jsonb),
    ('security_admin', '安全管理员',
        '["directory:read","request:manage","approval:manage","session:manage","audit:read"]'::jsonb,
        '{"access-gateway.io/role":"security_admin"}'::jsonb)
)
DELETE FROM iam_roles AS r USING legacy_defaults AS original
WHERE r.name = original.name AND NOT r.built_in AND r.enabled AND r.revision = 2
    AND r.description = original.description AND r.permissions = original.permissions AND r.labels = original.labels
    AND NOT EXISTS (SELECT 1 FROM role_assignments assignment WHERE assignment.role = r.name)
    AND NOT EXISTS (SELECT 1 FROM iam_bindings)
    AND NOT EXISTS (SELECT 1 FROM approval_workflows WHERE NOT built_in)
    AND NOT EXISTS (SELECT 1 FROM access_requests WHERE workflow_snapshot IS NOT NULL);

UPDATE approval_workflows
SET description = '负责人通过后，由平台审批角色处理；申请人不能自批。',
    revision = revision + 1,
    updated_at = NOW()
WHERE id = '00000000-0000-4000-8000-000000000020' AND built_in
    AND description = '负责人通过后，由 admin 或 sre 审批；申请人不能自批。';

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
    RAISE EXCEPTION 'built-in role cleanup requires a forward migration; saved permissions and grants must be retained';
END $$;
-- +goose StatementEnd
