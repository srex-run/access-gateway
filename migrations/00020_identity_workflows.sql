-- +goose Up
ALTER TABLE users ADD COLUMN labels JSONB NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(labels) = 'object');
ALTER TABLE users ADD COLUMN revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0);

CREATE TABLE iam_roles (
    name VARCHAR(64) PRIMARY KEY CHECK (name ~ '^[a-z][a-z0-9_-]{1,62}$'),
    description VARCHAR(512) NOT NULL DEFAULT '',
    permissions JSONB NOT NULL CHECK (jsonb_typeof(permissions) = 'array'),
    labels JSONB NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(labels) = 'object'),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    built_in BOOLEAN NOT NULL DEFAULT FALSE,
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (name <> 'admin' OR (enabled AND built_in))
);
INSERT INTO iam_roles (name, description, permissions, labels, built_in) VALUES
('user', '普通用户', '["directory:read","request:manage","approval:manage","session:manage"]', '{"access-gateway.io/role":"user"}', TRUE),
('admin', '平台管理员', '["directory:read","request:manage","approval:manage","session:manage","catalog:manage","audit:read","session:override","role:manage","user:read","user:manage","workflow:manage"]', '{"access-gateway.io/role":"admin","access-gateway.io/approval":"platform"}', TRUE),
('sre', '运维工程师', '["directory:read","request:manage","approval:manage","session:manage","catalog:manage","audit:read","session:override","user:read","workflow:manage"]', '{"access-gateway.io/role":"sre","access-gateway.io/approval":"platform"}', TRUE),
('catalog_admin', '目录管理员', '["directory:read","request:manage","approval:manage","session:manage","catalog:manage","user:read"]', '{"access-gateway.io/role":"catalog_admin"}', TRUE),
('auditor', '审计员', '["directory:read","request:manage","approval:manage","session:manage","audit:read"]', '{"access-gateway.io/role":"auditor"}', TRUE),
('security_admin', '安全管理员', '["directory:read","request:manage","approval:manage","session:manage","audit:read","session:override"]', '{"access-gateway.io/role":"security_admin"}', TRUE);
ALTER TABLE role_assignments DROP CONSTRAINT role_assignments_role_check;
ALTER TABLE role_assignments ADD CONSTRAINT role_assignments_role_fk FOREIGN KEY (role) REFERENCES iam_roles(name);

CREATE TABLE iam_bindings (
    id UUID PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    user_selector VARCHAR(1024) NOT NULL CHECK (length(btrim(user_selector)) > 0),
    role_selector VARCHAR(1024) NOT NULL CHECK (length(btrim(role_selector)) > 0),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE asset_labels (
    asset_id UUID PRIMARY KEY REFERENCES assets(id),
    labels JSONB NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(labels) = 'object'),
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE asset_ownerships (
    id UUID PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    asset_selector VARCHAR(1024) NOT NULL CHECK (length(btrim(asset_selector)) > 0),
    user_selector VARCHAR(1024) NOT NULL CHECK (length(btrim(user_selector)) > 0),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE approval_workflows (
    id UUID PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    description VARCHAR(512) NOT NULL DEFAULT '',
    labels JSONB NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(labels) = 'object'),
    asset_selector VARCHAR(1024) NOT NULL CHECK (length(btrim(asset_selector)) > 0),
    timeout_seconds INTEGER NOT NULL CHECK (timeout_seconds BETWEEN 60 AND 604800),
    steps JSONB NOT NULL CHECK (jsonb_typeof(steps) = 'array' AND jsonb_array_length(steps) BETWEEN 1 AND 10),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    built_in BOOLEAN NOT NULL DEFAULT FALSE,
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO approval_workflows (id, name, description, labels, asset_selector, timeout_seconds, steps, built_in)
VALUES ('00000000-0000-4000-8000-000000000020', '负责人及平台审批', '负责人通过后，由 admin 或 sre 审批；申请人不能自批。',
    '{"template":"owner-platform"}', 'approval=owner-platform', 86400,
    '[{"name":"资源负责人","kind":"owners","mode":"any","selector":""},{"name":"平台运维","kind":"role_selector","mode":"any","selector":"access-gateway.io/approval=platform"}]', TRUE);

ALTER TABLE access_requests ADD COLUMN workflow_snapshot JSONB CHECK (workflow_snapshot IS NULL OR jsonb_typeof(workflow_snapshot) = 'object');
ALTER TABLE access_requests ADD COLUMN approval_expires_at TIMESTAMPTZ;
ALTER TABLE approvals ADD COLUMN required_approvals INTEGER NOT NULL DEFAULT 1 CHECK (required_approvals BETWEEN 1 AND 100);
ALTER TABLE approvals ADD COLUMN step_name VARCHAR(128) NOT NULL DEFAULT '';
CREATE INDEX idx_requests_approval_deadline ON access_requests (approval_expires_at, id) WHERE status = 'pending_approval';
CREATE INDEX idx_approvals_level_decision ON approvals (request_id, approval_level, decision);

-- +goose Down
-- Refuse destructive rollback; a down/up cycle must not destroy approval evidence.
-- +goose StatementBegin
DO $$ BEGIN
    RAISE EXCEPTION 'identity/workflow migration requires a forward migration; approval snapshots must be retained';
END $$;
-- +goose StatementEnd
