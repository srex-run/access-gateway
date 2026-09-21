-- +goose Up
-- Ordinary accounts must receive an explicit approval-capable role to approve.
UPDATE iam_roles
SET permissions = permissions - 'approval:manage',
    revision = revision + 1,
    updated_at = NOW()
WHERE name = 'user' AND built_in AND permissions ? 'approval:manage';

-- +goose Down
UPDATE iam_roles
SET permissions = permissions || '["approval:manage"]'::jsonb,
    revision = revision + 1,
    updated_at = NOW()
WHERE name = 'user' AND built_in AND NOT (permissions ? 'approval:manage');
