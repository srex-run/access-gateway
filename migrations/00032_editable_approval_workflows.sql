-- +goose Up
UPDATE approval_workflows
SET built_in = FALSE,
    revision = revision + 1,
    updated_at = NOW()
WHERE built_in;

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
    RAISE EXCEPTION 'editable approval workflows require a forward migration; saved workflow changes must be retained';
END $$;
-- +goose StatementEnd
