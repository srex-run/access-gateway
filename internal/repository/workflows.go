package repository

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/srex-run/access-gateway/internal/approvalflow"
	"github.com/srex-run/access-gateway/internal/label"
)

type WorkflowRepository struct{}

func (r WorkflowRepository) List(ctx context.Context, q DBTX) ([]approvalflow.Definition, error) {
	const query = `SELECT ` + workflowColumns + ` FROM approval_workflows ORDER BY created_at, id LIMIT 1001`
	rows, err := q.QueryContext(ctx, query)
	if err != nil {
		return nil, opError("list approval workflows", err)
	}
	values, err := CollectRows(rows, scanWorkflow)
	return values, opError("list approval workflows", err)
}

func (r WorkflowRepository) Save(ctx context.Context, q DBTX, v approvalflow.Definition) (approvalflow.Definition, error) {
	steps, err := json.Marshal(v.Steps)
	if err != nil {
		return v, opError("encode approval steps", err)
	}
	labels, err := json.Marshal(v.Labels)
	if err != nil {
		return v, opError("encode workflow labels", err)
	}
	const create = `INSERT INTO approval_workflows (id, name, description, labels, asset_selector, timeout_seconds, steps, enabled)
		SELECT $1,$2,$3,$4,$5,$6,$7,$8 WHERE $9::bigint=0 ON CONFLICT DO NOTHING RETURNING ` + workflowColumns
	const update = `UPDATE approval_workflows SET name=$2, description=$3, labels=$4, asset_selector=$5, timeout_seconds=$6, steps=$7, enabled=$8, built_in=FALSE, revision=revision+1, updated_at=NOW()
		WHERE id=$1 AND revision=$9 RETURNING ` + workflowColumns
	query := create
	if v.Revision > 0 {
		query = update
	}
	value, err := scanWorkflow(q.QueryRowContext(ctx, query, v.ID, v.Name, v.Description, labels, v.AssetSelector, v.TimeoutSeconds, steps, v.Enabled, v.Revision))
	return value, opError("save approval workflow", err)
}

func (r WorkflowRepository) ListOwnerships(ctx context.Context, q DBTX) ([]approvalflow.Ownership, error) {
	const query = `SELECT ` + ownershipColumns + ` FROM asset_ownerships ORDER BY created_at, id LIMIT 1001`
	rows, err := q.QueryContext(ctx, query)
	if err != nil {
		return nil, opError("list asset ownership rules", err)
	}
	values, err := CollectRows(rows, scanOwnership)
	return values, opError("list asset ownership rules", err)
}

func (r WorkflowRepository) SaveOwnership(ctx context.Context, q DBTX, v approvalflow.Ownership) (approvalflow.Ownership, error) {
	const create = `INSERT INTO asset_ownerships (id, name, asset_selector, user_selector, enabled)
		SELECT $1,$2,$3,$4,$5 WHERE $6::bigint=0 ON CONFLICT DO NOTHING RETURNING ` + ownershipColumns
	const update = `UPDATE asset_ownerships SET name=$2, asset_selector=$3, user_selector=$4, enabled=$5, revision=revision+1, updated_at=NOW()
		WHERE id=$1 AND revision=$6 RETURNING ` + ownershipColumns
	query := create
	if v.Revision > 0 {
		query = update
	}
	value, err := scanOwnership(q.QueryRowContext(ctx, query, v.ID, v.Name, v.AssetSelector, v.UserSelector, v.Enabled, v.Revision))
	return value, opError("save asset ownership rule", err)
}

func (r WorkflowRepository) AssetPolicy(ctx context.Context, q DBTX, assetID string) (approvalflow.AssetPolicy, error) {
	const query = `SELECT ` + assetPolicyColumns + ` FROM asset_labels WHERE asset_id=$1`
	value, err := scanAssetPolicy(q.QueryRowContext(ctx, query, assetID))
	if errors.Is(err, ErrNotFound) {
		return approvalflow.AssetPolicy{AssetID: assetID, Labels: label.Labels{}}, nil
	}
	return value, opError("read asset labels", err)
}

func (r WorkflowRepository) SaveAssetPolicy(ctx context.Context, q DBTX, v approvalflow.AssetPolicy) (approvalflow.AssetPolicy, error) {
	labels, err := json.Marshal(v.Labels)
	if err != nil {
		return v, opError("encode asset labels", err)
	}
	// assets_default_audit_profile pre-creates this row with defaults_only=TRUE,
	// so a first explicit save claims that generated row at revision 1 instead
	// of inserting. A row that already holds configuration stays untouched and
	// is reported to the caller as a revision conflict.
	const create = `INSERT INTO asset_labels (asset_id, labels) SELECT $1,$2 WHERE $3::bigint=0
		ON CONFLICT (asset_id) DO UPDATE SET labels=EXCLUDED.labels, defaults_only=FALSE, updated_at=NOW()
		WHERE asset_labels.defaults_only RETURNING ` + assetPolicyColumns
	const update = `UPDATE asset_labels SET labels=$2, defaults_only=FALSE, revision=revision+1, updated_at=NOW() WHERE asset_id=$1 AND revision=$3 RETURNING ` + assetPolicyColumns
	query := create
	if v.Revision > 0 {
		query = update
	}
	value, err := scanAssetPolicy(q.QueryRowContext(ctx, query, v.AssetID, labels, v.Revision))
	return value, opError("save asset labels", err)
}
