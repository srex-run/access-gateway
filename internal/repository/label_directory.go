package repository

import (
	"context"

	"github.com/srex-run/access-gateway/internal/label"
)

type LabeledAsset struct {
	ID     string       `json:"id"`
	Name   string       `json:"name"`
	Labels label.Labels `json:"labels"`
}

// ListLabeledAssets includes unlabelled assets, since absence selectors match
// their empty label sets. The extra row detects directory overflow.
func (r WorkflowRepository) ListLabeledAssets(ctx context.Context, q DBTX) ([]LabeledAsset, error) {
	const query = `SELECT a.id, a.name, COALESCE(l.labels, '{}'::jsonb)
		FROM assets a JOIN regions r ON r.id=a.region_id
		LEFT JOIN asset_labels l ON l.asset_id=a.id
		WHERE a.status='enabled' AND r.status='enabled'
		ORDER BY a.name, a.id LIMIT 10001`
	rows, err := q.QueryContext(ctx, query)
	if err != nil {
		return nil, opError("list labeled assets", err)
	}
	values, err := CollectRows(rows, scanLabeledAsset)
	return values, opError("list labeled assets", err)
}
