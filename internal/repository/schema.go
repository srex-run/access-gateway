package repository

import (
	"context"
	"fmt"
)

type SchemaRepository struct{}

// FirstMissingMigration follows the connection's search_path, just like the
// application queries and migration runner. It never creates a version table.
func (r SchemaRepository) FirstMissingMigration(ctx context.Context, q DBTX, versions []int64) (int64, error) {
	if len(versions) == 0 {
		return 0, fmt.Errorf("required migration versions are empty")
	}
	const tableQuery = `SELECT to_regclass('goose_db_version') IS NOT NULL`
	var exists bool
	if err := q.QueryRowContext(ctx, tableQuery).Scan(&exists); err != nil {
		return 0, opError("check migration history table", err)
	}
	if !exists {
		return versions[0], nil
	}
	const versionQuery = `SELECT COALESCE(MIN(required.version_id), 0)
		FROM unnest($1::bigint[]) AS required(version_id)
		WHERE NOT COALESCE((
			SELECT history.is_applied FROM goose_db_version history
			WHERE history.version_id=required.version_id ORDER BY history.id DESC LIMIT 1
		), FALSE)`
	var missing int64
	err := q.QueryRowContext(ctx, versionQuery, versions).Scan(&missing)
	return missing, opError("check required database migrations", err)
}
