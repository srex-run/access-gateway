package service

import (
	"context"
	"fmt"

	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/migrations"
)

// CheckDatabaseSchema fails before the HTTP server or workers can use an older
// schema. Schema changes remain the migration command's responsibility.
func CheckDatabaseSchema(ctx context.Context, q repository.DBTX) error {
	versions, err := migrations.Versions()
	if err != nil {
		return err
	}
	missing, err := (repository.SchemaRepository{}).FirstMissingMigration(ctx, q, versions)
	if err != nil {
		return err
	}
	if missing != 0 {
		return fmt.Errorf("database schema is missing migration %05d (application requires %05d); run make dev-migrate locally or migrate up in your deployment using the same DATABASE_URL/DATABASE_URL_FILE and search_path, then restart access-gateway", missing, versions[len(versions)-1])
	}
	return nil
}
