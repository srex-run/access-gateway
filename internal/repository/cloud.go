package repository

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/srex-run/access-gateway/internal/domain"
)

type CloudRepository struct{}

func (*CloudRepository) ListAccounts(ctx context.Context, q DBTX) ([]domain.CloudAccount, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+cloudAccountColumns+` FROM cloud_accounts ORDER BY name, id`)
	if err != nil {
		return nil, opError("list cloud accounts", err)
	}
	values, err := CollectRows(rows, scanCloudAccount)
	return values, opError("list cloud accounts", err)
}

func (*CloudRepository) GetAccount(ctx context.Context, q DBTX, accountID string, lock bool) (domain.CloudAccount, error) {
	query := `SELECT ` + cloudAccountColumns + ` FROM cloud_accounts WHERE id = $1`
	if lock {
		query += ` FOR UPDATE`
	}
	value, err := scanCloudAccount(q.QueryRowContext(ctx, query, accountID))
	return value, opError("get cloud account", err)
}

func (*CloudRepository) CreateAccount(ctx context.Context, q DBTX, value domain.CloudAccount) (domain.CloudAccount, error) {
	const query = `INSERT INTO cloud_accounts (id, name, provider, enabled, credentials_ciphertext)
		VALUES ($1, $2, $3, $4, $5) RETURNING ` + cloudAccountColumns
	value, err := scanCloudAccount(q.QueryRowContext(ctx, query, value.ID, value.Name, value.Provider, value.Enabled, value.CredentialsCiphertext))
	return value, opError("create cloud account", err)
}

func (*CloudRepository) UpdateAccount(ctx context.Context, q DBTX, value domain.CloudAccount) (domain.CloudAccount, error) {
	const query = `UPDATE cloud_accounts SET name = $2, enabled = $3, credentials_ciphertext = $4,
		revision = revision + 1, updated_at = NOW() WHERE id = $1 AND revision = $5
		RETURNING ` + cloudAccountColumns
	value, err := scanCloudAccount(q.QueryRowContext(ctx, query, value.ID, value.Name, value.Enabled, value.CredentialsCiphertext, value.Revision))
	if errors.Is(err, ErrNotFound) {
		return domain.CloudAccount{}, ErrConflict
	}
	return value, opError("update cloud account", err)
}

func (*CloudRepository) CreateJob(ctx context.Context, q DBTX, value domain.CloudSyncJob) (domain.CloudSyncJob, error) {
	input, err := json.Marshal(value.Input)
	if err != nil {
		return domain.CloudSyncJob{}, err
	}
	const query = `INSERT INTO cloud_sync_jobs (id, account_id, account_revision, actor_id, region_id, input_json, status)
		VALUES ($1, $2, $3, $4, $5, $6, 'queued') RETURNING ` + cloudSyncColumns
	value, err = scanCloudSyncJob(q.QueryRowContext(ctx, query, value.ID, value.AccountID, value.AccountRevision, value.ActorID, value.Input.RegionID, input))
	return value, opError("create cloud sync job", err)
}

func (*CloudRepository) ListJobs(ctx context.Context, q DBTX, regionID string) ([]domain.CloudSyncJob, error) {
	const query = `SELECT ` + cloudSyncColumns + ` FROM cloud_sync_jobs
		WHERE ($1::text = '' OR region_id::text = $1) ORDER BY created_at DESC, id DESC LIMIT 20`
	rows, err := q.QueryContext(ctx, query, regionID)
	if err != nil {
		return nil, opError("list cloud sync jobs", err)
	}
	values, err := CollectRows(rows, scanCloudSyncJob)
	return values, opError("list cloud sync jobs", err)
}

func (*CloudRepository) ClaimJob(ctx context.Context, q DBTX, token string) (domain.CloudSyncJob, error) {
	const query = `UPDATE cloud_sync_jobs SET status = 'running', lease_token = $1,
		lease_until = NOW() + INTERVAL '5 minutes', started_at = NOW()
		WHERE id = (SELECT id FROM cloud_sync_jobs WHERE status = 'queued'
			OR (status = 'running' AND lease_until < NOW())
			ORDER BY created_at, id FOR UPDATE SKIP LOCKED LIMIT 1)
		RETURNING ` + cloudSyncColumns
	value, err := scanCloudSyncJob(q.QueryRowContext(ctx, query, token))
	return value, opError("claim cloud sync job", err)
}

// LockJob fences an expired worker before it can apply a cloud snapshot.
func (*CloudRepository) LockJob(ctx context.Context, q DBTX, jobID, token string) error {
	const query = `SELECT ` + cloudSyncColumns + ` FROM cloud_sync_jobs
		WHERE id = $1 AND status = 'running' AND lease_token = $2 AND lease_until > NOW() FOR UPDATE`
	_, err := scanCloudSyncJob(q.QueryRowContext(ctx, query, jobID, token))
	return opError("lock cloud sync job", err)
}

func (*CloudRepository) FinishJob(ctx context.Context, q DBTX, value domain.CloudSyncJob) error {
	result, err := json.Marshal(value.Result)
	if err != nil {
		return err
	}
	const query = `UPDATE cloud_sync_jobs SET status = $3, result_json = $4, error = $5,
		lease_token = NULL, lease_until = NULL, finished_at = NOW()
		WHERE id = $1 AND status = 'running' AND lease_token = $2`
	updated, err := q.ExecContext(ctx, query, value.ID, value.LeaseToken, value.Status, result, value.Error)
	if err != nil {
		return opError("finish cloud sync job", err)
	}
	return affected("finish cloud sync job", updated)
}

// Only discovery-owned fields are updated. Access policy and routing stay local.
func (*CloudRepository) UpdateDiscoveredAsset(ctx context.Context, q DBTX, value domain.Asset) error {
	const query = `UPDATE assets SET name = $2, target_ciphertext = $3, sync_generation = $4,
		last_synced_at = NOW(), updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL`
	result, err := q.ExecContext(ctx, query, value.ID, value.Name, value.TargetCiphertext, value.SyncGeneration)
	if err != nil {
		return opError("update cloud asset", err)
	}
	return affected("update cloud asset", result)
}
