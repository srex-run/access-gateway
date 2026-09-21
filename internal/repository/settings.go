package repository

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

type SystemSettings struct {
	ConfigJSON        json.RawMessage
	SecretsCiphertext string
	Revision          int64
	UpdatedAt         time.Time
	UpdatedBy         string
}

type SystemSettingsRepository struct{}

func (*SystemSettingsRepository) Get(ctx context.Context, q DBTX) (SystemSettings, error) {
	const query = `SELECT config_json, secrets_ciphertext, revision, updated_at, updated_by FROM system_settings WHERE singleton = TRUE`
	value, err := scanSystemSettings(q.QueryRowContext(ctx, query))
	return value, opError("get system settings", err)
}

func (*SystemSettingsRepository) Lock(ctx context.Context, q DBTX) error {
	const query = `SELECT pg_advisory_xact_lock(hashtextextended('system-settings', 0))`
	_, err := q.ExecContext(ctx, query)
	return opError("lock system settings", err)
}

func (*SystemSettingsRepository) Save(ctx context.Context, q DBTX, value SystemSettings, expected int64) (SystemSettings, error) {
	const query = `INSERT INTO system_settings(singleton, config_json, secrets_ciphertext, revision, updated_by)
		SELECT TRUE, $1, $2, 1, $4 WHERE $3::bigint = 0 OR EXISTS (SELECT 1 FROM system_settings WHERE singleton = TRUE AND revision = $3)
		ON CONFLICT (singleton) DO UPDATE SET config_json = EXCLUDED.config_json, secrets_ciphertext = EXCLUDED.secrets_ciphertext,
		revision = system_settings.revision + 1, updated_at = NOW(), updated_by = EXCLUDED.updated_by
		WHERE system_settings.revision = $3
		RETURNING config_json, secrets_ciphertext, revision, updated_at, updated_by`
	result, err := scanSystemSettings(q.QueryRowContext(ctx, query, []byte(value.ConfigJSON), value.SecretsCiphertext, expected, value.UpdatedBy))
	if errors.Is(err, ErrNotFound) {
		return SystemSettings{}, ErrConflict
	}
	return result, opError("save system settings", err)
}

func (*SystemSettingsRepository) HasFeishuBindings(ctx context.Context, q DBTX) (bool, error) {
	const query = `SELECT EXISTS(SELECT 1 FROM users WHERE feishu_open_id IS NOT NULL)`
	value, err := scanLockAcquired(q.QueryRowContext(ctx, query))
	return value, opError("check Feishu bindings", err)
}
