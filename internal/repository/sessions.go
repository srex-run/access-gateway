package repository

import (
	"context"
	"time"

	"github.com/srex-run/access-gateway/internal/domain"
)

type SessionRepository struct{}

func NewSessionRepository() *SessionRepository {
	return &SessionRepository{}
}

func (r *SessionRepository) LockApplicantAssetPort(ctx context.Context, q DBTX, applicantID, assetID string, port int) error {
	const query = `
		SELECT pg_advisory_xact_lock(
			hashtextextended($1::text || ':' || $2::text || ':' || $3::integer::text, 0)
		) AS lock_result, TRUE AS locked`
	if err := scanAdvisoryLock(q.QueryRowContext(ctx, query, applicantID, assetID, port)); err != nil {
		return opError("lock applicant asset port", err)
	}
	return nil
}

func (r *SessionRepository) Create(ctx context.Context, q DBTX, value domain.Session) (domain.Session, error) {
	const query = `
		INSERT INTO sessions (id, request_id, gateway_id, status, version, connection_mode, audit_policy, expires_at)
		VALUES ($1, $2, $3, $4, $5, COALESCE(NULLIF($6, ''), 'tunnel'), jsonb_build_object('profile', $7::text, 'revision', $8::text, 'protocol', $9::text), $10)
		RETURNING ` + sessionColumns
	created, err := scanSession(q.QueryRowContext(ctx, query,
		value.ID,
		value.RequestID,
		value.GatewayID,
		value.Status,
		value.Version,
		value.ConnectionMode,
		value.AuditPolicy.Profile, value.AuditPolicy.Revision, value.AuditPolicy.Protocol,
		value.ExpiresAt,
	))
	if err != nil {
		return domain.Session{}, opError("create session", err)
	}
	return created, nil
}

func (r *SessionRepository) GetByID(ctx context.Context, q DBTX, id string) (domain.Session, error) {
	const query = `SELECT ` + sessionColumns + ` FROM sessions WHERE id = $1`
	value, err := scanSession(q.QueryRowContext(ctx, query, id))
	if err != nil {
		return domain.Session{}, opError("get session by id", err)
	}
	return value, nil
}

// GetByIDForUpdate reads and locks one session row for a state-machine
// decision.  Callers must use it only inside a service-owned transaction; the
// lock serializes cancellation/force-close with provisioning completion.
func (r *SessionRepository) GetByIDForUpdate(ctx context.Context, q DBTX, id string) (domain.Session, error) {
	const query = `SELECT ` + sessionColumns + ` FROM sessions WHERE id = $1 FOR UPDATE`
	value, err := scanSession(q.QueryRowContext(ctx, query, id))
	if err != nil {
		return domain.Session{}, opError("lock session by id", err)
	}
	return value, nil
}

func (r *SessionRepository) GetByRequestID(ctx context.Context, q DBTX, requestID string) (domain.Session, error) {
	const query = `SELECT ` + sessionColumns + ` FROM sessions WHERE request_id = $1 ORDER BY created_at DESC, id DESC LIMIT 1`
	value, err := scanSession(q.QueryRowContext(ctx, query, requestID))
	if err != nil {
		return domain.Session{}, opError("get session by request id", err)
	}
	return value, nil
}

// ClaimProvisioning grants one worker a bounded provisioning lease. Version
// zero is the initial unclaimed state; a stale non-zero claim can be taken
// over after a worker crash.
func (r *SessionRepository) ClaimProvisioning(ctx context.Context, q DBTX, id string, expectedVersion int, staleBefore time.Time) (domain.Session, error) {
	const query = `
		UPDATE sessions
		SET version = version + 1, updated_at = NOW()
		WHERE id = $1 AND status = 'provisioning' AND version = $2
		  AND (version = 0 OR updated_at <= $3)`
	result, err := q.ExecContext(ctx, query, id, expectedVersion, staleBefore)
	if err != nil {
		return domain.Session{}, opError("claim provisioning session", err)
	}
	if err := affected("claim provisioning session", result); err != nil {
		return domain.Session{}, err
	}
	value, err := r.GetByID(ctx, q, id)
	if err != nil {
		return domain.Session{}, opError("read claimed provisioning session", err)
	}
	return value, nil
}

// ClaimProvisioningOnGateway assigns and reserves a healthy bound gateway.
// The caller must first hold GatewayRepository.LockCapacity for gatewayID so
// concurrent claims observe the capacity consumed by earlier transactions.
func (r *SessionRepository) ClaimProvisioningOnGateway(ctx context.Context, q DBTX, id string, expectedVersion int, staleBefore time.Time, gatewayID, assetID string, heartbeatAfter *time.Time) (domain.Session, error) {
	const query = `
		UPDATE sessions AS target
		SET gateway_id = $4, version = version + 1, updated_at = NOW()
		WHERE target.id = $1
		  AND target.status = 'provisioning'
		  AND target.version = $2
		  AND (target.version = 0 OR target.updated_at <= $3)
		  AND EXISTS (
			SELECT 1
			FROM asset_gateway_bindings AS binding
			JOIN assets AS asset ON asset.id = binding.asset_id
			JOIN gateways AS candidate
			  ON candidate.id = binding.gateway_id
			 AND candidate.region_id = asset.region_id
			WHERE binding.asset_id = $5
			  AND binding.gateway_id = $4
			  AND binding.enabled = TRUE
			  AND asset.status = 'enabled'
			  AND candidate.status = 'enabled'
			  AND ($6::timestamptz IS NULL OR candidate.last_heartbeat_at >= $6)
			  AND (
				SELECT COUNT(*)
				FROM sessions AS active_session
				WHERE active_session.gateway_id = candidate.id
				  AND active_session.id <> target.id
				  AND (
					active_session.status IN ('running', 'revoking', 'revoke_failed', 'manual_intervention')
					OR (active_session.status = 'provisioning' AND active_session.version > 0)
				  )
			  ) < candidate.max_sessions
		  )`
	result, err := q.ExecContext(ctx, query, id, expectedVersion, staleBefore, gatewayID, assetID, heartbeatAfter)
	if err != nil {
		return domain.Session{}, opError("claim provisioning session on gateway", err)
	}
	if err := affected("claim provisioning session on gateway", result); err != nil {
		return domain.Session{}, err
	}
	value, err := r.GetByID(ctx, q, id)
	if err != nil {
		return domain.Session{}, opError("read gateway-assigned provisioning session", err)
	}
	return value, nil
}

// RenewProvisioningLease extends the lease without changing the optimistic
// version. A worker may renew only the exact attempt it originally claimed;
// once another worker takes over, the conditional update affects no rows.
func (r *SessionRepository) RenewProvisioningLease(ctx context.Context, q DBTX, id string, expectedVersion int) error {
	const query = `
		UPDATE sessions
		SET updated_at = NOW()
		WHERE id = $1 AND status = 'provisioning' AND version = $2`
	result, err := q.ExecContext(ctx, query, id, expectedVersion)
	if err != nil {
		return opError("renew provisioning session lease", err)
	}
	return affected("renew provisioning session lease", result)
}

func (r *SessionRepository) MarkRunning(ctx context.Context, q DBTX, id string, expectedVersion int, tokenHash, processID string, startedAt, expiresAt time.Time) (domain.Session, error) {
	const query = `
		UPDATE sessions
		SET token_hash = $2, remote_process_id = $3, status = 'running',
		    started_at = $4, expires_at = $5, version = version + 1, updated_at = NOW()
		WHERE id = $1 AND status = 'provisioning' AND version = $6`
	result, err := q.ExecContext(ctx, query, id, tokenHash, processID, startedAt, expiresAt, expectedVersion)
	if err != nil {
		return domain.Session{}, opError("mark session running", err)
	}
	if err := affected("mark session running", result); err != nil {
		return domain.Session{}, err
	}
	value, err := r.GetByID(ctx, q, id)
	if err != nil {
		return domain.Session{}, opError("read running session", err)
	}
	return value, nil
}

func (r *SessionRepository) MarkDirectRunning(ctx context.Context, q DBTX, id string, expectedVersion int, processID string, listenerPort, externalPort int, exposureMode, exposureRef string, startedAt, expiresAt time.Time, clientPublicKey, serverCertificate string) (domain.Session, error) {
	const query = `
		UPDATE sessions
		SET token_hash = NULL, remote_process_id = $2, status = 'running',
		    listener_port = $3, external_port = $4, exposure_mode = $5, exposure_ref = $6,
		    started_at = $7, expires_at = $8, version = version + 1, updated_at = NOW(),
		    tunnel_client_public_key = $10, tunnel_server_certificate = $11
		WHERE id = $1 AND status = 'provisioning' AND version = $9`
	result, err := q.ExecContext(ctx, query, id, processID, listenerPort, externalPort, exposureMode, exposureRef, startedAt, expiresAt, expectedVersion, clientPublicKey, serverCertificate)
	if err != nil {
		return domain.Session{}, opError("mark direct session running", err)
	}
	if err := affected("mark direct session running", result); err != nil {
		return domain.Session{}, err
	}
	value, err := r.GetByID(ctx, q, id)
	if err != nil {
		return domain.Session{}, opError("read direct running session", err)
	}
	return value, nil
}

func (r *SessionRepository) MarkProvisionFailed(ctx context.Context, q DBTX, id string, expectedVersion int, reason string) error {
	const query = `
		UPDATE sessions
		SET status = 'failed', failure_reason = $2, closed_at = NOW(), version = version + 1, updated_at = NOW()
		WHERE id = $1 AND status = 'provisioning' AND version = $3`
	result, err := q.ExecContext(ctx, query, id, reason, expectedVersion)
	if err != nil {
		return opError("mark session provisioning failed", err)
	}
	return affected("mark session provisioning failed", result)
}

// MarkProvisionRevokeFailed records that a provisioning attempt may have
// created a remote session but its compensation could not be confirmed. It is
// intentionally distinct from MarkProvisionFailed so the revoke worker can
// retry the gateway operation instead of treating the session as terminal.
func (r *SessionRepository) MarkProvisionRevokeFailed(ctx context.Context, q DBTX, id string, expectedVersion int, reason string) error {
	const query = `
		UPDATE sessions
		SET status = 'revoke_failed', failure_reason = $2, version = version + 1, updated_at = NOW()
		WHERE id = $1 AND status = 'provisioning' AND version = $3`
	result, err := q.ExecContext(ctx, query, id, reason, expectedVersion)
	if err != nil {
		return opError("mark provisioning revoke failed", err)
	}
	return affected("mark provisioning revoke failed", result)
}

func (r *SessionRepository) MarkRuntimeTerminated(ctx context.Context, q DBTX, id string, status domain.SessionStatus, reason *string) (domain.Session, error) {
	if status != domain.SessionExpired && status != domain.SessionFailed {
		return domain.Session{}, opError("mark runtime session terminated", ErrConstraint)
	}
	const query = `
		UPDATE sessions
		SET status = $2, closed_at = NOW(), failure_reason = $3,
		    version = version + 1, updated_at = NOW()
		WHERE id = $1 AND status = 'running'`
	result, err := q.ExecContext(ctx, query, id, status, reason)
	if err != nil {
		return domain.Session{}, opError("mark runtime session terminated", err)
	}
	if err := affected("mark runtime session terminated", result); err != nil {
		return domain.Session{}, err
	}
	value, err := r.GetByID(ctx, q, id)
	if err != nil {
		return domain.Session{}, opError("read terminated runtime session", err)
	}
	return value, nil
}

func (r *SessionRepository) BeginRevoke(ctx context.Context, q DBTX, id string) (domain.Session, error) {
	const query = `
		UPDATE sessions
		SET status = 'revoking', version = version + 1, updated_at = NOW()
			WHERE id = $1 AND status IN ('running', 'revoke_failed', 'manual_intervention')`
	result, err := q.ExecContext(ctx, query, id)
	if err != nil {
		return domain.Session{}, opError("begin session revoke", err)
	}
	if err := affected("begin session revoke", result); err != nil {
		return domain.Session{}, err
	}
	value, err := r.GetByID(ctx, q, id)
	if err != nil {
		return domain.Session{}, opError("read revoking session", err)
	}
	return value, nil
}

func (r *SessionRepository) MarkClosed(ctx context.Context, q DBTX, id string, status domain.SessionStatus) error {
	if status != domain.SessionClosed && status != domain.SessionExpired {
		return opError("mark session closed", ErrConstraint)
	}
	const query = `
		UPDATE sessions
		SET status = $2, closed_at = NOW(), version = version + 1, updated_at = NOW()
		WHERE id = $1 AND status = 'revoking'`
	result, err := q.ExecContext(ctx, query, id, status)
	if err != nil {
		return opError("mark session closed", err)
	}
	return affected("mark session closed", result)
}

func (r *SessionRepository) MarkRevokeFailed(ctx context.Context, q DBTX, id string, reason string) error {
	const query = `
		UPDATE sessions
		SET status = 'revoke_failed', failure_reason = $2, version = version + 1, updated_at = NOW()
		WHERE id = $1 AND status = 'revoking'`
	result, err := q.ExecContext(ctx, query, id, reason)
	if err != nil {
		return opError("mark session revoke failed", err)
	}
	return affected("mark session revoke failed", result)
}

func (r *SessionRepository) MarkManualIntervention(ctx context.Context, q DBTX, id string, reason string) error {
	const query = `
		UPDATE sessions
		SET status = 'manual_intervention', failure_reason = $2,
		    version = version + 1, updated_at = NOW()
		WHERE id = $1 AND status IN ('revoking', 'revoke_failed')`
	result, err := q.ExecContext(ctx, query, id, reason)
	if err != nil {
		return opError("mark session manual intervention", err)
	}
	return affected("mark session manual intervention", result)
}

func (r *SessionRepository) ListExpired(ctx context.Context, q DBTX, limit int) ([]domain.Session, error) {
	const maxPageSize = 500
	if limit < 1 || limit > maxPageSize {
		limit = maxPageSize
	}
	const query = `
		SELECT ` + sessionColumns + `
		FROM sessions
		WHERE status = 'running' AND expires_at <= NOW()
		ORDER BY expires_at NULLS FIRST, id
		LIMIT $1`
	rows, err := q.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, opError("list expired sessions", err)
	}
	values, err := CollectRows(rows, scanSession)
	if err != nil {
		return nil, opError("list expired sessions", err)
	}
	return values, nil
}

// ListProvisioning returns sessions whose provisioning task may have been
// lost during a control-plane restart. ProvisionSession is idempotent on the
// provisioning state, so re-enqueueing these rows is safe.
func (r *SessionRepository) ListProvisioning(ctx context.Context, q DBTX, limit int) ([]domain.Session, error) {
	const maxPageSize = 500
	if limit < 1 || limit > maxPageSize {
		limit = maxPageSize
	}
	const query = `
		SELECT ` + sessionColumnsQualified + `
		FROM sessions s
		JOIN access_requests ar ON ar.id = s.request_id
		WHERE s.status = 'provisioning'
		ORDER BY s.created_at, s.id
		LIMIT $1`
	rows, err := q.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, opError("list provisioning sessions", err)
	}
	values, err := CollectRows(rows, scanSession)
	if err != nil {
		return nil, opError("list provisioning sessions", err)
	}
	return values, nil
}

func (r *SessionRepository) FindActiveByApplicantAssetPort(ctx context.Context, q DBTX, applicantID, assetID string, port int) (domain.Session, error) {
	const query = `
		SELECT ` + sessionColumnsQualified + `
		FROM sessions s
		JOIN access_requests ar ON ar.id = s.request_id
		WHERE ar.applicant_id = $1 AND ar.asset_id = $2 AND ar.target_port = $3
		  AND s.status IN ('provisioning', 'running', 'revoking', 'revoke_failed', 'manual_intervention')
		ORDER BY s.created_at DESC, s.id DESC
		LIMIT 1`
	value, err := scanSession(q.QueryRowContext(ctx, query, applicantID, assetID, port))
	if err != nil {
		return domain.Session{}, opError("find active session", err)
	}
	return value, nil
}

func (r *SessionRepository) ListRevocationsToQueueByApplicant(ctx context.Context, q DBTX, applicantID string, limit int) ([]domain.Session, error) {
	const maxPageSize = 500
	if limit < 1 || limit > maxPageSize {
		limit = maxPageSize
	}
	const query = `
		SELECT ` + sessionColumnsQualified + `
		FROM sessions s
		JOIN access_requests ar ON ar.id = s.request_id
		WHERE ar.applicant_id = $1
		  AND s.status IN ('running', 'revoking', 'revoke_failed', 'manual_intervention')
		  AND NOT EXISTS (
			SELECT 1 FROM outbox_events queued
			WHERE queued.aggregate_type = 'session'
			  AND queued.aggregate_id = s.id
			  AND queued.event_type = 'session.revoke'
			  AND queued.status IN ('pending', 'processing')
		  )
		ORDER BY s.created_at, s.id
		LIMIT $2`
	rows, err := q.QueryContext(ctx, query, applicantID, limit)
	if err != nil {
		return nil, opError("list revocable applicant sessions", err)
	}
	values, err := CollectRows(rows, scanSession)
	if err != nil {
		return nil, opError("list revocable applicant sessions", err)
	}
	return values, nil
}

func (r *SessionRepository) ListRevocationsToQueueByAsset(ctx context.Context, q DBTX, assetID string, limit int) ([]domain.Session, error) {
	const maxPageSize = 500
	if limit < 1 || limit > maxPageSize {
		limit = maxPageSize
	}
	const query = `
		SELECT ` + sessionColumnsQualified + `
		FROM sessions s
		JOIN access_requests ar ON ar.id = s.request_id
		WHERE ar.asset_id = $1
		  AND s.status IN ('running', 'revoking', 'revoke_failed', 'manual_intervention')
		  AND NOT EXISTS (
			SELECT 1 FROM outbox_events queued
			WHERE queued.aggregate_type = 'session'
			  AND queued.aggregate_id = s.id
			  AND queued.event_type = 'session.revoke'
			  AND queued.status IN ('pending', 'processing')
		  )
		ORDER BY s.created_at, s.id
		LIMIT $2`
	rows, err := q.QueryContext(ctx, query, assetID, limit)
	if err != nil {
		return nil, opError("list revocable asset sessions", err)
	}
	values, err := CollectRows(rows, scanSession)
	if err != nil {
		return nil, opError("list revocable asset sessions", err)
	}
	return values, nil
}

func (r *SessionRepository) ListRevocationsToQueueByGateway(ctx context.Context, q DBTX, gatewayID string, limit int) ([]domain.Session, error) {
	const maxPageSize = 500
	if limit < 1 || limit > maxPageSize {
		limit = maxPageSize
	}
	const query = `
		SELECT ` + sessionColumnsQualified + `
		FROM sessions s
		WHERE s.gateway_id = $1
		  AND s.status IN ('running', 'revoking', 'revoke_failed', 'manual_intervention')
		  AND NOT EXISTS (
			SELECT 1 FROM outbox_events queued
			WHERE queued.aggregate_type = 'session'
			  AND queued.aggregate_id = s.id
			  AND queued.event_type = 'session.revoke'
			  AND queued.status IN ('pending', 'processing')
		  )
		ORDER BY s.created_at, s.id
		LIMIT $2`
	rows, err := q.QueryContext(ctx, query, gatewayID, limit)
	if err != nil {
		return nil, opError("list revocable gateway sessions", err)
	}
	values, err := CollectRows(rows, scanSession)
	if err != nil {
		return nil, opError("list revocable gateway sessions", err)
	}
	return values, nil
}

func (r *SessionRepository) ListRevocationsToQueueByRegion(ctx context.Context, q DBTX, regionID string, limit int) ([]domain.Session, error) {
	const maxPageSize = 500
	if limit < 1 || limit > maxPageSize {
		limit = maxPageSize
	}
	const query = `
		SELECT ` + sessionColumnsQualified + `
		FROM sessions s
		JOIN access_requests ar ON ar.id = s.request_id
		JOIN assets a ON a.id = ar.asset_id
		WHERE a.region_id = $1
		  AND s.status IN ('running', 'revoking', 'revoke_failed', 'manual_intervention')
		  AND NOT EXISTS (
			SELECT 1 FROM outbox_events queued
			WHERE queued.aggregate_type = 'session'
			  AND queued.aggregate_id = s.id
			  AND queued.event_type = 'session.revoke'
			  AND queued.status IN ('pending', 'processing')
		  )
		ORDER BY s.created_at, s.id
		LIMIT $2`
	rows, err := q.QueryContext(ctx, query, regionID, limit)
	if err != nil {
		return nil, opError("list revocable region sessions", err)
	}
	values, err := CollectRows(rows, scanSession)
	if err != nil {
		return nil, opError("list revocable region sessions", err)
	}
	return values, nil
}
