package repository

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/securetransport"
)

const notificationColumns = `id, user_id, event_type, dedupe_key, title, content, request_id, session_id, read_at, created_at`

func scanNotification(s RowScanner) (domain.Notification, error) {
	var v domain.Notification
	err := s.Scan(
		&v.ID,        // id
		&v.UserID,    // user_id
		&v.EventType, // event_type
		&v.DedupeKey, // dedupe_key
		&v.Title,     // title
		&v.Content,   // content
		&v.RequestID, // request_id
		&v.SessionID, // session_id
		&v.ReadAt,    // read_at
		&v.CreatedAt, // created_at
	)
	return v, mapError(err)
}

func scanNotificationCount(s RowScanner) (int64, error) {
	var count int64
	err := s.Scan(&count) // count
	return count, mapError(err)
}

const assetAuditColumns = `asset_id, config_ciphertext, revision, updated_at, updated_by`

// assetAuditColumns and scanAssetAudit correspond in exactly the same order.
func scanAssetAudit(s RowScanner) (AssetAudit, error) {
	var value AssetAudit
	err := s.Scan(
		&value.AssetID,          // asset_id
		&value.ConfigCiphertext, // config_ciphertext
		&value.Revision,         // revision
		&value.UpdatedAt,        // updated_at
		&value.UpdatedBy,        // updated_by
	)
	return value, mapError(err)
}

// EXPLAIN returns one text column named QUERY PLAN, in this same order.
func scanQueryPlan(s RowScanner) (string, error) {
	var value string
	err := s.Scan(&value) // QUERY PLAN
	return value, mapError(err)
}

func scanTransportKey(s RowScanner) (TransportKey, error) {
	var value TransportKey
	err := s.Scan(&value.ID, &value.PublicKey, &value.PrivateKeyCiphertext)
	return value, mapError(err)
}

func scanTransportChallenge(s RowScanner) (securetransport.Challenge, error) {
	var value securetransport.Challenge
	err := s.Scan(&value.ID, &value.KeyID, &value.Method, &value.Path, &value.Subject, &value.ExpiresAt)
	return value, mapError(err)
}

func scanConsumedTransport(s RowScanner) (securetransport.Challenge, TransportKey, error) {
	var value securetransport.Challenge
	var key TransportKey
	err := s.Scan(&value.ID, &value.KeyID, &value.Method, &value.Path, &value.Subject, &value.ExpiresAt, &key.PrivateKeyCiphertext)
	key.ID = value.KeyID
	return value, key, mapError(err)
}

const userColumns = `id, feishu_open_id, feishu_union_id, nickname, email, department, status, created_at, updated_at, auth_version, labels, revision, username`

const cloudAccountColumns = `id, name, provider, enabled, revision, credentials_ciphertext, created_at, updated_at`

func scanCloudAccount(s RowScanner) (domain.CloudAccount, error) {
	var value domain.CloudAccount
	err := s.Scan(&value.ID, &value.Name, &value.Provider, &value.Enabled, &value.Revision,
		&value.CredentialsCiphertext, &value.CreatedAt, &value.UpdatedAt)
	return value, mapError(err)
}

const cloudSyncColumns = `id, account_id, account_revision, actor_id, input_json, status, result_json, error,
	lease_token, lease_until, created_at, started_at, finished_at`

func scanCloudSyncJob(s RowScanner) (domain.CloudSyncJob, error) {
	var value domain.CloudSyncJob
	var input, result []byte
	err := s.Scan(&value.ID, &value.AccountID, &value.AccountRevision, &value.ActorID, &input,
		&value.Status, &result, &value.Error, &value.LeaseToken, &value.LeaseUntil, &value.CreatedAt,
		&value.StartedAt, &value.FinishedAt)
	if err != nil {
		return value, mapError(err)
	}
	if err := json.Unmarshal(input, &value.Input); err != nil {
		return value, fmt.Errorf("decode cloud sync input: %w", err)
	}
	err = json.Unmarshal(result, &value.Result)
	return value, err
}

// scanSystemSettings matches config_json, secrets_ciphertext, revision, updated_at, updated_by.
func scanSystemSettings(s RowScanner) (SystemSettings, error) {
	var value SystemSettings
	err := s.Scan(&value.ConfigJSON, &value.SecretsCiphertext, &value.Revision, &value.UpdatedAt, &value.UpdatedBy)
	return value, mapError(err)
}

// userColumns and scanUser must stay in the same order.
func scanUser(s RowScanner) (domain.User, error) {
	var value domain.User
	var labels []byte
	var openID, unionID, email, department sql.NullString
	if err := s.Scan(
		&value.ID,          // id
		&openID,            // feishu_open_id
		&unionID,           // feishu_union_id
		&value.Nickname,    // nickname
		&email,             // email
		&department,        // department
		&value.Status,      // status
		&value.CreatedAt,   // created_at
		&value.UpdatedAt,   // updated_at
		&value.AuthVersion, // auth_version
		&labels,            // labels
		&value.Revision,    // revision
		&value.Username,    // username
	); err != nil {
		return domain.User{}, opError("scan user", err)
	}
	value.FeishuUnionID = nullableString(unionID)
	value.FeishuOpenID = openID.String
	value.Email = nullableString(email)
	value.Department = nullableString(department)
	if err := json.Unmarshal(labels, &value.Labels); err != nil {
		return value, opError("decode user labels", err)
	}
	return value, nil
}

const regionColumns = `id, code, name, status, created_at, updated_at`

// regionColumns and scanRegion must stay in the same order: id, code, name, status, created_at, updated_at.
func scanRegion(s RowScanner) (domain.Region, error) {
	var value domain.Region
	if err := s.Scan(
		&value.ID,        // id
		&value.Code,      // code
		&value.Name,      // name
		&value.Status,    // status
		&value.CreatedAt, // created_at
		&value.UpdatedAt, // updated_at
	); err != nil {
		return domain.Region{}, opError("scan region", err)
	}
	return value, nil
}

const gatewayColumns = `id, region_id, name, management_endpoint, public_endpoint, auth_secret_ref, status, max_sessions, last_heartbeat_at, created_at, updated_at`

const gatewayColumnsQualified = `g.id, g.region_id, g.name, g.management_endpoint, g.public_endpoint, g.auth_secret_ref, g.status, g.max_sessions, g.last_heartbeat_at, g.created_at, g.updated_at`

// gatewayColumns and scanGateway must stay in the same order: id, region_id, name, management_endpoint, public_endpoint, auth_secret_ref, status, max_sessions, last_heartbeat_at, created_at, updated_at.
func scanGateway(s RowScanner) (domain.Gateway, error) {
	var value domain.Gateway
	var secretRef sql.NullString
	var heartbeat sql.NullTime
	if err := s.Scan(
		&value.ID,                 // id
		&value.RegionID,           // region_id
		&value.Name,               // name
		&value.ManagementEndpoint, // management_endpoint
		&value.PublicEndpoint,     // public_endpoint
		&secretRef,                // auth_secret_ref
		&value.Status,             // status
		&value.MaxSessions,        // max_sessions
		&heartbeat,                // last_heartbeat_at
		&value.CreatedAt,          // created_at
		&value.UpdatedAt,          // updated_at
	); err != nil {
		return domain.Gateway{}, opError("scan gateway", err)
	}
	value.AuthSecretRef = nullableString(secretRef)
	value.LastHeartbeatAt = nullableTime(heartbeat)
	return value, nil
}

const assetColumns = `id, region_id, gateway_id, name, asset_type, target_ciphertext, risk_level, max_ttl_seconds, status, external_source, external_id, sync_generation, last_synced_at, created_at, updated_at, approval_workflow_id, deleted_at`

// assetColumns and scanAsset must stay in the same order.
func scanAsset(s RowScanner) (domain.Asset, error) {
	var value domain.Asset
	var externalSource, externalID, syncGeneration sql.NullString
	var approvalWorkflowID sql.NullString
	var lastSyncedAt, deletedAt sql.NullTime
	if err := s.Scan(
		&value.ID,               // id
		&value.RegionID,         // region_id
		&value.GatewayID,        // gateway_id
		&value.Name,             // name
		&value.AssetType,        // asset_type
		&value.TargetCiphertext, // target_ciphertext
		&value.RiskLevel,        // risk_level
		&value.MaxTTLSeconds,    // max_ttl_seconds
		&value.Status,           // status
		&externalSource,         // external_source
		&externalID,             // external_id
		&syncGeneration,         // sync_generation
		&lastSyncedAt,           // last_synced_at
		&value.CreatedAt,        // created_at
		&value.UpdatedAt,        // updated_at
		&approvalWorkflowID,     // approval_workflow_id
		&deletedAt,              // deleted_at
	); err != nil {
		return domain.Asset{}, opError("scan asset", err)
	}
	value.ExternalSource = nullableString(externalSource)
	value.ExternalID = nullableString(externalID)
	value.SyncGeneration = nullableString(syncGeneration)
	value.LastSyncedAt = nullableTime(lastSyncedAt)
	value.DeletedAt = nullableTime(deletedAt)
	value.ApprovalWorkflowID = nullableString(approvalWorkflowID)
	return value, nil
}

// scanLockAcquired is the only scanner for advisory-lock boolean results.
func scanLockAcquired(s RowScanner) (bool, error) {
	var acquired bool
	if err := s.Scan(&acquired /* acquired */); err != nil {
		return false, opError("scan advisory lock acquisition", err)
	}
	return acquired, nil
}

const assetGatewayBindingColumns = `asset_id, gateway_id, priority, enabled, created_at, updated_at`

// assetGatewayBindingColumns and scanAssetGatewayBinding must stay in the same order: asset_id, gateway_id, priority, enabled, created_at, updated_at.
func scanAssetGatewayBinding(s RowScanner) (domain.AssetGatewayBinding, error) {
	var value domain.AssetGatewayBinding
	if err := s.Scan(
		&value.AssetID,   // asset_id
		&value.GatewayID, // gateway_id
		&value.Priority,  // priority
		&value.Enabled,   // enabled
		&value.CreatedAt, // created_at
		&value.UpdatedAt, // updated_at
	); err != nil {
		return domain.AssetGatewayBinding{}, opError("scan asset gateway binding", err)
	}
	return value, nil
}

const gatewayCatalogEntryColumns = `a.id, a.external_source, a.external_id, jsonb_agg(p.port ORDER BY p.port)`

// gatewayCatalogEntryColumns and scanGatewayCatalogEntry must stay in the same order: target id, external_source, external_id, enabled ports.
func scanGatewayCatalogEntry(s RowScanner) (domain.GatewayCatalogEntry, error) {
	var value domain.GatewayCatalogEntry
	var externalSource, externalID sql.NullString
	var portsJSON []byte
	if err := s.Scan(
		&value.TargetID, // a.id
		&externalSource, // a.external_source
		&externalID,     // a.external_id
		&portsJSON,      // jsonb_agg(p.port ORDER BY p.port)
	); err != nil {
		return domain.GatewayCatalogEntry{}, opError("scan gateway catalog entry", err)
	}
	if err := json.Unmarshal(portsJSON, &value.Ports); err != nil {
		return domain.GatewayCatalogEntry{}, opError("decode gateway catalog ports", err)
	}
	value.ExternalSource = nullableString(externalSource)
	value.ExternalID = nullableString(externalID)
	return value, nil
}

const assetPortColumns = `id, asset_id, port, protocol, enabled, created_at`

// assetPortColumns and scanAssetPort must stay in the same order: id, asset_id, port, protocol, enabled, created_at.
func scanAssetPort(s RowScanner) (domain.AssetPort, error) {
	var value domain.AssetPort
	if err := s.Scan(
		&value.ID,        // id
		&value.AssetID,   // asset_id
		&value.Port,      // port
		&value.Protocol,  // protocol
		&value.Enabled,   // enabled
		&value.CreatedAt, // created_at
	); err != nil {
		return domain.AssetPort{}, opError("scan asset port", err)
	}
	return value, nil
}

const approverColumns = `id, asset_id, user_id, approval_level, role, enabled, created_at`

// approverColumns and scanApprover must stay in the same order: id, asset_id, user_id, approval_level, role, enabled, created_at.
func scanApprover(s RowScanner) (domain.AssetApprover, error) {
	var value domain.AssetApprover
	if err := s.Scan(
		&value.ID,            // id
		&value.AssetID,       // asset_id
		&value.UserID,        // user_id
		&value.ApprovalLevel, // approval_level
		&value.Role,          // role
		&value.Enabled,       // enabled
		&value.CreatedAt,     // created_at
	); err != nil {
		return domain.AssetApprover{}, opError("scan approver", err)
	}
	return value, nil
}

const accessRequestColumns = `id, applicant_id, asset_id, target_port, reason, ticket_no, emergency, requested_start_at, ttl_seconds, status, idempotency_key, source_ip, target_account, created_at, updated_at, approval_mode, workflow_snapshot, approval_expires_at`

// scanAccessRequest follows accessRequestColumns, including the persisted approval mode.
func scanAccessRequest(s RowScanner) (domain.AccessRequest, error) {
	var value domain.AccessRequest
	var snapshot []byte
	var ticketNo, sourceIP, targetAccount sql.NullString
	var requestedStart sql.NullTime
	if err := s.Scan(
		&value.ID,                // id
		&value.ApplicantID,       // applicant_id
		&value.AssetID,           // asset_id
		&value.TargetPort,        // target_port
		&value.Reason,            // reason
		&ticketNo,                // ticket_no
		&value.Emergency,         // emergency
		&requestedStart,          // requested_start_at
		&value.TTLSeconds,        // ttl_seconds
		&value.Status,            // status
		&value.IdempotencyKey,    // idempotency_key
		&sourceIP,                // source_ip
		&targetAccount,           // target_account
		&value.CreatedAt,         // created_at
		&value.UpdatedAt,         // updated_at
		&value.ApprovalMode,      // approval_mode
		&snapshot,                // workflow_snapshot
		&value.ApprovalExpiresAt, // approval_expires_at
	); err != nil {
		return domain.AccessRequest{}, opError("scan access request", err)
	}
	value.TicketNo = nullableString(ticketNo)
	value.RequestedStartAt = nullableTime(requestedStart)
	value.SourceIP = nullableString(sourceIP)
	value.TargetAccount = nullableString(targetAccount)
	if len(snapshot) > 0 {
		if err := json.Unmarshal(snapshot, &value.WorkflowSnapshot); err != nil {
			return value, opError("decode approval snapshot", err)
		}
	}
	return value, nil
}

const approvalColumns = `id, request_id, approver_id, approval_level, decision, comment, decided_at, created_at, required_approvals, step_name`

const approvalColumnsQualified = `a.id, a.request_id, a.approver_id, a.approval_level, a.decision, a.comment, a.decided_at, a.created_at, a.required_approvals, a.step_name`

// approvalColumns and scanApproval must stay in the same order: id, request_id, approver_id, approval_level, decision, comment, decided_at, created_at.
func scanApproval(s RowScanner) (domain.Approval, error) {
	return scanApprovalWithPriority(s, false)
}

func scanPendingApproval(s RowScanner) (domain.Approval, error) {
	return scanApprovalWithPriority(s, true)
}

func scanApprovalWithPriority(s RowScanner, includePriority bool) (domain.Approval, error) {
	var value domain.Approval
	var decision, comment sql.NullString
	var decidedAt sql.NullTime
	fields := []any{
		&value.ID,                // id
		&value.RequestID,         // request_id
		&value.ApproverID,        // approver_id
		&value.ApprovalLevel,     // approval_level
		&decision,                // decision
		&comment,                 // comment
		&decidedAt,               // decided_at
		&value.CreatedAt,         // created_at
		&value.RequiredApprovals, // required_approvals
		&value.StepName,          // step_name
	}
	if includePriority {
		fields = append(fields, &value.Emergency)
	}
	if err := s.Scan(fields...); err != nil {
		return domain.Approval{}, opError("scan approval", err)
	}
	if decision.Valid {
		parsed := domain.ApprovalDecision(decision.String)
		value.Decision = &parsed
	}
	value.Comment = nullableString(comment)
	value.DecidedAt = nullableTime(decidedAt)
	return value, nil
}

const sessionColumns = `id, request_id, gateway_id, token_hash, remote_process_id, status, started_at, expires_at, closed_at, failure_reason, version, listener_port, external_port, exposure_mode, exposure_ref, created_at, updated_at, tunnel_client_public_key, tunnel_server_certificate, connection_mode, COALESCE(audit_policy->>'profile',''), COALESCE(audit_policy->>'revision',''), COALESCE(audit_policy->>'protocol','')`

const sessionColumnsQualified = `s.id, s.request_id, s.gateway_id, s.token_hash, s.remote_process_id, s.status, s.started_at, s.expires_at, s.closed_at, s.failure_reason, s.version, s.listener_port, s.external_port, s.exposure_mode, s.exposure_ref, s.created_at, s.updated_at, s.tunnel_client_public_key, s.tunnel_server_certificate, s.connection_mode, COALESCE(s.audit_policy->>'profile',''), COALESCE(s.audit_policy->>'revision',''), COALESCE(s.audit_policy->>'protocol','')`

// sessionColumns and scanSession must stay in the same order, including the
// final tunnel public identity fields and connection mode.
func scanSession(s RowScanner) (domain.Session, error) {
	var value domain.Session
	var tokenHash, processID, failureReason, exposureMode, exposureRef sql.NullString
	var listenerPort, externalPort sql.NullInt64
	var startedAt, expiresAt, closedAt sql.NullTime
	if err := s.Scan(
		&value.ID,        // id
		&value.RequestID, // request_id
		&value.GatewayID, // gateway_id
		&tokenHash,       // token_hash
		&processID,       // remote_process_id
		&value.Status,    // status
		&startedAt,       // started_at
		&expiresAt,       // expires_at
		&closedAt,        // closed_at
		&failureReason,   // failure_reason
		&value.Version,   // version
		&listenerPort,    // listener_port
		&externalPort,    // external_port
		&exposureMode,    // exposure_mode
		&exposureRef,     // exposure_ref
		&value.CreatedAt, // created_at
		&value.UpdatedAt, // updated_at
		&value.TunnelClientPublicKey,
		&value.TunnelServerCertificate,
		&value.ConnectionMode,
		&value.AuditPolicy.Profile, &value.AuditPolicy.Revision, &value.AuditPolicy.Protocol,
	); err != nil {
		return domain.Session{}, opError("scan session", err)
	}
	value.TokenHash = nullableString(tokenHash)
	value.RemoteProcessID = nullableString(processID)
	value.StartedAt = nullableTime(startedAt)
	value.ExpiresAt = nullableTime(expiresAt)
	value.ClosedAt = nullableTime(closedAt)
	value.FailureReason = nullableString(failureReason)
	value.ListenerPort = nullableInt(listenerPort)
	value.ExternalPort = nullableInt(externalPort)
	value.ExposureMode = nullableString(exposureMode)
	value.ExposureRef = nullableString(exposureRef)
	return value, nil
}

const sessionTokenDeliveryColumns = `session_id, token_ciphertext, expires_at, created_at`

// sessionTokenDeliveryColumns and scanSessionTokenDelivery must stay in the same order: session_id, token_ciphertext, expires_at, created_at.
func scanSessionTokenDelivery(s RowScanner) (domain.SessionTokenDelivery, error) {
	var value domain.SessionTokenDelivery
	if err := s.Scan(
		&value.SessionID,       // session_id
		&value.TokenCiphertext, // token_ciphertext
		&value.ExpiresAt,       // expires_at
		&value.CreatedAt,       // created_at
	); err != nil {
		return domain.SessionTokenDelivery{}, opError("scan session token delivery", err)
	}
	return value, nil
}

const oauthStateColumns = `state_hash, expires_at, created_at`

// oauthStateColumns and scanOAuthState must stay in the same order: state_hash, expires_at, created_at.
func scanOAuthState(s RowScanner) (domain.OAuthState, error) {
	var value domain.OAuthState
	if err := s.Scan(
		&value.StateHash, // state_hash
		&value.ExpiresAt, // expires_at
		&value.CreatedAt, // created_at
	); err != nil {
		return domain.OAuthState{}, opError("scan OAuth state", err)
	}
	return value, nil
}

const sessionEventColumns = `id, session_id, event_type, actor_type, actor_id, metadata, created_at`

// sessionEventColumns and scanSessionEvent must stay in the same order: id, session_id, event_type, actor_type, actor_id, metadata, created_at.
func scanSessionEvent(s RowScanner) (domain.SessionEvent, error) {
	var value domain.SessionEvent
	var actorID sql.NullString
	var raw []byte
	if err := s.Scan(
		&value.ID,        // id
		&value.SessionID, // session_id
		&value.EventType, // event_type
		&value.ActorType, // actor_type
		&actorID,         // actor_id
		&raw,             // metadata
		&value.CreatedAt, // created_at
	); err != nil {
		return domain.SessionEvent{}, opError("scan session event", err)
	}
	value.ActorID = nullableString(actorID)
	metadata, err := decodeJSON(raw, "session event metadata")
	if err != nil {
		return domain.SessionEvent{}, err
	}
	value.Metadata = metadata
	return value, nil
}

const gatewayConnectionEventColumns = `event_id, connection_id, session_id, event_type, source_ip, backend_source_ip, backend_source_port, bytes_up, bytes_down, duration_ms, result, reason, occurred_at, created_at`

// gatewayConnectionEventColumns and scanGatewayConnectionEvent must stay in the same order: event_id, connection_id, session_id, event_type, source_ip, backend_source_ip, backend_source_port, bytes_up, bytes_down, duration_ms, result, reason, occurred_at, created_at.
func scanGatewayConnectionEvent(s RowScanner) (domain.GatewayConnectionEvent, error) {
	var value domain.GatewayConnectionEvent
	var sourceIP, backendSourceIP, result, reason sql.NullString
	var backendSourcePort, bytesUp, bytesDown, durationMS sql.NullInt64
	if err := s.Scan(
		&value.EventID,      // event_id
		&value.ConnectionID, // connection_id
		&value.SessionID,    // session_id
		&value.EventType,    // event_type
		&sourceIP,           // source_ip
		&backendSourceIP,    // backend_source_ip
		&backendSourcePort,  // backend_source_port
		&bytesUp,            // bytes_up
		&bytesDown,          // bytes_down
		&durationMS,         // duration_ms
		&result,             // result
		&reason,             // reason
		&value.OccurredAt,   // occurred_at
		&value.CreatedAt,    // created_at
	); err != nil {
		return domain.GatewayConnectionEvent{}, opError("scan gateway connection event", err)
	}
	value.SourceIP = nullableString(sourceIP)
	value.BackendSourceIP = nullableString(backendSourceIP)
	value.BackendSourcePort = nullableInt(backendSourcePort)
	value.BytesUp = nullableInt64(bytesUp)
	value.BytesDown = nullableInt64(bytesDown)
	value.DurationMS = nullableInt64(durationMS)
	value.Result = nullableString(result)
	value.Reason = nullableString(reason)
	return value, nil
}

const operationAuditEventColumns = `event_id, connection_id, session_id, protocol, asset_id, target_port, actual_account, operation_type, statement_fingerprint, normalized_operation, object_name, result, duration_ms, backend_source_ip, backend_source_port, source_record_id, correlation_status, occurred_at, metadata, created_at`

const operationAuditEventColumnsQualified = `o.event_id, o.connection_id, o.session_id, o.protocol, o.asset_id, o.target_port, o.actual_account, o.operation_type, o.statement_fingerprint, o.normalized_operation, o.object_name, o.result, o.duration_ms, o.backend_source_ip, o.backend_source_port, o.source_record_id, o.correlation_status, o.occurred_at, o.metadata, o.created_at`

// operationAuditEventColumns and scanOperationAuditEvent must stay in the same order: event_id, connection_id, session_id, protocol, asset_id, target_port, actual_account, operation_type, statement_fingerprint, normalized_operation, object_name, result, duration_ms, backend_source_ip, backend_source_port, source_record_id, correlation_status, occurred_at, metadata, created_at.
func scanOperationAuditEvent(s RowScanner) (domain.OperationAuditEvent, error) {
	var value domain.OperationAuditEvent
	var connectionID, sessionID, fingerprint, operation, objectName sql.NullString
	var durationMS sql.NullInt64
	var raw []byte
	if err := s.Scan(
		&value.EventID,           // event_id
		&connectionID,            // connection_id
		&sessionID,               // session_id
		&value.Protocol,          // protocol
		&value.AssetID,           // asset_id
		&value.TargetPort,        // target_port
		&value.ActualAccount,     // actual_account
		&value.OperationType,     // operation_type
		&fingerprint,             // statement_fingerprint
		&operation,               // normalized_operation
		&objectName,              // object_name
		&value.Result,            // result
		&durationMS,              // duration_ms
		&value.BackendSourceIP,   // backend_source_ip
		&value.BackendSourcePort, // backend_source_port
		&value.SourceRecordID,    // source_record_id
		&value.CorrelationStatus, // correlation_status
		&value.OccurredAt,        // occurred_at
		&raw,                     // metadata
		&value.CreatedAt,         // created_at
	); err != nil {
		return domain.OperationAuditEvent{}, opError("scan operation audit event", err)
	}
	value.ConnectionID = nullableString(connectionID)
	value.SessionID = nullableString(sessionID)
	value.StatementFingerprint = nullableString(fingerprint)
	value.NormalizedOperation = nullableString(operation)
	value.ObjectName = nullableString(objectName)
	value.DurationMS = nullableInt64(durationMS)
	metadata, err := decodeJSON(raw, "operation audit metadata")
	if err != nil {
		return domain.OperationAuditEvent{}, err
	}
	value.Metadata = metadata
	return value, nil
}

const operationCorrelationColumns = `connection_id, session_id, target_account`

type operationCorrelation struct {
	ConnectionID  string
	SessionID     string
	TargetAccount string
}

// operationCorrelationColumns and scanOperationCorrelation must stay in the same order: connection_id, session_id, target_account.
func scanOperationCorrelation(s RowScanner) (operationCorrelation, error) {
	var value operationCorrelation
	if err := s.Scan(
		&value.ConnectionID,  // connection_id
		&value.SessionID,     // session_id
		&value.TargetAccount, // target_account
	); err != nil {
		return operationCorrelation{}, opError("scan operation correlation", err)
	}
	return value, nil
}

const outboxEventColumns = `id, aggregate_type, aggregate_id, event_type, payload, status, retry_count, next_retry_at, created_at, processed_at`

const outboxEventColumnsQualified = `e.id, e.aggregate_type, e.aggregate_id, e.event_type, e.payload, e.status, e.retry_count, e.next_retry_at, e.created_at, e.processed_at`

// outboxEventColumns and scanOutboxEvent must stay in the same order: id, aggregate_type, aggregate_id, event_type, payload, status, retry_count, next_retry_at, created_at, processed_at.
func scanOutboxEvent(s RowScanner) (domain.OutboxEvent, error) {
	var value domain.OutboxEvent
	var raw []byte
	var nextRetry, processedAt sql.NullTime
	if err := s.Scan(
		&value.ID,            // id
		&value.AggregateType, // aggregate_type
		&value.AggregateID,   // aggregate_id
		&value.EventType,     // event_type
		&raw,                 // payload
		&value.Status,        // status
		&value.RetryCount,    // retry_count
		&nextRetry,           // next_retry_at
		&value.CreatedAt,     // created_at
		&processedAt,         // processed_at
	); err != nil {
		return domain.OutboxEvent{}, opError("scan outbox event", err)
	}
	var err error
	value.Payload, err = decodeJSON(raw, "outbox event payload")
	if err != nil {
		return domain.OutboxEvent{}, err
	}
	value.NextRetryAt = nullableTime(nextRetry)
	value.ProcessedAt = nullableTime(processedAt)
	return value, nil
}

const outboxQueueStatsColumns = `pending_count, oldest_age_seconds`

// outboxQueueStatsColumns and scanOutboxQueueStats must stay in the same order: pending_count, oldest_age_seconds.
func scanOutboxQueueStats(s RowScanner) (OutboxQueueStats, error) {
	var value OutboxQueueStats
	if err := s.Scan(
		&value.PendingCount,     // pending_count
		&value.OldestAgeSeconds, // oldest_age_seconds
	); err != nil {
		return OutboxQueueStats{}, opError("scan outbox queue stats", err)
	}
	return value, nil
}

const auditEventColumns = `id, event_type, actor_type, actor_id, subject_user_id, request_id, session_id, region_id, asset_id, target_port, source_ip, client_version, result, reason, metadata, created_at`

// scanAuditEvent reads auditEventColumns, followed by the actor's display name
// and local username joined by AuditEventRepository.List.
func scanAuditEvent(s RowScanner) (domain.AuditEvent, error) {
	var value domain.AuditEvent
	var actorID, subjectUserID, requestID, sessionID, regionID, assetID sql.NullString
	var targetPort sql.NullInt64
	var sourceIP, clientVersion, result, reason sql.NullString
	var raw []byte
	if err := s.Scan(
		&value.ID,        // id
		&value.EventType, // event_type
		&value.ActorType, // actor_type
		&actorID,         // actor_id
		&subjectUserID,   // subject_user_id
		&requestID,       // request_id
		&sessionID,       // session_id
		&regionID,        // region_id
		&assetID,         // asset_id
		&targetPort,      // target_port
		&sourceIP,        // source_ip
		&clientVersion,   // client_version
		&result,          // result
		&reason,          // reason
		&raw,             // metadata
		&value.CreatedAt, // created_at
		&value.ActorName,
		&value.ActorUsername,
	); err != nil {
		return domain.AuditEvent{}, opError("scan audit event", err)
	}
	value.ActorID = nullableString(actorID)
	value.SubjectUserID = nullableString(subjectUserID)
	value.RequestID = nullableString(requestID)
	value.SessionID = nullableString(sessionID)
	value.RegionID = nullableString(regionID)
	value.AssetID = nullableString(assetID)
	if targetPort.Valid {
		port := int(targetPort.Int64)
		value.TargetPort = &port
	}
	value.SourceIP = nullableString(sourceIP)
	value.ClientVersion = nullableString(clientVersion)
	value.Result = nullableString(result)
	value.Reason = nullableString(reason)
	var err error
	value.Metadata, err = decodeJSON(raw, "audit event metadata")
	if err != nil {
		return domain.AuditEvent{}, err
	}
	return value, nil
}

func nullableString(value sql.NullString) *string {
	if !value.Valid {
		return nil
	}
	result := value.String
	return &result
}

const roleAssignmentColumns = `id, user_id, role, granted_by, created_at, revoked_at`

// roleAssignmentColumns and scanRoleAssignment must stay in the same order: id, user_id, role, granted_by, created_at, revoked_at.
func scanRoleAssignment(s RowScanner) (domain.RoleAssignment, error) {
	var value domain.RoleAssignment
	var revokedAt sql.NullTime
	if err := s.Scan(
		&value.ID,        // id
		&value.UserID,    // user_id
		&value.Role,      // role
		&value.GrantedBy, // granted_by
		&value.CreatedAt, // created_at
		&revokedAt,       // revoked_at
	); err != nil {
		return domain.RoleAssignment{}, opError("scan role assignment", err)
	}
	value.RevokedAt = nullableTime(revokedAt)
	return value, nil
}

func nullableTime(value sql.NullTime) *time.Time {
	if !value.Valid {
		return nil
	}
	result := value.Time
	return &result
}

func nullableInt(value sql.NullInt64) *int {
	if !value.Valid {
		return nil
	}
	result := int(value.Int64)
	return &result
}

func nullableInt64(value sql.NullInt64) *int64 {
	if !value.Valid {
		return nil
	}
	result := value.Int64
	return &result
}

func decodeJSON(raw []byte, field string) (map[string]any, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, fmt.Errorf("decode %s: %w", field, err)
	}
	return value, nil
}

const advisoryLockColumns = `lock_result, locked`

// advisoryLockColumns and scanAdvisoryLock must stay in the same order: lock_result, locked.
func scanAdvisoryLock(s RowScanner) error {
	var lockResult any
	var locked bool
	if err := s.Scan(
		&lockResult, // lock_result (pg_advisory_xact_lock returns void)
		&locked,     // locked
	); err != nil {
		return opError("scan advisory lock", err)
	}
	if !locked {
		return fmt.Errorf("scan advisory lock: lock function returned false")
	}
	return nil
}

const sessionEvidenceSummaryColumns = `verified_accounts, operation_count, connection_count, failed_connections, context`

// The Scan arguments below correspond one-to-one to sessionEvidenceSummaryColumns.
func scanSessionEvidenceSummary(row RowScanner) (domain.SessionEvidenceSummary, error) {
	var value domain.SessionEvidenceSummary
	var accounts, contextJSON []byte
	if err := row.Scan(
		&accounts,                // verified_accounts
		&value.OperationCount,    // operation_count
		&value.ConnectionCount,   // connection_count
		&value.FailedConnections, // failed_connections
		&contextJSON,             // context
	); err != nil {
		return value, mapError(err)
	}
	if err := json.Unmarshal(accounts, &value.VerifiedAccounts); err != nil {
		return value, opError("decode session verified accounts", err)
	}
	err := json.Unmarshal(contextJSON, &value.Context)
	return value, opError("decode session evidence context", err)
}

const invitationColumns = `id, user_id, invited_by, expires_at, accepted_at, revoked_at, sent_at, created_at`

// Scan order matches invitationColumns.
func scanInvitation(row RowScanner) (Invitation, error) {
	var v Invitation
	err := row.Scan(
		&v.ID,         // id
		&v.UserID,     // user_id
		&v.InvitedBy,  // invited_by
		&v.ExpiresAt,  // expires_at
		&v.AcceptedAt, // accepted_at
		&v.RevokedAt,  // revoked_at
		&v.SentAt,     // sent_at
		&v.CreatedAt,  // created_at
	)
	return v, err
}

const invitationViewColumns = `i.id, i.user_id, i.invited_by, i.expires_at, i.accepted_at, i.revoked_at, i.sent_at, i.created_at,
	u.username, u.nickname, inviter.nickname, CASE WHEN i.accepted_at IS NOT NULL THEN 'accepted' WHEN i.revoked_at IS NOT NULL THEN 'revoked' WHEN i.expires_at <= NOW() THEN 'expired' ELSE 'pending' END`

// Scan order matches invitationViewColumns; no email or invitation token is selected.
func scanInvitationView(row RowScanner) (InvitationView, error) {
	var v InvitationView
	err := row.Scan(
		&v.ID,          // i.id
		&v.UserID,      // i.user_id
		&v.InvitedBy,   // i.invited_by
		&v.ExpiresAt,   // i.expires_at
		&v.AcceptedAt,  // i.accepted_at
		&v.RevokedAt,   // i.revoked_at
		&v.SentAt,      // i.sent_at
		&v.CreatedAt,   // i.created_at
		&v.Username,    // u.username
		&v.Nickname,    // u.nickname
		&v.InviterName, // inviter.nickname
		&v.Status,      // derived status
	)
	return v, err
}

const mfaColumns = `user_id, secret_ciphertext, last_step, created_at`

func scanMFA(row RowScanner) (MFABinding, error) {
	var v MFABinding
	err := row.Scan(&v.UserID, // user_id
		&v.SecretCiphertext, // secret_ciphertext
		&v.LastStep,         // last_step
		&v.CreatedAt,        // created_at
	)
	return v, err
}

const mfaChallengeColumns = `user_id, auth_version, kind, secret_ciphertext, attempts, expires_at, NOW()`

func scanMFAChallenge(row RowScanner) (MFAChallenge, error) {
	var v MFAChallenge
	err := row.Scan(&v.UserID, // user_id
		&v.AuthVersion,      // auth_version
		&v.Kind,             // kind
		&v.SecretCiphertext, // secret_ciphertext
		&v.Attempts,         // attempts
		&v.ExpiresAt,        // expires_at
		&v.Now,              // NOW()
	)
	return v, err
}

func scanIdentityCount(row RowScanner) (int, error) {
	var count int
	err := row.Scan(&count) // COUNT(*)
	return count, err
}

func scanIdentityTime(row RowScanner) (time.Time, error) {
	var now time.Time
	err := row.Scan(&now) // NOW()
	return now, err
}
