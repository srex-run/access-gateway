package repository

import (
	"encoding/json"

	"github.com/srex-run/access-gateway/internal/domain"
)

const sessionRecordColumns = `s.id, r.id, u.id, u.nickname, a.id, a.name, a.asset_type, COALESCE(r.target_account,''), r.target_port, s.status, s.created_at, s.started_at, s.expires_at`

func scanSessionRecord(row RowScanner) (domain.SessionRecord, error) {
	var value domain.SessionRecord
	err := row.Scan(&value.ID, &value.RequestID, &value.ApplicantID, &value.ApplicantName, &value.AssetID, &value.AssetName, &value.AssetType,
		&value.TargetAccount, &value.TargetPort, &value.Status, &value.CreatedAt, &value.StartedAt, &value.ExpiresAt)
	return value, mapError(err)
}

func scanSessionTrace(row RowScanner) (domain.SessionTraceEvent, error) {
	var value domain.SessionTraceEvent
	var details []byte
	if err := row.Scan(&value.ID, &value.Stage, &value.EventType, &value.OccurredAt, &details); err != nil {
		return value, mapError(err)
	}
	err := json.Unmarshal(details, &value.SessionTraceDetails)
	return value, err
}

func scanOperationAuditSession(row RowScanner) (domain.OperationAuditSession, error) {
	var value domain.OperationAuditSession
	var accounts, protocols []byte
	if err := row.Scan(&value.ID, &value.RequestID, &value.ApplicantID, &value.ApplicantName, &value.AssetID, &value.AssetName, &value.AssetType,
		&value.TargetAccount, &value.TargetPort, &value.Status, &value.CreatedAt, &value.StartedAt, &value.ExpiresAt,
		&value.CommandCount, &value.SuccessCommandCount, &value.FailedCommandCount, &accounts, &protocols, &value.LastOccurredAt); err != nil {
		return value, mapError(err)
	}
	if err := json.Unmarshal(accounts, &value.ActualAccounts); err != nil {
		return value, err
	}
	err := json.Unmarshal(protocols, &value.Protocols)
	return value, err
}
