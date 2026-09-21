package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/gateway"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/operationaudit"
	"github.com/srex-run/access-gateway/internal/repository"
)

// Session credentials only authorize evidence for this grant and an existing
// backend_connected event. Asset IDs/accounts/tuples are independently checked.
func (s *AccessService) RecordSessionOperations(ctx context.Context, gatewayID, sessionID string, events []operationaudit.SessionEvent) ([]string, error) {
	if !id.IsUUID(sessionID) || len(events) == 0 || len(events) > 100 {
		return nil, ErrValidation
	}
	ids := make([]string, 0, len(events))
	seen := map[string]bool{}
	err := InTx(ctx, s.db, func(q repository.DBTX) error {
		session, err := s.sessions.GetByID(ctx, q, sessionID)
		if err != nil {
			return err
		}
		if session.GatewayID != gatewayID || session.ConnectionMode != gateway.ConnectionModeAudit {
			return ErrForbidden
		}
		request, err := s.requests.GetByID(ctx, q, session.RequestID)
		if err != nil {
			return err
		}
		for _, event := range events {
			input, err := validateOperationAuditInput(event.Event, s.clock())
			if err != nil {
				return err
			}
			if !id.IsUUID(event.ConnectionID) || !id.IsUUID(event.OperationID) || seen[input.EventID] || (event.Phase != "started" && event.Phase != "completed") {
				return ErrValidation
			}
			seen[input.EventID] = true
			if input.AssetID != request.AssetID || input.TargetPort != request.TargetPort || input.Protocol != session.AuditPolicy.Protocol {
				return ErrForbidden
			}
			var valid bool
			err = q.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM gateway_connection_events WHERE session_id=$1 AND connection_id=$2 AND event_type='backend_connected' AND backend_source_ip=$3::inet AND backend_source_port=$4 AND occurred_at<=$5)`, sessionID, event.ConnectionID, input.BackendSourceIP, input.BackendSourcePort, input.OccurredAt).Scan(&valid)
			if err != nil {
				return err
			}
			if !valid {
				return fmt.Errorf("operation connection evidence is missing: %w", ErrForbidden)
			}
			if input.SourceRecordID != "proxy/"+event.OperationID+"/"+event.Phase {
				return ErrValidation
			}
			if event.Phase == "started" && input.Result != "unknown" {
				return ErrValidation
			}
			if event.Phase == "completed" {
				if err = q.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM operation_audit_events WHERE session_id=$1 AND connection_id=$2 AND metadata->>'source'='session_proxy' AND metadata->>'operation_id'=$3 AND metadata->>'phase'='started' AND protocol=$4 AND actual_account=$5 AND normalized_operation IS NOT DISTINCT FROM $6)`, sessionID, event.ConnectionID, event.OperationID, input.Protocol, input.ActualAccount, input.NormalizedOperation).Scan(&valid); err != nil {
					return err
				}
				if !valid {
					return ErrValidation
				}
			}
			metadata := input.Metadata
			metadata["source"] = "session_proxy"
			metadata["operation_id"] = event.OperationID
			metadata["phase"] = event.Phase
			metadata["profile"] = session.AuditPolicy.Profile
			correlation := "matched"
			if request.TargetAccount == nil || *request.TargetAccount != input.ActualAccount {
				correlation = "identity_mismatch"
			}
			if input.ActualAccount == "unverified" || input.ActualAccount == "unauthenticated" {
				correlation = "unmatched"
			}
			value := domain.OperationAuditEvent{
				EventID: input.EventID, ConnectionID: &event.ConnectionID, SessionID: &sessionID, Protocol: input.Protocol, AssetID: input.AssetID, TargetPort: input.TargetPort, ActualAccount: input.ActualAccount, OperationType: input.OperationType, StatementFingerprint: input.StatementFingerprint, NormalizedOperation: input.NormalizedOperation, ObjectName: input.ObjectName, Result: input.Result, DurationMS: input.DurationMS, BackendSourceIP: input.BackendSourceIP, BackendSourcePort: input.BackendSourcePort, SourceRecordID: input.SourceRecordID, CorrelationStatus: correlation, OccurredAt: input.OccurredAt, Metadata: metadata,
			}
			created, err := s.accessEvidence.AppendOperationEvent(ctx, q, value)
			if err != nil {
				return err
			}
			if !created {
				stored, err := s.accessEvidence.GetOperationEvent(ctx, q, input.EventID)
				if err != nil {
					return err
				}
				// PostgreSQL stores timestamps with microsecond precision.
				if !stored.OccurredAt.Equal(value.OccurredAt.Truncate(time.Microsecond)) {
					return ErrValidation
				}
				stored.CreatedAt = value.CreatedAt
				stored.OccurredAt = value.OccurredAt
				left, _ := json.Marshal(stored)
				right, _ := json.Marshal(value)
				if !bytes.Equal(left, right) {
					return fmt.Errorf("operation event identity conflict: %w", ErrValidation)
				}
			}
			ids = append(ids, input.EventID)
		}
		return nil
	})
	return ids, err
}
