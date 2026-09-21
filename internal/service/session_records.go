package service

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/repository"
)

type SessionRecordView struct {
	Record   domain.SessionRecord
	View     SessionView
	Workflow WorkflowView
	Evidence domain.SessionEvidenceSummary
	CanClose bool
}

func (s *AccessService) sessionRecordAccess(ctx context.Context, actor string, openOnly bool) (readAll, canManage bool, err error) {
	err = s.readIAM(ctx, func(q repository.DBTX) error {
		if err := validateUUID(actor, "user ID"); err != nil {
			return ErrForbidden
		}
		user, err := s.users.GetByID(ctx, q, actor)
		if err != nil {
			return err
		}
		if user.Status != domain.UserStatusActive {
			return ErrForbidden
		}
		roles, err := s.resolvedRoles(ctx, q, user)
		if err != nil {
			return err
		}
		readAll = s.allowedRoles(roles, authz.PermissionAuditRead)
		// Force-close operators need the open-session selector, not historical
		// records or audit details. Only the list filtered to "open" opts in.
		if openOnly && s.allowedRoles(roles, authz.PermissionSessionOverride) {
			readAll = true
		}
		canManage = s.allowedRoles(roles, authz.PermissionSessionManage)
		if !readAll && !canManage && !s.allowedRoles(roles, authz.PermissionApprovalManage) {
			return ErrForbidden
		}
		return nil
	})
	return
}

func (s *AccessService) ListSessionRecords(ctx context.Context, actor string, filter domain.SessionRecordFilter) ([]domain.SessionRecord, error) {
	readAll, _, err := s.sessionRecordAccess(ctx, actor, filter.Status == "open")
	if err != nil {
		return nil, err
	}
	filter.ActorID, filter.ReadAll = actor, readAll
	filter, err = normalizeSessionRecordFilter(filter)
	if err != nil {
		return nil, err
	}
	return s.sessions.ListRecords(ctx, s.db, filter)
}

func normalizeSessionRecordFilter(filter domain.SessionRecordFilter) (domain.SessionRecordFilter, error) {
	filter.Search = strings.TrimSpace(filter.Search)
	if len(filter.Search) > 200 {
		return filter, requestValidation("搜索内容过长，请缩短后重试")
	}
	if !slices.Contains([]string{"", "open", "provisioning", "running", "revoking", "expired", "closed", "failed", "revoke_failed", "manual_intervention"}, filter.Status) {
		return filter, requestValidation("不支持的会话状态，请刷新页面后重试")
	}
	return filter, nil
}

func (s *AccessService) GetSessionRecord(ctx context.Context, actor, recordID string, byRequest bool) (SessionRecordView, error) {
	readAll, canManage, err := s.sessionRecordAccess(ctx, actor, false)
	if err != nil {
		return SessionRecordView{}, err
	}
	if err := validateUUID(recordID, "record ID"); err != nil {
		return SessionRecordView{}, err
	}
	var session domain.Session
	if byRequest {
		session, err = s.sessions.GetByRequestID(ctx, s.db, recordID)
	} else {
		session, err = s.sessions.GetByID(ctx, s.db, recordID)
	}
	if err != nil {
		return SessionRecordView{}, err
	}
	record, err := s.sessions.GetRecord(ctx, s.db, actor, readAll, session.ID)
	if err != nil {
		return SessionRecordView{}, err
	}
	request, err := s.requests.GetByID(ctx, s.db, session.RequestID)
	if err != nil {
		return SessionRecordView{}, err
	}
	view, err := s.sessionView(ctx, actor, session, request)
	if err != nil {
		return SessionRecordView{}, err
	}
	view.CanConnect = view.CanConnect && canManage
	approvals, err := s.approvals.ListByRequest(ctx, s.db, request.ID)
	if err != nil {
		return SessionRecordView{}, err
	}
	workflow, err := s.workflowView(ctx, s.db, request, approvals)
	if err != nil {
		return SessionRecordView{}, err
	}
	evidence, err := s.sessions.EvidenceSummary(ctx, s.db, session.ID)
	if err != nil {
		return SessionRecordView{}, err
	}
	canClose := canManage && (request.ApplicantID == actor || s.isAdminUser(ctx, actor)) &&
		(session.Status == domain.SessionRunning || session.Status == domain.SessionRevokeFailed)
	return SessionRecordView{Record: record, View: view, Workflow: workflow, Evidence: evidence, CanClose: canClose}, nil
}

func (s *AccessService) ListSessionTrace(ctx context.Context, actor, sessionID, stage string, limit, offset int) ([]domain.SessionTraceEvent, error) {
	readAll, _, err := s.sessionRecordAccess(ctx, actor, false)
	if err != nil {
		return nil, err
	}
	if err := validateUUID(sessionID, "session ID"); err != nil {
		return nil, err
	}
	if !slices.Contains([]string{"", "request", "approval", "session", "connection", "operation"}, stage) {
		return nil, fmt.Errorf("invalid trace stage: %w", ErrValidation)
	}
	if _, err := s.sessions.GetRecord(ctx, s.db, actor, readAll, sessionID); err != nil {
		return nil, err
	}
	return s.sessions.ListTrace(ctx, s.db, sessionID, stage, limit, offset)
}

func (s *AccessService) ListTerminalRecording(ctx context.Context, actor, sessionID, channelID string, limit, offset int) ([]domain.TerminalRecordingFrame, error) {
	readAll, _, err := s.sessionRecordAccess(ctx, actor, false)
	if err != nil {
		return nil, err
	}
	if err := validateUUID(sessionID, "session ID"); err != nil {
		return nil, err
	}
	if err := validateUUID(channelID, "terminal channel ID"); err != nil {
		return nil, err
	}
	if _, err := s.sessions.GetRecord(ctx, s.db, actor, readAll, sessionID); err != nil {
		return nil, err
	}
	return s.sessions.ListTerminalRecording(ctx, s.db, sessionID, channelID, limit, offset)
}
