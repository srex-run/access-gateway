package service

import (
	"context"
	"slices"

	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/domain"
)

func (s *AccessService) operationAuditReadFilter(ctx context.Context, userID string, filter domain.OperationAuditFilter) (domain.OperationAuditFilter, error) {
	permissions, err := s.EffectivePermissions(ctx, userID)
	if err != nil {
		return filter, err
	}
	if !slices.Contains(permissions, authz.PermissionAuditRead) {
		if !slices.Contains(permissions, authz.PermissionSessionManage) {
			return filter, ErrForbidden
		}
		if filter.SubjectUserID != "" && filter.SubjectUserID != userID {
			return filter, ErrForbidden
		}
		filter.SubjectUserID = userID
	}
	return filter, validateOperationAuditFilter(filter)
}

func (s *AccessService) ListOperationAuditSessions(ctx context.Context, userID string, filter domain.OperationAuditFilter) ([]domain.OperationAuditSession, error) {
	filter, err := s.operationAuditReadFilter(ctx, userID, filter)
	if err != nil {
		return nil, err
	}
	return s.accessEvidence.ListOperationSessions(ctx, s.db, filter)
}
