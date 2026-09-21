package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/repository"
)

type GrantRoleInput struct {
	UserID string
	Role   string
}

func (s *AccessService) GrantRole(ctx context.Context, actorID string, input GrantRoleInput) (domain.RoleAssignment, error) {
	if err := s.Authorize(ctx, actorID, authz.PermissionRoleManage); err != nil {
		return domain.RoleAssignment{}, err
	}
	input.UserID = strings.TrimSpace(input.UserID)
	input.Role = strings.TrimSpace(input.Role)
	if err := validateUUID(input.UserID, "role user ID"); err != nil {
		return domain.RoleAssignment{}, err
	}
	if _, err := s.users.GetByID(ctx, s.db, input.UserID); err != nil {
		return domain.RoleAssignment{}, fmt.Errorf("validate role user: %w", err)
	}
	value := domain.RoleAssignment{ID: id.New(), UserID: input.UserID, Role: input.Role, GrantedBy: actorID}
	err := s.mutateIAM(ctx, actorID, authz.PermissionRoleManage, func(q repository.DBTX) error {
		definitions, err := (repository.IAMRepository{}).ListRoles(ctx, q)
		if err != nil {
			return err
		}
		found := false
		for _, role := range definitions {
			if role.Name == input.Role && role.Enabled {
				found = true
			}
		}
		if !found {
			return requestValidation("角色不存在或已停用")
		}
		var createErr error
		value, createErr = s.roles.Create(ctx, q, value)
		if createErr != nil {
			return createErr
		}
		return s.appendAudit(ctx, q, domain.AuditEvent{
			EventType: "rbac.role_granted", ActorType: "admin", ActorID: stringPtr(actorID),
			SubjectUserID: stringPtr(value.UserID), Result: stringPtr("success"),
			Metadata: map[string]any{"assignment_id": value.ID, "role": value.Role},
		})
	})
	if err != nil {
		return domain.RoleAssignment{}, fmt.Errorf("grant role: %w", err)
	}
	return value, nil
}

func (s *AccessService) RevokeRole(ctx context.Context, actorID, assignmentID string) (domain.RoleAssignment, error) {
	if err := s.Authorize(ctx, actorID, authz.PermissionRoleManage); err != nil {
		return domain.RoleAssignment{}, err
	}
	if err := validateUUID(assignmentID, "role assignment ID"); err != nil {
		return domain.RoleAssignment{}, err
	}
	existing, err := s.roles.GetByID(ctx, s.db, assignmentID)
	if err != nil {
		return domain.RoleAssignment{}, fmt.Errorf("load role assignment: %w", err)
	}
	if existing.RevokedAt != nil {
		return existing, nil
	}
	if existing.UserID == actorID && existing.Role == string(authz.RoleAdmin) {
		return domain.RoleAssignment{}, fmt.Errorf("an administrator cannot revoke their own admin role: %w", ErrValidation)
	}
	var value domain.RoleAssignment
	err = s.mutateIAM(ctx, actorID, authz.PermissionRoleManage, func(q repository.DBTX) error {
		var revokeErr error
		value, revokeErr = s.roles.Revoke(ctx, q, assignmentID)
		if revokeErr != nil {
			return revokeErr
		}
		return s.appendAudit(ctx, q, domain.AuditEvent{
			EventType: "rbac.role_revoked", ActorType: "admin", ActorID: stringPtr(actorID),
			SubjectUserID: stringPtr(value.UserID), Result: stringPtr("success"),
			Metadata: map[string]any{"assignment_id": value.ID, "role": value.Role},
		})
	})
	if err != nil {
		return domain.RoleAssignment{}, fmt.Errorf("revoke role: %w", err)
	}
	return value, nil
}

func (s *AccessService) ListRoleAssignments(ctx context.Context, actorID, userID string) ([]domain.RoleAssignment, error) {
	if err := s.Authorize(ctx, actorID, authz.PermissionRoleManage); err != nil {
		return nil, err
	}
	if err := validateUUID(userID, "role user ID"); err != nil {
		return nil, err
	}
	values, err := s.roles.ListActiveByUser(ctx, s.db, userID)
	if err != nil {
		return nil, fmt.Errorf("list role assignments: %w", err)
	}
	return values, nil
}

func assignedRole(value string) (authz.Role, bool) {
	role := authz.Role(strings.TrimSpace(value))
	switch role {
	case authz.RoleAdmin, authz.RoleAuditor, authz.RoleCatalogAdmin, authz.RoleSecurityAdmin, authz.RoleSRE:
		return role, true
	default:
		return "", false
	}
}
