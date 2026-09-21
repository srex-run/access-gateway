package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/mail"
	"slices"
	"strings"

	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/iam"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/label"
	"github.com/srex-run/access-gateway/internal/repository"
)

// readIAM prevents combining an old subject label set with a newly committed
// binding/role definition. Writers use the exclusive side of this same lock.
func (s *AccessService) readIAM(ctx context.Context, read func(repository.DBTX) error) error {
	return InTx(ctx, s.db, func(q repository.DBTX) error {
		if err := (repository.IAMRepository{}).Lock(ctx, q, true); err != nil {
			return err
		}
		return read(q)
	})
}

func (s *AccessService) resolvedRoles(ctx context.Context, q repository.DBTX, user domain.User) ([]iam.Role, error) {
	grants, err := s.userRoleGrants(ctx, q, user)
	if err != nil {
		return nil, err
	}
	roles := make([]iam.Role, 0, len(grants))
	for _, grant := range grants {
		roles = append(roles, grant.Role)
	}
	return roles, nil
}

func (s *AccessService) userRoleGrants(ctx context.Context, q repository.DBTX, user domain.User) ([]iam.RoleGrant, error) {
	repo := repository.IAMRepository{}
	roles, err := repo.ListRoles(ctx, q)
	if err != nil {
		return nil, err
	}
	bindings, err := repo.ListBindings(ctx, q)
	if err != nil {
		return nil, err
	}
	if len(roles) > 1000 || len(bindings) > 1000 {
		return nil, fmt.Errorf("IAM 配置数量超出上限: %w", ErrStateConflict)
	}
	assignments, err := s.roles.ListActiveByUser(ctx, q, user.ID)
	if err != nil {
		return nil, err
	}
	explicit := []iam.DirectGrant{}
	for _, assignment := range assignments {
		explicit = append(explicit, iam.DirectGrant{Role: assignment.Role, Source: iam.GrantSource{Kind: "direct", ID: assignment.ID, Name: "直接角色授权"}})
	}
	if s.configuredAdmin(user) {
		explicit = append(explicit, iam.DirectGrant{Role: "admin", Source: iam.GrantSource{Kind: "bootstrap", Name: "启动配置管理员"}})
	}
	return iam.NewResolver(roles, bindings).Explain(user.Labels, explicit), nil
}

func (s *AccessService) rolePermissions(roles []iam.Role) []authz.Permission {
	permissions := []authz.Permission{}
	for _, entry := range authz.Catalog() {
		if s.allowedRoles(roles, entry.Key) {
			permissions = append(permissions, entry.Key)
		}
	}
	return permissions
}

// EffectivePermissions returns the identity's complete permission set from one
// locked read, including the active status check.
func (s *AccessService) EffectivePermissions(ctx context.Context, userID string) ([]authz.Permission, error) {
	if !id.IsUUID(userID) {
		return nil, ErrForbidden
	}
	permissions := []authz.Permission{}
	err := s.readIAM(ctx, func(q repository.DBTX) error {
		user, err := s.users.GetByID(ctx, q, userID)
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
		permissions = s.rolePermissions(roles)
		return nil
	})
	return permissions, err
}

func (s *AccessService) configuredAdmin(user domain.User) bool {
	return s.isAdmin(user.ID) || s.isConfiguredAdminReference(user.FeishuOpenID) || (user.FeishuUnionID != nil && s.isConfiguredAdminReference(*user.FeishuUnionID))
}

func (s *AccessService) allowedRoles(roles []iam.Role, permission authz.Permission) bool {
	if !authz.Known(permission) {
		return false
	}
	for _, role := range roles {
		if !role.Enabled {
			continue
		}
		if s.authorizer.AllowedPermissions(role.Permissions, permission) {
			return true
		}
	}
	return false
}

func (s *AccessService) authorizeIn(ctx context.Context, q repository.DBTX, userID string, permission authz.Permission) error {
	if !id.IsUUID(userID) {
		return ErrForbidden
	}
	user, err := s.users.GetByID(ctx, q, userID)
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
	if !s.allowedRoles(roles, permission) {
		return fmt.Errorf("permission %s is required: %w", permission, ErrForbidden)
	}
	return nil
}

// mutateIAM serializes authorization changes and forbids removing the last
// explicit active administrator. Selector grants are never the recovery account.
func (s *AccessService) mutateIAM(ctx context.Context, actor string, permission authz.Permission, mutate func(repository.DBTX) error) error {
	return InTx(ctx, s.db, func(q repository.DBTX) error {
		repo := repository.IAMRepository{}
		if err := repo.Lock(ctx, q, false); err != nil {
			return err
		}
		if err := s.authorizeIn(ctx, q, actor, permission); err != nil {
			return err
		}
		before, err := s.explicitAdmins(ctx, q)
		if err != nil {
			return err
		}
		if err := mutate(q); err != nil {
			return err
		}
		after, err := s.explicitAdmins(ctx, q)
		if err != nil {
			return err
		}
		if before > 0 && after == 0 {
			return requestValidation("至少保留一个启用且直接授权的管理员账户")
		}
		return nil
	})
}

func (s *AccessService) explicitAdmins(ctx context.Context, q repository.DBTX) (int, error) {
	repo := repository.IAMRepository{}
	users, err := repo.ListSubjects(ctx, q)
	if err != nil {
		return 0, err
	}
	assignments, err := repo.ListAssignments(ctx, q)
	if err != nil {
		return 0, err
	}
	if len(users) > 10000 || len(assignments) > 100000 {
		return 0, fmt.Errorf("IAM 用户数量超出上限: %w", ErrStateConflict)
	}
	admins := map[string]bool{}
	for _, a := range assignments {
		if a.Role == "admin" {
			admins[a.UserID] = true
		}
	}
	count := 0
	for _, user := range users {
		if admins[user.ID] || s.configuredAdmin(user) {
			count++
		}
	}
	return count, nil
}

func (s *AccessService) ListIAMRoles(ctx context.Context, actor string) ([]iam.Role, error) {
	if err := s.Authorize(ctx, actor, authz.PermissionRoleManage); err != nil {
		return nil, err
	}
	values, err := (repository.IAMRepository{}).ListRoles(ctx, s.db)
	if err != nil {
		return nil, err
	}
	if len(values) > 1000 {
		return nil, ErrStateConflict
	}
	return values, nil
}

func (s *AccessService) SaveIAMRole(ctx context.Context, actor string, input iam.Role) (iam.Role, error) {
	if input.Revision < 0 {
		return input, ErrValidation
	}
	if input.Labels == nil {
		input.Labels = label.Labels{}
	}
	var result iam.Role
	err := s.mutateIAM(ctx, actor, authz.PermissionRoleManage, func(q repository.DBTX) error {
		var err error
		roles, err := (repository.IAMRepository{}).ListRoles(ctx, q)
		if err != nil {
			return err
		}
		if len(roles) >= 1000 && input.Revision == 0 {
			return ErrValidation
		}
		var existing *iam.Role
		for _, role := range roles {
			if role.Name == input.Name {
				existing = &role
				break
			}
		}
		if err := validateRoleChange(input, existing); err != nil {
			return requestValidation(err.Error())
		}
		// Classification comes from the stored role, never from the request.
		input.BuiltIn = existing != nil && existing.BuiltIn
		result, err = (repository.IAMRepository{}).SaveRole(ctx, q, input)
		if err != nil {
			return revisionError(err)
		}
		return s.iamAudit(ctx, q, actor, "iam.role_saved", map[string]any{"role": result.Name, "revision": result.Revision, "permissions": result.Permissions, "labels": result.Labels, "enabled": result.Enabled})
	})
	return result, err
}

func validateRoleChange(input iam.Role, existing *iam.Role) error {
	if existing == nil && input.BuiltIn {
		return fmt.Errorf("不能创建内置角色")
	}
	if err := input.Labels.Validate(); err != nil {
		return err
	}
	editable := input
	editable.Labels = maps.Clone(input.Labels)
	for key, value := range input.Labels {
		if label.IsSystemKey(key) {
			if existing == nil {
				return fmt.Errorf("%s 为系统托管标签，不能修改", key)
			}
			if previous, ok := existing.Labels[key]; !ok || previous != value {
				return fmt.Errorf("%s 为系统托管标签，不能修改", key)
			}
			delete(editable.Labels, key)
		}
	}
	if existing != nil {
		for key, value := range existing.Labels {
			if label.IsSystemKey(key) {
				if actual, ok := input.Labels[key]; !ok || actual != value {
					return fmt.Errorf("%s 为系统托管标签，不能删除或修改", key)
				}
			}
		}
		if existing.BuiltIn && (existing.Name == string(authz.RoleAdmin) || existing.Name == string(authz.RoleUser)) && !input.Enabled {
			return fmt.Errorf("内置管理员和普通用户角色不能停用")
		}
	}
	if err := editable.Validate(); err != nil {
		return err
	}
	isAdmin := existing != nil && existing.BuiltIn && existing.Name == string(authz.RoleAdmin)
	if isAdmin && !slices.Contains(input.Permissions, authz.PermissionRoleManage) {
		return fmt.Errorf("平台管理员必须保留授权管理权限")
	}
	return nil
}

func (s *AccessService) ListIAMBindings(ctx context.Context, actor string) ([]iam.Binding, error) {
	if err := s.Authorize(ctx, actor, authz.PermissionRoleManage); err != nil {
		return nil, err
	}
	values, err := (repository.IAMRepository{}).ListBindings(ctx, s.db)
	if err != nil {
		return nil, err
	}
	if len(values) > 1000 {
		return nil, ErrStateConflict
	}
	return values, nil
}

func (s *AccessService) SaveIAMBinding(ctx context.Context, actor string, input iam.Binding) (iam.Binding, error) {
	if err := input.Validate(); err != nil {
		return input, requestValidation(err.Error())
	}
	if err := prepareRevisionID(&input.ID, input.Revision); err != nil {
		return input, err
	}
	var result iam.Binding
	err := s.mutateIAM(ctx, actor, authz.PermissionRoleManage, func(q repository.DBTX) error {
		repo := repository.IAMRepository{}
		bindings, err := repo.ListBindings(ctx, q)
		if err != nil {
			return err
		}
		if len(bindings) >= 1000 && input.Revision == 0 {
			return ErrValidation
		}
		roles, err := repo.ListRoles(ctx, q)
		if err != nil {
			return err
		}
		if input.Enabled && !iam.MatchesRole(input.RoleSelector, roles) {
			return requestValidation("角色条件没有匹配到角色，请先配置角色标签")
		}
		result, err = repo.SaveBinding(ctx, q, input)
		if err != nil {
			return revisionError(err)
		}
		return s.iamAudit(ctx, q, actor, "iam.binding_saved", map[string]any{"binding_id": result.ID, "revision": result.Revision, "user_selector": result.UserSelector, "role_selector": result.RoleSelector, "enabled": result.Enabled})
	})
	return result, err
}

type UpdateUserInput struct {
	Nickname   string            `json:"nickname"`
	Email      string            `json:"email"`
	Department string            `json:"department"`
	Status     domain.UserStatus `json:"status"`
	Labels     label.Labels      `json:"labels"`
	Revision   int64             `json:"revision"`
}

type UserDetail struct {
	repository.UserSummary
	Roles       []iam.Role         `json:"roles"`
	RoleGrants  []iam.RoleGrant    `json:"role_grants"`
	Permissions []authz.Permission `json:"permissions"`
	CanEdit     bool               `json:"can_edit"`
	CanLabel    bool               `json:"can_label"`
}

func (s *AccessService) GetManagedUser(ctx context.Context, actor, userID string) (UserDetail, error) {
	if err := validateUUID(userID, "user ID"); err != nil {
		return UserDetail{}, err
	}
	var detail UserDetail
	err := s.readIAM(ctx, func(q repository.DBTX) error {
		if err := s.authorizeIn(ctx, q, actor, authz.PermissionUserRead); err != nil {
			return err
		}
		var err error
		detail, err = s.managedUserDetail(ctx, q, actor, userID)
		return err
	})
	return detail, err
}

func (s *AccessService) managedUserDetail(ctx context.Context, q repository.DBTX, actor, userID string) (UserDetail, error) {
	detail := UserDetail{Roles: []iam.Role{}, RoleGrants: []iam.RoleGrant{}, Permissions: []authz.Permission{}}
	var err error
	detail.UserSummary, err = s.users.DirectoryByID(ctx, q, userID)
	if err != nil {
		return detail, err
	}
	user, err := s.users.GetByID(ctx, q, userID)
	if err != nil {
		return detail, err
	}
	grants, err := s.userRoleGrants(ctx, q, user)
	if err != nil {
		return detail, err
	}
	privileged := false
	for _, grant := range grants {
		if grant.Role.Name != "user" {
			privileged = true
		}
	}
	if user.Status == domain.UserStatusActive {
		detail.RoleGrants = grants
		for _, grant := range grants {
			detail.Roles = append(detail.Roles, grant.Role)
		}
		detail.Permissions = s.rolePermissions(detail.Roles)
	}
	viewer, err := s.users.GetByID(ctx, q, actor)
	if err != nil {
		return detail, err
	}
	viewerRoles, err := s.resolvedRoles(ctx, q, viewer)
	if err != nil {
		return detail, err
	}
	detail.CanLabel = s.allowedRoles(viewerRoles, authz.PermissionRoleManage) && s.allowedRoles(viewerRoles, authz.PermissionUserManage)
	detail.CanEdit = s.allowedRoles(viewerRoles, authz.PermissionUserManage) && (!privileged || detail.CanLabel)
	return detail, nil
}

func (s *AccessService) UpdateManagedUser(ctx context.Context, actor, userID string, input UpdateUserInput) (UserDetail, error) {
	if err := validateUUID(userID, "user ID"); err != nil {
		return UserDetail{}, err
	}
	input.Nickname, input.Email, input.Department = strings.TrimSpace(input.Nickname), strings.TrimSpace(input.Email), strings.TrimSpace(input.Department)
	if len(input.Nickname) > 128 || len(input.Department) > 128 || input.Revision < 1 || (input.Status != domain.UserStatusActive && input.Status != domain.UserStatusInactive) {
		return UserDetail{}, ErrValidation
	}
	if input.Email != "" {
		address, err := mail.ParseAddress(input.Email)
		if err != nil || address.Address != input.Email || len(input.Email) > 254 {
			return UserDetail{}, requestValidation("邮箱格式无效")
		}
	}
	if err := label.ValidateEditable(input.Labels); err != nil {
		return UserDetail{}, requestValidation(err.Error())
	}
	if input.Labels == nil {
		input.Labels = label.Labels{}
	}
	var result UserDetail
	err := s.mutateIAM(ctx, actor, authz.PermissionUserManage, func(q repository.DBTX) error {
		user, err := s.users.GetByIDForUpdate(ctx, q, userID)
		if err != nil {
			return err
		}
		roles, err := s.resolvedRoles(ctx, q, user)
		if err != nil {
			return err
		}
		privileged := false
		for _, role := range roles {
			if role.Name != "user" {
				privileged = true
			}
		}
		if !maps.Equal(user.Labels, input.Labels) || privileged {
			if err := s.authorizeIn(ctx, q, actor, authz.PermissionRoleManage); err != nil {
				return err
			}
		}
		if actor == userID && input.Status == domain.UserStatusInactive {
			return requestValidation("不能停用当前登录账户")
		}
		if input.Nickname == "" {
			input.Nickname = user.Username
		}
		user.Nickname, user.Email, user.Department, user.Status, user.Labels, user.Revision = input.Nickname, optionalString(input.Email), optionalString(input.Department), input.Status, input.Labels, input.Revision
		if err := s.users.UpdateProfile(ctx, q, user); err != nil {
			return revisionError(err)
		}
		metadata, err := plainMetadata(map[string]any{"revision": input.Revision + 1, "labels": input.Labels, "status": input.Status})
		if err != nil {
			return err
		}
		if err := s.appendAudit(ctx, q, domain.AuditEvent{EventType: "iam.user_updated", ActorType: "admin", ActorID: stringPtr(actor), SubjectUserID: stringPtr(userID), Result: stringPtr("success"), Metadata: metadata}); err != nil {
			return err
		}
		// Authorization precedes the mutation. Self-demotion must still return
		// the committed update instead of failing a second permission check.
		result, err = s.managedUserDetail(ctx, q, actor, userID)
		return err
	})
	if err != nil {
		return UserDetail{}, err
	}
	if input.Status == domain.UserStatusInactive {
		if err := s.enqueueUserRevocations(ctx, userID); err != nil {
			return UserDetail{}, err
		}
	}
	return result, nil
}

func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func (s *AccessService) iamAudit(ctx context.Context, q repository.DBTX, actor, event string, metadata map[string]any) error {
	metadata, err := plainMetadata(metadata)
	if err != nil {
		return err
	}
	return s.appendAudit(ctx, q, domain.AuditEvent{EventType: event, ActorType: "admin", ActorID: stringPtr(actor), Result: stringPtr("success"), Metadata: metadata})
}

func plainMetadata(value map[string]any) (map[string]any, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode governance audit: %w", err)
	}
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("decode governance audit: %w", err)
	}
	return result, nil
}

func revisionError(err error) error {
	if errors.Is(err, repository.ErrNotFound) {
		return fmt.Errorf("配置已更新或不存在，请刷新后重试: %w", ErrStateConflict)
	}
	return err
}

func prepareRevisionID(value *string, revision int64) error {
	if revision < 0 {
		return ErrValidation
	}
	if revision == 0 && *value == "" {
		*value = id.New()
	}
	return validateUUID(*value, "configuration ID")
}
