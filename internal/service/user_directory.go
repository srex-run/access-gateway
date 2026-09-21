package service

import (
	"context"
	"strings"

	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/security"
)

func (s *AccessService) ListUsers(ctx context.Context, actor, search string, activeOnly bool, limit, offset int) ([]repository.UserSummary, error) {
	if err := s.Authorize(ctx, actor, authz.PermissionUserRead); err != nil {
		return nil, err
	}
	search = strings.TrimSpace(search)
	if len(search) > 128 || limit < 1 || limit > 100 || offset < 0 {
		return nil, requestValidation("账户搜索条件或分页参数无效")
	}
	return s.users.ListDirectory(ctx, s.db, search, activeOnly, limit, offset)
}

func (s *AccessService) ListAssetApprovers(ctx context.Context, actor, assetID string) ([]repository.AssetApproverSummary, error) {
	if err := s.requireAdmin(ctx, actor); err != nil {
		return nil, err
	}
	if validateUUID(assetID, "asset ID") != nil {
		return nil, requestValidation("请选择有效资产")
	}
	return s.assets.ListApproverDirectory(ctx, s.db, assetID)
}

func (s *AccessService) ListRequestApprovers(ctx context.Context, actor, assetID string) ([]repository.AssetApproverSummary, error) {
	// Apply the same visibility checks as the asset's requestable ports.
	if _, err := s.ListAssetPorts(ctx, actor, assetID); err != nil {
		return nil, err
	}
	return s.assets.ListApproverDirectory(ctx, s.db, assetID)
}

type CreateLocalUserInput struct {
	Username string `json:"username"`
	Nickname string `json:"nickname"`
	Password string `json:"password"`
}

func (s *AccessService) CreateLocalUser(ctx context.Context, actor string, input CreateLocalUserInput) (repository.UserSummary, error) {
	if err := s.Authorize(ctx, actor, authz.PermissionUserManage); err != nil {
		return repository.UserSummary{}, err
	}
	username, err := security.NormalizeUsername(input.Username)
	if err != nil {
		return repository.UserSummary{}, requestValidation("用户名需为 3–64 位字母、数字、点、下划线或连字符")
	}
	nickname := strings.TrimSpace(input.Nickname)
	if nickname == "" {
		nickname = username
	}
	if !ValidAccountName(nickname) {
		return repository.UserSummary{}, requestValidation("请填写有效昵称，最多 128 字节")
	}
	if len(input.Password) < 12 || len(input.Password) > 72 {
		return repository.UserSummary{}, requestValidation("密码需为 12–72 字节")
	}
	hash, err := security.HashPassword(input.Password)
	input.Password = ""
	if err != nil {
		return repository.UserSummary{}, err
	}
	var user domain.User
	err = s.mutateIAM(ctx, actor, authz.PermissionUserManage, func(q repository.DBTX) error {
		var err error
		user, err = s.users.Create(ctx, q, domain.User{ID: id.New(), Username: username, Nickname: nickname, Status: domain.UserStatusActive})
		if err != nil {
			return err
		}
		if err := s.users.CreateLocalCredential(ctx, q, repository.LocalCredential{UserID: user.ID, Username: username, PasswordHash: hash}); err != nil {
			return err
		}
		return s.appendAudit(ctx, q, domain.AuditEvent{EventType: "user.local_created", ActorType: "admin", ActorID: &actor, SubjectUserID: &user.ID, Result: stringPtr("success")})
	})
	return repository.UserSummary{ID: user.ID, Nickname: user.Nickname, Username: user.Username, Status: string(user.Status), CreatedAt: user.CreatedAt, Labels: user.Labels, Revision: user.Revision}, err
}
