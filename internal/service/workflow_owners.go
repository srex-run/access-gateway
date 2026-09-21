package service

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/label"
	"github.com/srex-run/access-gateway/internal/repository"
)

const assetOwnerLabel = "owner"

func (s *AccessService) validateAssetOwner(ctx context.Context, q repository.DBTX, labels label.Labels) error {
	ownerID := labels[assetOwnerLabel]
	if ownerID == "" {
		return nil
	}
	if validateUUID(ownerID, "owner") != nil {
		return requestValidation("owner 标签请选择负责人账户")
	}
	user, err := s.users.GetByID(ctx, q, ownerID)
	if errors.Is(err, repository.ErrNotFound) || err == nil && user.Status != domain.UserStatusActive {
		return requestValidation("owner 负责人账户不存在或已停用")
	}
	if err != nil {
		return err
	}
	if err := s.authorizeIn(ctx, q, ownerID, authz.PermissionApprovalManage); err != nil {
		if errors.Is(err, ErrForbidden) {
			return requestValidation("owner 负责人需要具备审批权限，请先为该账户配置审批角色")
		}
		return err
	}
	return nil
}

// An explicit owner is authoritative. Existing rules remain available for
// assets without an owner label; they cannot add candidates to a named owner.
func matchesAssetOwner(labels label.Labels, user domain.User, selectors []label.Selector) bool {
	if ownerID := labels[assetOwnerLabel]; ownerID != "" {
		return strings.EqualFold(user.ID, ownerID)
	}
	return slices.ContainsFunc(selectors, func(selector label.Selector) bool { return selector.Matches(user.Labels) })
}
