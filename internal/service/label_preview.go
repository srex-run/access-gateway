package service

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/label"
	"github.com/srex-run/access-gateway/internal/repository"
)

type LabelPreviewInput struct {
	UserSelector  string `json:"user_selector"`
	RoleSelector  string `json:"role_selector"`
	AssetSelector string `json:"asset_selector"`
	UserOffset    int    `json:"user_offset"`
	RoleOffset    int    `json:"role_offset"`
	AssetOffset   int    `json:"asset_offset"`
	Limit         int    `json:"limit"`
}

type LabelMatch struct {
	ID     string       `json:"id"`
	Name   string       `json:"name"`
	Labels label.Labels `json:"labels"`
}

type LabelMatchPage struct {
	Items  []LabelMatch `json:"items"`
	Total  int          `json:"total"`
	Offset int          `json:"offset"`
	Limit  int          `json:"limit"`
}

type LabelPreview struct {
	Users  LabelMatchPage `json:"users"`
	Roles  LabelMatchPage `json:"roles"`
	Assets LabelMatchPage `json:"assets"`
}

func (s *AccessService) PreviewRoleBinding(ctx context.Context, actor string, input LabelPreviewInput) (LabelPreview, error) {
	return s.previewLabels(ctx, actor, input, false)
}

func (s *AccessService) PreviewOwnership(ctx context.Context, actor string, input LabelPreviewInput) (LabelPreview, error) {
	return s.previewLabels(ctx, actor, input, true)
}

func (s *AccessService) previewLabels(ctx context.Context, actor string, input LabelPreviewInput, ownership bool) (LabelPreview, error) {
	if input.Limit == 0 {
		input.Limit = 20
	}
	if input.Limit < 1 || input.Limit > 50 || input.UserOffset < 0 || input.UserOffset > 10000 || input.RoleOffset < 0 || input.RoleOffset > 1000 || input.AssetOffset < 0 || input.AssetOffset > 10000 {
		return LabelPreview{}, ErrValidation
	}
	userSelector, err := label.BindingSelector(input.UserSelector)
	if err != nil {
		return LabelPreview{}, requestValidation(err.Error())
	}
	targetSelector := input.RoleSelector
	permission := authz.PermissionRoleManage
	if ownership {
		targetSelector = input.AssetSelector
		permission = authz.PermissionWorkflowManage
	}
	target, err := label.BindingSelector(targetSelector)
	if err != nil {
		return LabelPreview{}, requestValidation(err.Error())
	}
	users, roles, assets := []LabelMatch{}, []LabelMatch{}, []LabelMatch{}
	err = s.readIAM(ctx, func(q repository.DBTX) error {
		if err := s.authorizeIn(ctx, q, actor, permission); err != nil {
			return err
		}
		subjects, err := (repository.IAMRepository{}).ListSubjects(ctx, q)
		if err != nil {
			return err
		}
		if len(subjects) > 10000 {
			return fmt.Errorf("用户目录超过标签匹配上限: %w", ErrStateConflict)
		}
		for _, user := range subjects {
			if userSelector.Matches(user.Labels) {
				users = append(users, LabelMatch{ID: user.ID, Name: user.Nickname, Labels: user.Labels})
			}
		}
		if ownership {
			directory, err := (repository.WorkflowRepository{}).ListLabeledAssets(ctx, q)
			if err != nil {
				return err
			}
			if len(directory) > 10000 {
				return fmt.Errorf("资源目录超过标签匹配上限: %w", ErrStateConflict)
			}
			for _, asset := range directory {
				if target.Matches(asset.Labels) {
					assets = append(assets, LabelMatch{ID: asset.ID, Name: asset.Name, Labels: asset.Labels})
				}
			}
		} else {
			definitions, err := (repository.IAMRepository{}).ListRoles(ctx, q)
			if err != nil {
				return err
			}
			if len(definitions) > 1000 {
				return ErrStateConflict
			}
			for _, role := range definitions {
				if role.Enabled && target.Matches(role.Labels) {
					roles = append(roles, LabelMatch{ID: role.Name, Name: role.Name, Labels: role.Labels})
				}
			}
		}
		return nil
	})
	if err != nil {
		return LabelPreview{}, err
	}
	return LabelPreview{Users: labelMatchPage(users, input.UserOffset, input.Limit), Roles: labelMatchPage(roles, input.RoleOffset, input.Limit), Assets: labelMatchPage(assets, input.AssetOffset, input.Limit)}, nil
}

func labelMatchPage(values []LabelMatch, offset, limit int) LabelMatchPage {
	slices.SortFunc(values, func(a, b LabelMatch) int {
		if order := strings.Compare(a.Name, b.Name); order != 0 {
			return order
		}
		return strings.Compare(a.ID, b.ID)
	})
	page := LabelMatchPage{Items: []LabelMatch{}, Total: len(values), Offset: offset, Limit: limit}
	if offset < len(values) {
		page.Items = values[offset:min(offset+limit, len(values))]
	}
	return page
}
