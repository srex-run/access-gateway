package service

import (
	"context"
	"strings"

	"github.com/srex-run/access-gateway/internal/approvalflow"
	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/repository"
)

// Asset managers may choose a workflow without receiving permission to edit
// workflow definitions, approver rules or role grants.
func (s *AccessService) ListAssetWorkflows(ctx context.Context, actor string) ([]approvalflow.Definition, error) {
	if err := s.Authorize(ctx, actor, authz.PermissionCatalogManage); err != nil {
		return nil, err
	}
	values, err := (repository.WorkflowRepository{}).List(ctx, s.db)
	if err != nil {
		return nil, err
	}
	if len(values) > 1000 {
		return nil, ErrStateConflict
	}
	return values, nil
}

func validateAssetWorkflow(ctx context.Context, q repository.DBTX, workflowID string) (*string, error) {
	workflowID = strings.TrimSpace(workflowID)
	if workflowID == "" {
		return nil, nil
	}
	if err := validateUUID(workflowID, "workflow ID"); err != nil {
		return nil, requestValidation("请选择有效的审批流程")
	}
	values, err := (repository.WorkflowRepository{}).List(ctx, q)
	if err != nil {
		return nil, err
	}
	if len(values) > 1000 {
		return nil, ErrStateConflict
	}
	for _, flow := range values {
		if flow.ID != workflowID {
			continue
		}
		if !flow.Enabled {
			return nil, requestValidation("所选审批流程已停用，请选择启用的流程")
		}
		return &workflowID, nil
	}
	return nil, requestValidation("所选审批流程不存在，请刷新后重新选择")
}

func selectApprovalWorkflow(flows []approvalflow.Definition, workflowID *string) (*approvalflow.Definition, error) {
	if workflowID == nil || strings.TrimSpace(*workflowID) == "" {
		return nil, requestValidation("该资产尚未关联审批流程，请管理员在资产配置中选择审批流程")
	}
	for _, flow := range flows {
		if flow.ID != *workflowID {
			continue
		}
		if !flow.Enabled {
			return nil, requestValidation("资产关联的审批流程已停用，请管理员重新选择审批流程")
		}
		return &flow, nil
	}
	return nil, requestValidation("资产关联的审批流程不存在，请管理员重新选择审批流程")
}
