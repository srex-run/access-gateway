package service

import (
	"context"
	"errors"
	"slices"

	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/repository"
)

type WorkflowStage struct {
	Level      int    `json:"level"`
	Name       string `json:"name"`
	Required   int    `json:"required"`
	Approved   int    `json:"approved"`
	Candidates int    `json:"candidates"`
	Status     string `json:"status"`
}

func workflowStages(approvals []domain.Approval, status domain.AccessRequestStatus, current int) []WorkflowStage {
	byLevel := map[int]*WorkflowStage{}
	for _, approval := range approvals {
		stage, ok := byLevel[approval.ApprovalLevel]
		if !ok {
			stage = &WorkflowStage{Level: approval.ApprovalLevel, Name: approval.StepName, Required: 1}
			byLevel[approval.ApprovalLevel] = stage
		}
		stage.Candidates++
		stage.Required = max(stage.Required, approval.RequiredApprovals)
		if approval.Decision != nil {
			if *approval.Decision == domain.ApprovalApproved {
				stage.Approved++
			} else if *approval.Decision == domain.ApprovalRejected {
				stage.Status = "rejected"
			}
		}
	}
	stages := make([]WorkflowStage, 0, len(byLevel))
	for _, stage := range byLevel {
		switch {
		case stage.Status == "rejected":
		case stage.Approved >= stage.Required:
			stage.Status = "approved"
		case status == domain.AccessRequestApprovalExpired:
			stage.Status = "expired"
		case status == domain.AccessRequestCancelled:
			stage.Status = "cancelled"
		case status != domain.AccessRequestPendingApproval:
			stage.Status = "skipped"
		case stage.Level == current:
			stage.Status = "pending"
		default:
			stage.Status = "waiting"
		}
		stages = append(stages, *stage)
	}
	slices.SortFunc(stages, func(a, b WorkflowStage) int { return a.Level - b.Level })
	return stages
}

func (s *AccessService) workflowDecision(ctx context.Context, q repository.DBTX, actor string, request domain.AccessRequest, approvals []domain.Approval, view *WorkflowView) error {
	if view.Status != domain.AccessRequestPendingApproval {
		view.DecisionReason = "审批已结束"
		if view.Status == domain.AccessRequestApprovalExpired {
			view.DecisionReason = "审批已过期"
		}
		return nil
	}
	if actor == request.ApplicantID {
		view.DecisionReason = "申请人不能审批自己的申请"
		return nil
	}
	view.DecisionReason = "当前节点未分配给你"
	for _, approval := range approvals {
		if approval.ApproverID != actor || approval.ApprovalLevel != view.CurrentLevel {
			continue
		}
		if approval.Decision != nil {
			view.DecisionReason = "你已处理当前节点"
			return nil
		}
		if err := s.validateWorkflowVoter(ctx, q, request, approval); err != nil {
			if errors.Is(err, ErrForbidden) {
				view.DecisionReason = "你的审批授权或负责人匹配已变更"
				return nil
			}
			if errors.Is(err, ErrStateConflict) {
				view.DecisionReason = "审批状态已变化，请刷新"
				return nil
			}
			return err
		}
		view.CanDecide, view.ApprovalID, view.DecisionReason = true, approval.ID, ""
		return nil
	}
	return nil
}
