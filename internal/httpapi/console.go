package httpapi

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/emicklei/go-restful/v3"

	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/service"
)

func (s *Server) identity(request *restful.Request, response *restful.Response) {
	userID, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	ctx := request.Request.Context()
	if err := s.requireActive(ctx, userID); err != nil {
		s.writeError(response, err)
		return
	}
	permissions := make([]authz.Permission, 0, 8)
	if provider, ok := s.Service.(interface {
		EffectivePermissions(context.Context, string) ([]authz.Permission, error)
	}); ok {
		var err error
		permissions, err = provider.EffectivePermissions(ctx, userID)
		if err != nil {
			s.writeError(response, err)
			return
		}
	} else {
		for _, entry := range authz.Catalog() {
			permission := entry.Key
			err := s.Service.Authorize(ctx, userID, permission)
			if errors.Is(err, service.ErrForbidden) {
				continue
			}
			if err != nil {
				s.writeError(response, err)
				return
			}
			permissions = append(permissions, permission)
		}
	}
	_ = response.WriteEntity(struct {
		UserID      string             `json:"user_id"`
		Permissions []authz.Permission `json:"permissions"`
	}{UserID: userID, Permissions: permissions})
}

type approvalResponse struct {
	Emergency         bool                     `json:"emergency"`
	RequiredApprovals int                      `json:"required_approvals"`
	StepName          string                   `json:"step_name"`
	ID                string                   `json:"id"`
	RequestID         string                   `json:"request_id"`
	ApproverID        string                   `json:"approver_id"`
	ApprovalLevel     int                      `json:"approval_level"`
	Decision          *domain.ApprovalDecision `json:"decision,omitempty"`
	Comment           *string                  `json:"comment,omitempty"`
	DecidedAt         *time.Time               `json:"decided_at,omitempty"`
	CreatedAt         time.Time                `json:"created_at"`
}

func toApprovalResponse(value domain.Approval) approvalResponse {
	return approvalResponse{
		Emergency:         value.Emergency,
		RequiredApprovals: value.RequiredApprovals, StepName: value.StepName,
		ID: value.ID, RequestID: value.RequestID, ApproverID: value.ApproverID,
		ApprovalLevel: value.ApprovalLevel, Decision: value.Decision,
		Comment: value.Comment, DecidedAt: value.DecidedAt, CreatedAt: value.CreatedAt,
	}
}

func (s *Server) listPendingApprovals(request *restful.Request, response *restful.Response) {
	userID, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	limit, offset, err := parsePageQuery(request, 20, 100)
	if err != nil {
		s.writeError(response, err)
		return
	}
	values, err := s.Service.ListPendingApprovals(request.Request.Context(), userID, limit, offset)
	if err != nil {
		s.writeError(response, err)
		return
	}
	result := make([]approvalResponse, 0, len(values))
	for _, value := range values {
		result = append(result, toApprovalResponse(value))
	}
	_ = response.WriteEntity(result)
}

func (s *Server) approve(request *restful.Request, response *restful.Response) {
	s.decideApproval(request, response, domain.ApprovalApproved)
}

func (s *Server) reject(request *restful.Request, response *restful.Response) {
	s.decideApproval(request, response, domain.ApprovalRejected)
}

func (s *Server) decideApproval(request *restful.Request, response *restful.Response, decision domain.ApprovalDecision) {
	userID, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	var body struct {
		Comment *string `json:"comment"`
	}
	if err := decodeJSONBody(request.Request, &body, false); err != nil {
		s.writeError(response, fmt.Errorf("decode approval decision: %w", service.ErrValidation))
		return
	}
	value, err := s.Service.DecideApproval(request.Request.Context(), userID, request.PathParameter("approval_id"), decision, body.Comment)
	if err != nil {
		s.writeError(response, err)
		return
	}
	_ = response.WriteEntity(struct {
		Request  accessRequestResponse `json:"request"`
		Approval approvalResponse      `json:"approval"`
	}{Request: toAccessRequestResponse(value.Request), Approval: toApprovalResponse(value.Approval)})
}
