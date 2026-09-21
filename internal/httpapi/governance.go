package httpapi

import (
	"context"
	"net/http"

	"github.com/emicklei/go-restful/v3"
	"github.com/srex-run/access-gateway/internal/approvalflow"
	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/iam"
	"github.com/srex-run/access-gateway/internal/service"
)

// GovernanceService keeps the user center/workflow API as a module without
// expanding the gateway agent contract or requiring external authentication.
type GovernanceService interface {
	ListIAMRoles(context.Context, string) ([]iam.Role, error)
	SaveIAMRole(context.Context, string, iam.Role) (iam.Role, error)
	ListIAMBindings(context.Context, string) ([]iam.Binding, error)
	SaveIAMBinding(context.Context, string, iam.Binding) (iam.Binding, error)
	GetManagedUser(context.Context, string, string) (service.UserDetail, error)
	UpdateManagedUser(context.Context, string, string, service.UpdateUserInput) (service.UserDetail, error)
	ListWorkflows(context.Context, string) ([]approvalflow.Definition, error)
	SaveWorkflow(context.Context, string, approvalflow.Definition) (approvalflow.Definition, error)
	ListOwnerships(context.Context, string) ([]approvalflow.Ownership, error)
	SaveOwnership(context.Context, string, approvalflow.Ownership) (approvalflow.Ownership, error)
	GetAssetPolicy(context.Context, string, string) (approvalflow.AssetPolicy, error)
	SaveAssetPolicy(context.Context, string, string, approvalflow.AssetPolicy) (approvalflow.AssetPolicy, error)
	GetRequestWorkflow(context.Context, string, string) (service.WorkflowView, error)
	PreviewAssetWorkflow(context.Context, string, string) (service.WorkflowView, error)
	PreviewRoleBinding(context.Context, string, service.LabelPreviewInput) (service.LabelPreview, error)
	PreviewOwnership(context.Context, string, service.LabelPreviewInput) (service.LabelPreview, error)
}

func (s *Server) registerGovernance(ws *restful.WebService) {
	ws.Route(ws.GET("/admin/permissions").To(s.permissionCatalog))
	ws.Route(ws.GET("/admin/roles").To(s.listIAMRoles))
	ws.Route(ws.POST("/admin/roles").To(s.saveIAMRole))
	ws.Route(ws.GET("/admin/role-bindings").To(s.listIAMBindings))
	ws.Route(ws.POST("/admin/role-bindings").To(s.saveIAMBinding))
	ws.Route(ws.POST("/admin/role-bindings/preview").To(s.previewRoleBinding))
	ws.Route(ws.GET("/admin/users/{user_id}").To(s.getManagedUser))
	ws.Route(ws.PATCH("/admin/users/{user_id}").To(s.updateManagedUser))
	ws.Route(ws.GET("/admin/workflows").To(s.listWorkflows))
	ws.Route(ws.GET("/admin/asset-workflows").To(s.listAssetWorkflows))
	ws.Route(ws.POST("/admin/workflows").To(s.saveWorkflow))
	ws.Route(ws.GET("/admin/ownerships").To(s.listOwnerships))
	ws.Route(ws.POST("/admin/ownerships").To(s.saveOwnership))
	ws.Route(ws.POST("/admin/ownerships/preview").To(s.previewOwnership))
	ws.Route(ws.GET("/assets/{asset_id}/labels").To(s.getAssetPolicy))
	ws.Route(ws.PATCH("/admin/assets/{asset_id}/labels").To(s.saveAssetPolicy))
	ws.Route(ws.GET("/assets/{asset_id}/workflow").To(s.previewAssetWorkflow))
	ws.Route(ws.GET("/access-requests/{request_id}/workflow").To(s.getRequestWorkflow))
}

func (s *Server) listAssetWorkflows(req *restful.Request, res *restful.Response) {
	actor, ok := s.currentUser(req, res)
	if !ok {
		return
	}
	provider, ok := s.Service.(interface {
		ListAssetWorkflows(context.Context, string) ([]approvalflow.Definition, error)
	})
	if !ok {
		s.writeError(res, service.ErrNotConfigured)
		return
	}
	value, err := provider.ListAssetWorkflows(req.Request.Context(), actor)
	s.governanceResult(res, value, err)
}

func (s *Server) previewRoleBinding(req *restful.Request, res *restful.Response) {
	s.previewLabelBinding(req, res, false)
}

func (s *Server) previewOwnership(req *restful.Request, res *restful.Response) {
	s.previewLabelBinding(req, res, true)
}

func (s *Server) previewLabelBinding(req *restful.Request, res *restful.Response, ownership bool) {
	svc, actor, ok := s.governance(req, res)
	if !ok {
		return
	}
	var input service.LabelPreviewInput
	if err := req.ReadEntity(&input); err != nil {
		s.writeError(res, service.ErrValidation)
		return
	}
	var result service.LabelPreview
	var err error
	if ownership {
		result, err = svc.PreviewOwnership(req.Request.Context(), actor, input)
	} else {
		result, err = svc.PreviewRoleBinding(req.Request.Context(), actor, input)
	}
	s.governanceResult(res, result, err)
}

func (s *Server) governance(req *restful.Request, res *restful.Response) (GovernanceService, string, bool) {
	actor, ok := s.currentUser(req, res)
	if !ok {
		return nil, "", false
	}
	svc, ok := s.Service.(GovernanceService)
	if !ok {
		s.writeError(res, service.ErrNotConfigured)
	}
	return svc, actor, ok
}

func (s *Server) governanceResult(res *restful.Response, value any, err error) {
	if err != nil {
		s.writeError(res, err)
		return
	}
	_ = res.WriteHeaderAndEntity(http.StatusOK, value)
}

func (s *Server) permissionCatalog(req *restful.Request, res *restful.Response) {
	_ = res.WriteEntity(authz.Catalog())
}

func (s *Server) getManagedUser(req *restful.Request, res *restful.Response) {
	svc, actor, ok := s.governance(req, res)
	if !ok {
		return
	}
	value, err := svc.GetManagedUser(req.Request.Context(), actor, req.PathParameter("user_id"))
	s.governanceResult(res, value, err)
}

func (s *Server) updateManagedUser(req *restful.Request, res *restful.Response) {
	svc, actor, ok := s.governance(req, res)
	if !ok {
		return
	}
	var input service.UpdateUserInput
	if err := decodeJSONBody(req.Request, &input, false); err != nil {
		s.writeError(res, err)
		return
	}
	value, err := svc.UpdateManagedUser(req.Request.Context(), actor, req.PathParameter("user_id"), input)
	s.governanceResult(res, value, err)
}

func (s *Server) getAssetPolicy(req *restful.Request, res *restful.Response) {
	svc, actor, ok := s.governance(req, res)
	if !ok {
		return
	}
	value, err := svc.GetAssetPolicy(req.Request.Context(), actor, req.PathParameter("asset_id"))
	s.governanceResult(res, value, err)
}

func (s *Server) saveAssetPolicy(req *restful.Request, res *restful.Response) {
	svc, actor, ok := s.governance(req, res)
	if !ok {
		return
	}
	var input approvalflow.AssetPolicy
	if err := decodeJSONBody(req.Request, &input, false); err != nil {
		s.writeError(res, err)
		return
	}
	value, err := svc.SaveAssetPolicy(req.Request.Context(), actor, req.PathParameter("asset_id"), input)
	s.governanceResult(res, value, err)
}

func (s *Server) getRequestWorkflow(req *restful.Request, res *restful.Response) {
	svc, actor, ok := s.governance(req, res)
	if !ok {
		return
	}
	value, err := svc.GetRequestWorkflow(req.Request.Context(), actor, req.PathParameter("request_id"))
	s.governanceResult(res, value, err)
}

func (s *Server) previewAssetWorkflow(req *restful.Request, res *restful.Response) {
	svc, actor, ok := s.governance(req, res)
	if !ok {
		return
	}
	value, err := svc.PreviewAssetWorkflow(req.Request.Context(), actor, req.PathParameter("asset_id"))
	s.governanceResult(res, value, err)
}

func (s *Server) listIAMRoles(req *restful.Request, res *restful.Response) {
	svc, actor, ok := s.governance(req, res)
	if !ok {
		return
	}
	value, err := svc.ListIAMRoles(req.Request.Context(), actor)
	s.governanceResult(res, value, err)
}

func (s *Server) saveIAMRole(req *restful.Request, res *restful.Response) {
	svc, actor, ok := s.governance(req, res)
	if !ok {
		return
	}
	var input iam.Role
	if err := decodeJSONBody(req.Request, &input, false); err != nil {
		s.writeError(res, err)
		return
	}
	value, err := svc.SaveIAMRole(req.Request.Context(), actor, input)
	s.governanceResult(res, value, err)
}

func (s *Server) listIAMBindings(req *restful.Request, res *restful.Response) {
	svc, actor, ok := s.governance(req, res)
	if !ok {
		return
	}
	value, err := svc.ListIAMBindings(req.Request.Context(), actor)
	s.governanceResult(res, value, err)
}

func (s *Server) saveIAMBinding(req *restful.Request, res *restful.Response) {
	svc, actor, ok := s.governance(req, res)
	if !ok {
		return
	}
	var input iam.Binding
	if err := decodeJSONBody(req.Request, &input, false); err != nil {
		s.writeError(res, err)
		return
	}
	value, err := svc.SaveIAMBinding(req.Request.Context(), actor, input)
	s.governanceResult(res, value, err)
}

func (s *Server) listWorkflows(req *restful.Request, res *restful.Response) {
	svc, actor, ok := s.governance(req, res)
	if !ok {
		return
	}
	value, err := svc.ListWorkflows(req.Request.Context(), actor)
	s.governanceResult(res, value, err)
}

func (s *Server) saveWorkflow(req *restful.Request, res *restful.Response) {
	svc, actor, ok := s.governance(req, res)
	if !ok {
		return
	}
	var input approvalflow.Definition
	if err := decodeJSONBody(req.Request, &input, false); err != nil {
		s.writeError(res, err)
		return
	}
	value, err := svc.SaveWorkflow(req.Request.Context(), actor, input)
	s.governanceResult(res, value, err)
}

func (s *Server) listOwnerships(req *restful.Request, res *restful.Response) {
	svc, actor, ok := s.governance(req, res)
	if !ok {
		return
	}
	value, err := svc.ListOwnerships(req.Request.Context(), actor)
	s.governanceResult(res, value, err)
}

func (s *Server) saveOwnership(req *restful.Request, res *restful.Response) {
	svc, actor, ok := s.governance(req, res)
	if !ok {
		return
	}
	var input approvalflow.Ownership
	if err := decodeJSONBody(req.Request, &input, false); err != nil {
		s.writeError(res, err)
		return
	}
	value, err := svc.SaveOwnership(req.Request.Context(), actor, input)
	s.governanceResult(res, value, err)
}
