package httpapi

import (
	"context"
	"net/http"

	"github.com/emicklei/go-restful/v3"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/service"
)

type UserDirectoryService interface {
	ListUsers(context.Context, string, string, bool, int, int) ([]repository.UserSummary, error)
	CreateLocalUser(context.Context, string, service.CreateLocalUserInput) (repository.UserSummary, error)
	ListAssetApprovers(context.Context, string, string) ([]repository.AssetApproverSummary, error)
	ListRequestApprovers(context.Context, string, string) ([]repository.AssetApproverSummary, error)
}

func (s *Server) userDirectory(request *restful.Request, response *restful.Response) (UserDirectoryService, string, bool) {
	actor, ok := s.currentUser(request, response)
	if !ok {
		return nil, "", false
	}
	svc, ok := s.Service.(UserDirectoryService)
	if !ok {
		s.writeError(response, service.ErrNotConfigured)
	}
	return svc, actor, ok
}

func (s *Server) listUsers(request *restful.Request, response *restful.Response) {
	svc, actor, ok := s.userDirectory(request, response)
	if !ok {
		return
	}
	limit, offset, err := parsePageQuery(request, 50, 100)
	if err != nil {
		s.writeError(response, err)
		return
	}
	active := request.QueryParameter("active")
	if active != "" && active != "true" && active != "false" {
		s.writeError(response, service.ErrValidation)
		return
	}
	users, err := svc.ListUsers(request.Request.Context(), actor, request.QueryParameter("search"), active == "true", limit, offset)
	if err != nil {
		s.writeError(response, err)
		return
	}
	_ = response.WriteEntity(users)
}

func (s *Server) createLocalUser(request *restful.Request, response *restful.Response) {
	svc, actor, ok := s.userDirectory(request, response)
	if !ok {
		return
	}
	var input service.CreateLocalUserInput
	if err := decodeJSONBody(request.Request, &input, false); err != nil {
		s.writeError(response, &service.RequestValidationError{Message: "账户提交格式无效，请检查用户名、昵称和密码"})
		return
	}
	user, err := svc.CreateLocalUser(request.Request.Context(), actor, input)
	input.Password = ""
	if err != nil {
		s.writeError(response, err)
		return
	}
	_ = response.WriteHeaderAndEntity(http.StatusCreated, user)
}

func (s *Server) listAssetApprovers(request *restful.Request, response *restful.Response) {
	svc, actor, ok := s.userDirectory(request, response)
	if !ok {
		return
	}
	values, err := svc.ListAssetApprovers(request.Request.Context(), actor, request.PathParameter("asset_id"))
	if err != nil {
		s.writeError(response, err)
		return
	}
	_ = response.WriteEntity(values)
}

func (s *Server) listRequestApprovers(request *restful.Request, response *restful.Response) {
	svc, actor, ok := s.userDirectory(request, response)
	if !ok {
		return
	}
	values, err := svc.ListRequestApprovers(request.Request.Context(), actor, request.PathParameter("asset_id"))
	if err != nil {
		s.writeError(response, err)
		return
	}
	_ = response.WriteEntity(values)
}

type TestAccessService interface {
	CreateTestAccessRequest(context.Context, service.CreateRequestInput) (domain.AccessRequest, error)
}

func (s *Server) createTestAccessRequest(request *restful.Request, response *restful.Response) {
	s.createRequestWithMode(request, response, true)
}
