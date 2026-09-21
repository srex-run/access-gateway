package httpapi

import (
	"context"
	"fmt"

	"github.com/emicklei/go-restful/v3"
	"github.com/srex-run/access-gateway/internal/service"
)

type gatewayRuntimeProvider interface {
	GetGatewayRuntime(context.Context, string) (service.GatewayRuntimeView, error)
}

func (s *Server) gatewayRuntime(request *restful.Request, response *restful.Response) {
	actor, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	provider, ok := s.Service.(gatewayRuntimeProvider)
	if !ok {
		s.writeError(response, fmt.Errorf("gateway runtime is unavailable: %w", service.ErrNotConfigured))
		return
	}
	view, err := provider.GetGatewayRuntime(request.Request.Context(), actor)
	if err != nil {
		s.writeError(response, err)
		return
	}
	_ = response.WriteEntity(view)
}
