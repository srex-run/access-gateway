package httpapi

import (
	"context"

	"github.com/emicklei/go-restful/v3"
	"github.com/srex-run/access-gateway/internal/service"
	"github.com/srex-run/access-gateway/internal/settings"
)

type assetAuditProvider interface {
	GetAssetAudit(context.Context, string, string) (service.AssetAuditView, error)
}

type assetCertificateProvider interface {
	GenerateAssetAuditCertificate(context.Context, string, settings.CertificateRequest) (settings.CertificateBundle, error)
}

func (s *Server) generateAssetAuditCertificate(request *restful.Request, response *restful.Response) {
	actorID, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	var input settings.CertificateRequest
	if err := decodeJSONBody(request.Request, &input, false); err != nil {
		s.writeError(response, service.ErrValidation)
		return
	}
	provider, ok := s.Service.(assetCertificateProvider)
	if !ok {
		s.writeError(response, service.ErrNotConfigured)
		return
	}
	bundle, err := provider.GenerateAssetAuditCertificate(request.Request.Context(), actorID, input)
	if err != nil {
		s.writeError(response, err)
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	_ = response.WriteEntity(bundle)
}

func (s *Server) getAssetAudit(request *restful.Request, response *restful.Response) {
	actorID, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	provider, ok := s.Service.(assetAuditProvider)
	if !ok {
		s.writeError(response, service.ErrNotConfigured)
		return
	}
	view, err := provider.GetAssetAudit(request.Request.Context(), actorID, request.PathParameter("asset_id"))
	if err != nil {
		s.writeError(response, err)
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	_ = response.WriteEntity(view)
}
