package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/emicklei/go-restful/v3"
	"github.com/srex-run/access-gateway/internal/service"
	"github.com/srex-run/access-gateway/internal/settings"
)

type SystemSettingsService interface {
	Get(context.Context) (service.SettingsView, error)
	Save(context.Context, string, service.SettingsUpdate) (service.SettingsView, error)
	Current(context.Context) (*settings.Snapshot, error)
}

type mysqlCertificateProvider interface {
	GenerateMySQLAuditCertificate(context.Context, string, settings.CertificateRequest) (settings.CertificateBundle, error)
}

func (s *Server) getSettings(request *restful.Request, response *restful.Response) {
	if s.Settings == nil {
		s.writeError(response, service.ErrNotConfigured)
		return
	}
	view, err := s.Settings.Get(request.Request.Context())
	if err != nil {
		s.writeError(response, err)
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	_ = response.WriteEntity(view)
}

func (s *Server) generateAuditCertificate(request *restful.Request, response *restful.Response) {
	var input settings.CertificateRequest
	if err := decodeJSONBody(request.Request, &input, false); err != nil {
		s.writeError(response, service.ErrValidation)
		return
	}
	if input.Purpose == "mysql" {
		actor, ok := s.currentUser(request, response)
		if !ok {
			return
		}
		provider, ok := s.Service.(mysqlCertificateProvider)
		if !ok {
			s.writeError(response, service.ErrNotConfigured)
			return
		}
		bundle, err := provider.GenerateMySQLAuditCertificate(request.Request.Context(), actor, input)
		if err != nil {
			s.writeError(response, err)
			return
		}
		response.Header().Set("Cache-Control", "no-store")
		_ = response.WriteEntity(bundle)
		return
	}
	bundle, err := settings.GenerateAuditCertificate(input)
	if err != nil {
		_ = response.WriteHeaderAndEntity(http.StatusBadRequest, errorResponse{Error: err.Error()})
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	_ = response.WriteEntity(bundle)
}

func (s *Server) saveSettings(request *restful.Request, response *restful.Response) {
	if s.Settings == nil {
		s.writeError(response, service.ErrNotConfigured)
		return
	}
	actor, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	var update service.SettingsUpdate
	if err := decodeJSONBody(request.Request, &update, false); err != nil {
		s.writeError(response, service.ErrValidation)
		return
	}
	view, err := s.Settings.Save(request.Request.Context(), actor, update)
	if err != nil {
		var validation *service.SettingsValidationError
		if errors.As(err, &validation) {
			_ = response.WriteHeaderAndEntity(http.StatusBadRequest, errorResponse{Error: validation.Message})
		} else {
			s.writeError(response, err)
		}
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	_ = response.WriteEntity(view)
}

func (s *Server) settingsFilter(request *restful.Request, response *restful.Response, chain *restful.FilterChain) {
	path := request.Request.URL.Path
	if s.Settings != nil && (strings.HasPrefix(path, "/api/v1/auth/") || path == "/callbacks/feishu") {
		snapshot, err := s.Settings.Current(request.Request.Context())
		if err != nil {
			s.writeError(response, err)
			return
		}
		request.Request = request.Request.WithContext(settings.WithSnapshot(request.Request.Context(), snapshot))
	}
	chain.ProcessFilter(request, response)
}

func (s *Server) authRuntime(ctx context.Context) *settings.Snapshot {
	if snapshot := settings.FromContext(ctx); snapshot != nil {
		return snapshot
	}
	return &settings.Snapshot{Auth: s.AuthConfig, RedirectProviders: s.RedirectProviders, LDAP: s.LDAP, OAuth: s.OAuth,
		CallbackSecret: s.FeishuCallbackSecret, Feishu: settings.FeishuConfig{TenantKey: s.FeishuTenantKey,
			LoginEnabled: s.FeishuLoginEnabled, BindingEnabled: s.FeishuBindingEnabled}}
}
