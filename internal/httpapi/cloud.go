package httpapi

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"net/http"

	"github.com/emicklei/go-restful/v3"
	"github.com/srex-run/access-gateway/internal/catalogrelease"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/service"
)

type CloudService interface {
	ListCloudAccounts(context.Context, string) ([]domain.CloudAccount, error)
	SaveCloudAccount(context.Context, string, string, service.CloudAccountInput) (domain.CloudAccount, error)
	QueueCloudSync(context.Context, string, string, domain.CloudSyncInput) (domain.CloudSyncJob, error)
	ListCloudSyncJobs(context.Context, string, string) ([]domain.CloudSyncJob, error)
	ListCloudSyncGateways(context.Context, string, string) ([]domain.Gateway, error)
	ExportGatewayRelease(context.Context, string, string) (catalogrelease.Bundle, error)
}

func (s *Server) cloudService(request *restful.Request, response *restful.Response) (CloudService, string, bool) {
	actor, ok := s.currentUser(request, response)
	if !ok {
		return nil, "", false
	}
	svc, ok := s.Service.(CloudService)
	if !ok {
		s.writeError(response, service.ErrNotConfigured)
		return nil, "", false
	}
	response.Header().Set("Cache-Control", "no-store")
	return svc, actor, true
}

func (s *Server) writeCloudError(response *restful.Response, err error) {
	var validation *service.CloudValidationError
	if errors.As(err, &validation) {
		_ = response.WriteHeaderAndEntity(http.StatusBadRequest, errorResponse{Error: validation.Message})
		return
	}
	s.writeError(response, err)
}

func (s *Server) listCloudAccounts(request *restful.Request, response *restful.Response) {
	svc, actor, ok := s.cloudService(request, response)
	if !ok {
		return
	}
	values, err := svc.ListCloudAccounts(request.Request.Context(), actor)
	if err != nil {
		s.writeCloudError(response, err)
		return
	}
	if values == nil {
		values = []domain.CloudAccount{}
	}
	_ = response.WriteEntity(values)
}

func (s *Server) saveCloudAccount(request *restful.Request, response *restful.Response) {
	svc, actor, ok := s.cloudService(request, response)
	if !ok {
		return
	}
	var input service.CloudAccountInput
	if decodeJSONBody(request.Request, &input, false) != nil {
		s.writeError(response, service.ErrValidation)
		return
	}
	value, err := svc.SaveCloudAccount(request.Request.Context(), actor, request.PathParameter("account_id"), input)
	if err != nil {
		s.writeCloudError(response, err)
		return
	}
	status := http.StatusOK
	if request.Request.Method == http.MethodPost {
		status = http.StatusCreated
	}
	_ = response.WriteHeaderAndEntity(status, value)
}

func (s *Server) queueCloudSync(request *restful.Request, response *restful.Response) {
	svc, actor, ok := s.cloudService(request, response)
	if !ok {
		return
	}
	var input domain.CloudSyncInput
	if decodeJSONBody(request.Request, &input, false) != nil {
		s.writeError(response, service.ErrValidation)
		return
	}
	value, err := svc.QueueCloudSync(request.Request.Context(), actor, request.PathParameter("account_id"), input)
	if err != nil {
		s.writeCloudError(response, err)
		return
	}
	_ = response.WriteHeaderAndEntity(http.StatusAccepted, value)
}

func (s *Server) listCloudSyncJobs(request *restful.Request, response *restful.Response) {
	svc, actor, ok := s.cloudService(request, response)
	if !ok {
		return
	}
	values, err := svc.ListCloudSyncJobs(request.Request.Context(), actor, request.QueryParameter("region_id"))
	if err != nil {
		s.writeCloudError(response, err)
		return
	}
	if values == nil {
		values = []domain.CloudSyncJob{}
	}
	_ = response.WriteEntity(values)
}

func (s *Server) listCloudSyncGateways(request *restful.Request, response *restful.Response) {
	svc, actor, ok := s.cloudService(request, response)
	if !ok {
		return
	}
	values, err := svc.ListCloudSyncGateways(request.Request.Context(), actor, request.QueryParameter("region_id"))
	if err != nil {
		s.writeCloudError(response, err)
		return
	}
	type choice struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		RegionID string `json:"region_id"`
	}
	result := make([]choice, 0, len(values))
	for _, value := range values {
		result = append(result, choice{ID: value.ID, Name: value.Name, RegionID: value.RegionID})
	}
	_ = response.WriteEntity(result)
}

func (s *Server) exportGatewayRelease(request *restful.Request, response *restful.Response) {
	svc, actor, ok := s.cloudService(request, response)
	if !ok {
		return
	}
	bundle, err := svc.ExportGatewayRelease(request.Request.Context(), actor, request.PathParameter("gateway_id"))
	if err != nil {
		s.writeCloudError(response, err)
		return
	}
	var buffer bytes.Buffer
	archive := zip.NewWriter(&buffer)
	for _, file := range []struct {
		name string
		data []byte
	}{{"assets.json", bundle.Assets}, {"targets.json", bundle.Targets}, {"manifest.json", bundle.Manifest}} {
		header := &zip.FileHeader{Name: file.name, Method: zip.Deflate}
		header.SetMode(0600)
		entry, err := archive.CreateHeader(header)
		if err != nil {
			s.writeError(response, err)
			return
		}
		if _, err := entry.Write(file.data); err != nil {
			s.writeError(response, err)
			return
		}
	}
	if err := archive.Close(); err != nil {
		s.writeError(response, err)
		return
	}
	_ = response.WriteEntity(struct {
		Filename string `json:"filename"`
		Data     []byte `json:"data"`
	}{
		Filename: "gateway-" + bundle.Release.GatewayID + ".zip", Data: buffer.Bytes(),
	})
}
