package httpapi

import (
	"context"
	"fmt"
	"time"

	"github.com/emicklei/go-restful/v3"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/service"
)

type operationAuditSessionProvider interface {
	ListOperationAuditSessions(context.Context, string, domain.OperationAuditFilter) ([]domain.OperationAuditSession, error)
}

func (s *Server) listOperationAuditSessions(request *restful.Request, response *restful.Response) {
	actor, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	filter, err := parseOperationAuditFilter(request, 10)
	if err != nil {
		s.writeError(response, err)
		return
	}
	provider, ok := s.Service.(operationAuditSessionProvider)
	if !ok {
		s.writeError(response, fmt.Errorf("session operation audit is unavailable: %w", service.ErrNotConfigured))
		return
	}
	values, err := provider.ListOperationAuditSessions(request.Request.Context(), actor, filter)
	if err != nil {
		s.writeError(response, err)
		return
	}
	if values == nil {
		values = []domain.OperationAuditSession{}
	}
	_ = response.WriteEntity(values)
}

func parseOperationAuditFilter(request *restful.Request, defaultLimit int) (domain.OperationAuditFilter, error) {
	query := request.Request.URL.Query()
	limit, offset, err := parsePageQuery(request, defaultLimit, 200)
	if err != nil {
		return domain.OperationAuditFilter{}, err
	}
	filter := domain.OperationAuditFilter{
		SubjectUserID: query.Get("subject_user_id"), ActualAccount: query.Get("actual_account"),
		AssetID: query.Get("asset_id"), SessionID: query.Get("session_id"), Protocol: query.Get("protocol"),
		Result: query.Get("result"), CorrelationStatus: query.Get("correlation_status"), Limit: limit, Offset: offset,
	}
	for _, field := range []struct {
		name   string
		target **time.Time
	}{{"from", &filter.From}, {"to", &filter.To}} {
		if raw := query.Get(field.name); raw != "" {
			parsed, err := time.Parse(time.RFC3339, raw)
			if err != nil {
				return filter, fmt.Errorf("invalid %s time: %w", field.name, service.ErrValidation)
			}
			*field.target = &parsed
		}
	}
	return filter, nil
}
