package httpapi

import (
	"context"
	"fmt"
	"net/http"

	"github.com/emicklei/go-restful/v3"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/service"
)

type sessionRecordProvider interface {
	ListSessionRecords(context.Context, string, domain.SessionRecordFilter) ([]domain.SessionRecord, error)
	GetSessionRecord(context.Context, string, string, bool) (service.SessionRecordView, error)
	ListSessionTrace(context.Context, string, string, string, int, int) ([]domain.SessionTraceEvent, error)
	ListTerminalRecording(context.Context, string, string, string, int, int) ([]domain.TerminalRecordingFrame, error)
}

type sessionRecordResponse struct {
	domain.SessionRecord
	Session  sessionResponse               `json:"session"`
	Request  accessRequestResponse         `json:"request"`
	Workflow service.WorkflowView          `json:"workflow"`
	Evidence domain.SessionEvidenceSummary `json:"evidence"`
	CanClose bool                          `json:"can_close"`
}

func toSessionRecordResponse(value service.SessionRecordView) sessionRecordResponse {
	view := value.View
	session := toSessionResponse(view.Session)
	session.CanConnect = view.CanConnect
	session.AuditTrust = view.AuditTrust
	session.CanWebConnect = view.CanWebConnect
	session.GatewayEndpoint, session.GatewayHost, session.GatewayPort = view.GatewayEndpoint, view.GatewayHost, view.GatewayPort
	session.TargetPort, session.SourceIP, session.TargetAccount = view.Request.TargetPort, view.Request.SourceIP, view.Request.TargetAccount
	return sessionRecordResponse{SessionRecord: value.Record, Session: session, Request: toAccessRequestResponse(view.Request), Workflow: value.Workflow, Evidence: value.Evidence, CanClose: value.CanClose}
}

func isSessionRecordRoute(method, path string) bool {
	if method != http.MethodGet {
		return false
	}
	switch path {
	case "/api/v1/session-records", "/api/v1/session-records/{session_id}", "/api/v1/session-records/{session_id}/trace", "/api/v1/session-records/{session_id}/terminal-recordings/{channel_id}", "/api/v1/access-requests/{request_id}/record":
		return true
	}
	return false
}

func (s *Server) sessionRecordsBackend(request *restful.Request, response *restful.Response) (string, sessionRecordProvider, bool) {
	actor, ok := s.currentUser(request, response)
	if !ok {
		return "", nil, false
	}
	provider, ok := s.Service.(sessionRecordProvider)
	if !ok {
		s.writeError(response, fmt.Errorf("session records are unavailable: %w", service.ErrNotConfigured))
		return "", nil, false
	}
	return actor, provider, true
}

func (s *Server) listSessionRecords(request *restful.Request, response *restful.Response) {
	actor, provider, ok := s.sessionRecordsBackend(request, response)
	if !ok {
		return
	}
	limit, offset, err := parsePageQuery(request, 21, 200)
	if err != nil {
		s.writeError(response, &service.RequestValidationError{Message: "会话列表分页参数无效，请刷新页面后重试"})
		return
	}
	values, err := provider.ListSessionRecords(request.Request.Context(), actor, domain.SessionRecordFilter{
		Search: request.QueryParameter("search"), Status: request.QueryParameter("status"), Limit: limit, Offset: offset,
	})
	if err != nil {
		s.writeError(response, err)
		return
	}
	if values == nil {
		values = []domain.SessionRecord{}
	}
	_ = response.WriteEntity(values)
}

func (s *Server) getSessionRecord(request *restful.Request, response *restful.Response) {
	actor, provider, ok := s.sessionRecordsBackend(request, response)
	if !ok {
		return
	}
	recordID := request.PathParameter("session_id")
	byRequest := recordID == ""
	if byRequest {
		recordID = request.PathParameter("request_id")
	}
	value, err := provider.GetSessionRecord(request.Request.Context(), actor, recordID, byRequest)
	if err != nil {
		s.writeError(response, err)
		return
	}
	_ = response.WriteEntity(toSessionRecordResponse(value))
}

func (s *Server) listSessionTrace(request *restful.Request, response *restful.Response) {
	actor, provider, ok := s.sessionRecordsBackend(request, response)
	if !ok {
		return
	}
	limit, offset, err := parsePageQuery(request, 21, 200)
	if err != nil {
		s.writeError(response, err)
		return
	}
	values, err := provider.ListSessionTrace(request.Request.Context(), actor, request.PathParameter("session_id"), request.QueryParameter("stage"), limit, offset)
	if err != nil {
		s.writeError(response, err)
		return
	}
	if values == nil {
		values = []domain.SessionTraceEvent{}
	}
	_ = response.WriteEntity(values)
}

func (s *Server) listTerminalRecording(request *restful.Request, response *restful.Response) {
	actor, provider, ok := s.sessionRecordsBackend(request, response)
	if !ok {
		return
	}
	limit, offset, err := parsePageQuery(request, 101, 200)
	if err != nil {
		s.writeError(response, err)
		return
	}
	values, err := provider.ListTerminalRecording(request.Request.Context(), actor, request.PathParameter("session_id"), request.PathParameter("channel_id"), limit, offset)
	if err != nil {
		s.writeError(response, err)
		return
	}
	if values == nil {
		values = []domain.TerminalRecordingFrame{}
	}
	_ = response.WriteEntity(values)
}
