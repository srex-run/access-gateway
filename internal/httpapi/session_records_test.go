package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/service"
)

type sessionRecordsStub struct {
	backendStub
	actor       string
	filter      domain.SessionRecordFilter
	stage       string
	channelID   string
	err         error
	permissions map[authz.Permission]bool
}

func (s *sessionRecordsStub) Authorize(ctx context.Context, actor string, permission authz.Permission) error {
	if s.permissions == nil {
		return s.backendStub.Authorize(ctx, actor, permission)
	}
	if s.permissions[permission] {
		return nil
	}
	return service.ErrForbidden
}

func (s *sessionRecordsStub) ListSessionRecords(_ context.Context, actor string, filter domain.SessionRecordFilter) ([]domain.SessionRecord, error) {
	s.actor, s.filter = actor, filter
	return nil, s.err
}
func (s *sessionRecordsStub) GetSessionRecord(_ context.Context, actor, recordID string, byRequest bool) (service.SessionRecordView, error) {
	s.actor = actor
	return service.SessionRecordView{
		Record: domain.SessionRecord{ID: testSessionID, AssetType: "mysql", TargetPort: 33306},
		View: service.SessionView{Session: domain.Session{ID: testSessionID}, Request: domain.AccessRequest{TargetPort: 33306},
			CanWebConnect: true,
			AuditTrust:    &service.SessionAuditTrust{CACertificate: "public-agent-ca"},
			GatewayHost:   "127.0.0.1", GatewayPort: 20001, GatewayEndpoint: "127.0.0.1:20001"},
	}, s.err
}
func (s *sessionRecordsStub) ListSessionTrace(_ context.Context, actor, sessionID, stage string, limit, offset int) ([]domain.SessionTraceEvent, error) {
	s.actor, s.stage = actor, stage
	s.filter.Limit, s.filter.Offset = limit, offset
	return nil, s.err
}

func (s *sessionRecordsStub) ListTerminalRecording(_ context.Context, actor, sessionID, channelID string, limit, offset int) ([]domain.TerminalRecordingFrame, error) {
	s.actor, s.channelID = actor, channelID
	s.filter.Limit, s.filter.Offset = limit, offset
	return nil, s.err
}

func TestTerminalRecordingRouteKeepsSessionVisibility(t *testing.T) {
	svc := &sessionRecordsStub{}
	server := testServer(t, svc, func(server *Server) { server.AllowDevAuth = true })
	path := "/api/v1/session-records/" + testSessionID + "/terminal-recordings/" + testApprovalID + "?limit=101&offset=100"
	for _, sample := range []struct {
		authenticated bool
		err           error
		status        int
	}{
		{false, nil, http.StatusUnauthorized},
		{true, nil, http.StatusOK},
		{true, service.ErrForbidden, http.StatusForbidden},
	} {
		svc.err = sample.err
		request := httptest.NewRequest(http.MethodGet, path, nil)
		if sample.authenticated {
			request.Header.Set("X-User-ID", testUserID)
		}
		response := httptest.NewRecorder()
		server.Container().ServeHTTP(response, request)
		if response.Code != sample.status {
			t.Fatalf("recording route: %d %s", response.Code, response.Body.String())
		}
		if sample.status == http.StatusOK && (strings.TrimSpace(response.Body.String()) != "[]" || svc.actor != testUserID || svc.channelID != testApprovalID || svc.filter.Limit != 101 || svc.filter.Offset != 100) {
			t.Fatal("recording lost actor, channel or pagination")
		}
	}
}

func TestSessionRecordRoutes(t *testing.T) {
	svc := &sessionRecordsStub{}
	server := testServer(t, svc, func(server *Server) { server.AllowDevAuth = true })
	for _, path := range []string{"/session-records?limit=11&offset=20&search=payments&status=running", "/session-records/" + testSessionID, "/session-records/" + testSessionID + "/trace?stage=connection&limit=11&offset=20", "/access-requests/" + testApprovalID + "/record"} {
		for _, authenticated := range []bool{false, true} {
			request := httptest.NewRequest(http.MethodGet, "/api/v1"+path, nil)
			if authenticated {
				request.Header.Set("X-User-ID", testUserID)
			}
			response := httptest.NewRecorder()
			server.Container().ServeHTTP(response, request)
			want := http.StatusUnauthorized
			if authenticated {
				want = http.StatusOK
			}
			if response.Code != want {
				t.Fatalf("route %s authenticated=%v: %d %s", path, authenticated, response.Code, response.Body.String())
			}
			if authenticated && (path == "/session-records/"+testSessionID || path == "/access-requests/"+testApprovalID+"/record") {
				var detail sessionRecordResponse
				if err := json.Unmarshal(response.Body.Bytes(), &detail); err != nil {
					t.Fatal(err)
				}
				if detail.AssetType != "mysql" || detail.Session.GatewayHost != "127.0.0.1" || detail.Session.GatewayPort != 20001 || detail.Session.TargetPort != 33306 {
					t.Fatal("session details lost the protocol or confused the client and target ports")
				}
				if detail.Session.AuditTrust == nil || detail.Session.AuditTrust.CACertificate != "public-agent-ca" {
					t.Fatal("session client trust material was lost")
				}
			}
		}
	}
	if svc.actor != testUserID || svc.filter.Limit != 11 || svc.filter.Offset != 20 || svc.filter.Search != "payments" || svc.filter.Status != "running" || svc.stage != "connection" {
		t.Fatalf("record query fields: %+v", svc)
	}
	svc.err = service.ErrForbidden
	request := httptest.NewRequest(http.MethodGet, "/api/v1/session-records/"+testSessionID+"/trace", nil)
	request.Header.Set("X-User-ID", testUserID)
	response := httptest.NewRecorder()
	server.Container().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("service visibility rejection was ignored: %d", response.Code)
	}
	if isSessionRecordRoute(http.MethodPost, "/api/v1/sessions/{session_id}/close") || isSessionRecordRoute(http.MethodPost, "/api/v1/sessions/{session_id}/credential") {
		t.Fatal("record routes widened write permissions")
	}
	svc.err = nil
	for _, permission := range []authz.Permission{authz.PermissionAuditRead, authz.PermissionApprovalManage} {
		svc.permissions = map[authz.Permission]bool{permission: true}
		response := httptest.NewRecorder()
		server.Container().ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("record reader %s rejected: %d", permission, response.Code)
		}
		closeRequest := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+testSessionID+"/close", nil)
		closeRequest.Header.Set("X-User-ID", testUserID)
		closeResponse := httptest.NewRecorder()
		server.Container().ServeHTTP(closeResponse, closeRequest)
		if closeResponse.Code != http.StatusForbidden || svc.closeCount != 0 {
			t.Fatalf("record reader %s gained session mutation rights", permission)
		}
	}
	svc.permissions = map[authz.Permission]bool{}
	response = httptest.NewRecorder()
	server.Container().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("unprivileged reader accepted: %d", response.Code)
	}
}

func TestOpenSessionRecordFilter(t *testing.T) {
	svc := &sessionRecordsStub{}
	server := testServer(t, svc, func(server *Server) { server.AllowDevAuth = true })
	request := httptest.NewRequest(http.MethodGet, "/api/v1/session-records?status=open&search=root&limit=51&offset=50", nil)
	request.Header.Set("X-User-ID", testUserID)
	response := httptest.NewRecorder()
	server.Container().ServeHTTP(response, request)
	if response.Code != http.StatusOK || svc.filter.Status != "open" || svc.filter.Search != "root" || svc.filter.Limit != 51 || svc.filter.Offset != 50 {
		t.Fatalf("open session filter: response=%d filter=%+v", response.Code, svc.filter)
	}
}

func TestForceClosePermissionOnlyOpensSessionSelector(t *testing.T) {
	for _, sample := range []struct {
		path    string
		allowed bool
	}{
		{path: "/session-records?status=open&limit=51&search=root", allowed: true},
		{path: "/session-records"},
		{path: "/session-records?status=running"},
		{path: "/session-records?status=closed"},
		{path: "/session-records/" + testSessionID + "?status=open"},
		{path: "/session-records/" + testSessionID + "/trace?status=open"},
		{path: "/access-requests/" + testApprovalID + "/record?status=open"},
	} {
		t.Run(sample.path, func(t *testing.T) {
			svc := &sessionRecordsStub{permissions: map[authz.Permission]bool{authz.PermissionSessionOverride: true}}
			server := testServer(t, svc, func(server *Server) { server.AllowDevAuth = true })
			request := httptest.NewRequest(http.MethodGet, "/api/v1"+sample.path, nil)
			request.Header.Set("X-User-ID", testUserID)
			response := httptest.NewRecorder()
			server.Container().ServeHTTP(response, request)
			want := http.StatusForbidden
			if sample.allowed {
				want = http.StatusOK
			}
			if response.Code != want {
				t.Fatalf("force-close selector access: %d %s", response.Code, response.Body.String())
			}
			if !sample.allowed && svc.actor != "" {
				t.Fatal("force-close permission reached a historical record handler")
			}
		})
	}
}

func TestSessionRecordValidationErrorsAreActionable(t *testing.T) {
	for _, sample := range []struct {
		query   string
		err     error
		message string
	}{
		{"?status=open&limit=201", nil, "会话列表分页参数无效，请刷新页面后重试"},
		{"?status=open", &service.RequestValidationError{Message: "搜索内容过长，请缩短后重试"}, "搜索内容过长，请缩短后重试"},
	} {
		svc := &sessionRecordsStub{err: sample.err}
		server := testServer(t, svc, func(server *Server) { server.AllowDevAuth = true })
		request := httptest.NewRequest(http.MethodGet, "/api/v1/session-records"+sample.query, nil)
		request.Header.Set("X-User-ID", testUserID)
		response := httptest.NewRecorder()
		server.Container().ServeHTTP(response, request)
		var body errorResponse
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if response.Code != http.StatusBadRequest || body.Error != sample.message {
			t.Fatalf("session query validation: status=%d body=%s", response.Code, response.Body.String())
		}
	}
}

func TestSessionRecordResponseDoesNotExposeCredentials(t *testing.T) {
	secret := "never-expose-credential"
	value := service.SessionRecordView{View: service.SessionView{Session: domain.Session{TokenHash: &secret, TunnelClientPublicKey: secret, TunnelServerCertificate: secret}}}
	encoded, err := json.Marshal(toSessionRecordResponse(value))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{secret, "token_hash", "target_ciphertext", "tunnel_client", "tunnel_server"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("record response exposed %s", forbidden)
		}
	}
}
