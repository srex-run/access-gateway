package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/service"
)

type forceCloseValidationStub struct {
	backendStub
	calls int
}

func (s *forceCloseValidationStub) ForceCloseSession(context.Context, string, string, string) (domain.Session, error) {
	s.calls++
	return domain.Session{}, &service.RequestValidationError{Message: "回收原因不能超过 4000 个字符"}
}

func TestForceCloseValidationErrorsAreActionable(t *testing.T) {
	for _, sample := range []struct {
		body    string
		message string
		calls   int
	}{
		{`{"reason":123}`, "回收请求格式不正确，请刷新页面后重新选择会话", 0},
		{`{"reason":"maintenance","unexpected":"never-expose-this"}`, "回收请求格式不正确，请刷新页面后重新选择会话", 0},
		{`{"reason":"maintenance"}`, "回收原因不能超过 4000 个字符", 1},
	} {
		svc := &forceCloseValidationStub{}
		server := testServer(t, svc, func(server *Server) { server.AllowDevAuth = true })
		request := httptest.NewRequest(http.MethodPost, "/api/v1/admin/sessions/"+testSessionID+"/force-close", strings.NewReader(sample.body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-User-ID", testUserID)
		response := httptest.NewRecorder()
		server.Container().ServeHTTP(response, request)
		var body errorResponse
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if response.Code != http.StatusBadRequest || body.Error != sample.message || svc.calls != sample.calls {
			t.Fatalf("force-close validation: status=%d calls=%d body=%s", response.Code, svc.calls, response.Body.String())
		}
	}
}
