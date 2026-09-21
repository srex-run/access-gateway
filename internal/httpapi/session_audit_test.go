package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/srex-run/access-gateway/internal/gateway"
	"github.com/srex-run/access-gateway/internal/gatewayauth"
)

func TestSessionAuditCannotWriteAnotherSessionsEvents(t *testing.T) {
	const gatewayID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	credentials, _ := gatewayauth.NewSessionCredentials(make([]byte, 32))
	svc := &backendStub{}
	server := testServer(t, svc, func(s *Server) { s.SessionAuditCredentials = credentials })
	for _, path := range []string{"/internal/gateway/events", "/internal/gateway/events/batch"} {
		for _, eventSession := range []string{testSessionID, testApprovalID} {
			event := gateway.ConnectionEvent{EventID: testApprovalID, GatewayID: gatewayID, SessionID: eventSession}
			var body any = event
			if path == "/internal/gateway/events/batch" {
				body = gateway.ConnectionEventBatch{Events: []gateway.ConnectionEvent{event}}
			}
			encoded, _ := json.Marshal(body)
			request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(encoded))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set(gatewayauth.SessionIDHeader, testSessionID)
			request.Header.Set(gateway.AuditGatewayIDHeader, gatewayID)
			request.Header.Set(gateway.AuditSecretHeader, credentials.Issue(gatewayID, testSessionID, time.Now().Add(time.Minute)))
			before := len(svc.gatewayEvents)
			response := httptest.NewRecorder()
			server.Container().ServeHTTP(response, request)
			if eventSession == testSessionID {
				if response.Code != http.StatusOK || len(svc.gatewayEvents) != before+1 {
					t.Fatalf("valid scoped event: %d %s", response.Code, response.Body.String())
				}
			} else if response.Code != http.StatusForbidden || len(svc.gatewayEvents) != before {
				t.Fatalf("cross-session event: %d", response.Code)
			}
		}
	}
}
