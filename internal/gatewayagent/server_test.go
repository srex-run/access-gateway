package gatewayagent

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/srex-run/access-gateway/internal/gateway"
)

const testGatewaySecret = "0123456789abcdef0123456789abcdef"

func TestServerAuthenticatesAndRunsSessionLifecycle(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	controller := &controllerStub{startResponse: gateway.CreateSessionResponse{
		ProcessID: "tcp-20000", StartedAt: now, ExpiresAt: now.Add(time.Minute),
	}}
	manager := newTestManager(t, controller, &memoryStateStore{}, []AssetCatalogEntry{{TargetID: testGatewayTargetID, Ports: []int{5432}}}, &now)
	server, err := NewServer(manager, testGatewaySecret, zerolog.Nop())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	healthResponse := httptest.NewRecorder()
	server.Container().ServeHTTP(healthResponse, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if healthResponse.Code != http.StatusOK {
		t.Fatalf("health status = %d", healthResponse.Code)
	}
	readyResponse := httptest.NewRecorder()
	server.Container().ServeHTTP(readyResponse, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	var readiness gateway.ReadinessReport
	if err := json.Unmarshal(readyResponse.Body.Bytes(), &readiness); err != nil || readiness.Status != "ready" || readiness.ActiveSessions == nil || *readiness.ActiveSessions != 0 || readiness.MaxSessions == nil || *readiness.MaxSessions != 100 {
		t.Fatalf("readiness response = %d %s err=%v", readyResponse.Code, readyResponse.Body.String(), err)
	}

	body, err := json.Marshal(validGatewayRequest())
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	unauthorizedResponse := httptest.NewRecorder()
	unauthorizedRequest := httptest.NewRequest(http.MethodPost, "/internal/gateway/sessions", bytes.NewReader(body))
	unauthorizedRequest.Header.Set("Content-Type", "application/json")
	server.Container().ServeHTTP(unauthorizedResponse, unauthorizedRequest)
	if unauthorizedResponse.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized response = %d %s", unauthorizedResponse.Code, unauthorizedResponse.Body.String())
	}

	createRequest := httptest.NewRequest(http.MethodPost, "/internal/gateway/sessions", bytes.NewReader(body))
	createRequest.Header.Set("Content-Type", "application/json")
	createRequest.Header.Set("X-Gateway-Internal-Secret", testGatewaySecret)
	createRequest.Header.Set("Idempotency-Key", testGatewaySessionID)
	createResponse := httptest.NewRecorder()
	server.Container().ServeHTTP(createResponse, createRequest)
	if createResponse.Code != http.StatusCreated || !strings.Contains(createResponse.Body.String(), `"external_port"`) {
		t.Fatalf("create response = %d %s", createResponse.Code, createResponse.Body.String())
	}
	if createResponse.Header().Get("Cache-Control") != "no-store" || createResponse.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("create cache headers = %v", createResponse.Header())
	}

	getRequest := httptest.NewRequest(http.MethodGet, "/internal/gateway/sessions/"+testGatewaySessionID, nil)
	getRequest.Header.Set("X-Gateway-Internal-Secret", testGatewaySecret)
	getResponse := httptest.NewRecorder()
	server.Container().ServeHTTP(getResponse, getRequest)
	if getResponse.Code != http.StatusOK || !strings.Contains(getResponse.Body.String(), sessionRunning) {
		t.Fatalf("get response = %d %s", getResponse.Code, getResponse.Body.String())
	}

	for attempt := 0; attempt < 2; attempt++ {
		closeRequest := httptest.NewRequest(http.MethodDelete, "/internal/gateway/sessions/"+testGatewaySessionID, nil)
		closeRequest.Header.Set("X-Gateway-Internal-Secret", testGatewaySecret)
		closeRequest.Header.Set("Idempotency-Key", "revoke-"+testGatewaySessionID)
		closeResponse := httptest.NewRecorder()
		server.Container().ServeHTTP(closeResponse, closeRequest)
		if closeResponse.Code != http.StatusOK || !strings.Contains(closeResponse.Body.String(), sessionClosed) {
			t.Fatalf("close attempt %d response = %d %s", attempt+1, closeResponse.Code, closeResponse.Body.String())
		}
	}
	if controller.stopCalls != 1 {
		t.Fatalf("idempotent close controller calls = %d", controller.stopCalls)
	}
}

func TestServerRejectsMismatchedIdempotencyKeyAndUnlistedTarget(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	controller := &controllerStub{}
	manager := newTestManager(t, controller, &memoryStateStore{}, []AssetCatalogEntry{{TargetID: testGatewayTargetID, Ports: []int{5432}}}, &now)
	server, err := NewServer(manager, testGatewaySecret, zerolog.Nop())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	requestBody := validGatewayRequest()
	requestBody.TargetPort = 22
	body, err := json.Marshal(requestBody)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	for name, testCase := range map[string]struct {
		key      string
		expected int
	}{
		"mismatched idempotency key": {key: "different", expected: http.StatusBadRequest},
		"unlisted target port":       {key: testGatewaySessionID, expected: http.StatusForbidden},
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/internal/gateway/sessions", bytes.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("X-Gateway-Internal-Secret", testGatewaySecret)
			request.Header.Set("Idempotency-Key", testCase.key)
			response := httptest.NewRecorder()
			server.Container().ServeHTTP(response, request)
			if response.Code != testCase.expected || strings.Contains(response.Body.String(), testGatewayTargetID) {
				t.Fatalf("response = %d %s", response.Code, response.Body.String())
			}
		})
	}
	if controller.startCalls != 0 {
		t.Fatalf("controller start calls = %d", controller.startCalls)
	}
}
