package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"
)

const clientTestSessionID = "11111111-1111-4111-8111-111111111111"

func TestHTTPClientSendsDirectSessionConstraintsAndUsesIdempotency(t *testing.T) {
	baseURL, err := url.Parse("http://gateway.test")
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}
	client := &HTTPClient{baseURL: baseURL, client: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodPost && request.URL.Path == "/internal/gateway/sessions" {
			if request.Header.Get("Idempotency-Key") != clientTestSessionID {
				return nil, fmt.Errorf("missing create idempotency key")
			}
			var body CreateSessionRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				return nil, err
			}
			if body.SourceIP != "127.0.0.1" || body.TargetAccount != "readonly" || body.MaxConnections != MaxSessionConnections {
				return nil, fmt.Errorf("missing direct session constraints")
			}
			response := validClientCreateResponse(body.SessionID)
			encoded, _ := json.Marshal(response)
			return responseWithJSON(encoded), nil
		}
		if request.Method == http.MethodDelete {
			if request.Header.Get("Idempotency-Key") != "revoke-s1" {
				return nil, fmt.Errorf("missing idempotency key")
			}
			encoded, _ := json.Marshal(CloseSessionResponse{SessionID: "s1", Status: "closed", ClosedAt: time.Now()})
			return responseWithJSON(encoded), nil
		}
		return &http.Response{StatusCode: http.StatusNotFound, Status: "404 Not Found", Body: http.NoBody, Header: make(http.Header)}, nil
	})}}
	created, err := client.CreateSession(context.Background(), "http://gateway.test", validClientCreateRequest("s1", "a1", 3306))
	if err != nil || created.ExternalPort != 20000 || created.ExposureMode != "direct" {
		t.Fatalf("CreateSession: %+v, %v", created, err)
	}
	if _, err := client.CloseSession(context.Background(), "http://gateway.test", "s1", "revoke-s1"); err != nil {
		t.Fatalf("CloseSession: %v", err)
	}
}

func TestHTTPClientSendsInternalSecretAndRejectsInvalidInput(t *testing.T) {
	baseURL, err := url.Parse("https://gateway.test")
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}
	client := &HTTPClient{
		baseURL: baseURL, internalSecret: "internal-secret",
		client: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.Header.Get("X-Gateway-Internal-Secret") != "internal-secret" {
				return nil, fmt.Errorf("missing internal gateway secret")
			}
			body, _ := json.Marshal(validClientCreateResponse("s1"))
			return responseWithJSON(body), nil
		})},
	}
	if _, err := client.CreateSession(context.Background(), "https://gateway.test", validClientCreateRequest("s1", "a1", 3306)); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	invalid := validClientCreateRequest("s2", "a1", 70000)
	if _, err := client.CreateSession(context.Background(), "https://gateway.test", invalid); err == nil {
		t.Fatal("invalid target port was accepted")
	}
}

func TestHTTPClientChecksGatewayReadinessStrictly(t *testing.T) {
	for name, testCase := range map[string]struct {
		body    string
		wantErr bool
	}{
		"ready":            {body: `{"status":"ready"}`},
		"ready capacity":   {body: `{"status":"ready","active_sessions":3,"max_sessions":10}`},
		"wrong status":     {body: `{"status":"starting"}`, wantErr: true},
		"partial capacity": {body: `{"status":"ready","max_sessions":10}`, wantErr: true},
		"invalid capacity": {body: `{"status":"ready","active_sessions":11,"max_sessions":10}`, wantErr: true},
		"unknown field":    {body: `{"status":"ready","token":"must-not-be-accepted"}`, wantErr: true},
		"trailing value": {body: `{"status":"ready"}{}`,
			wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			baseURL, err := url.Parse("https://gateway.test/base")
			if err != nil {
				t.Fatalf("parse URL: %v", err)
			}
			client := &HTTPClient{
				baseURL: baseURL, internalSecret: "internal-secret",
				client: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
					if request.Method != http.MethodGet || request.URL.Path != "/base/readyz" {
						return nil, fmt.Errorf("unexpected readiness request %s %s", request.Method, request.URL.Path)
					}
					if request.Header.Get("X-Gateway-Internal-Secret") != "internal-secret" {
						return nil, fmt.Errorf("missing internal gateway secret")
					}
					return responseWithJSON([]byte(testCase.body)), nil
				})},
			}
			err = client.CheckReady(context.Background(), "")
			if (err != nil) != testCase.wantErr {
				t.Fatalf("CheckReady error = %v, wantErr=%v", err, testCase.wantErr)
			}
		})
	}
}

func TestHTTPClientConfigRequiresHTTPSAndCompleteMTLSFiles(t *testing.T) {
	if _, err := NewHTTPClientWithSecret("http://gateway.test", time.Second, "secret"); err == nil {
		t.Fatal("default gateway client accepted an HTTP base URL")
	}
	if _, err := NewHTTPClientWithConfig(HTTPClientConfig{BaseURL: "http://gateway.test", RequireHTTPS: true}); err == nil {
		t.Fatal("required HTTPS accepted an HTTP base URL")
	}
	client, err := NewHTTPClientWithConfig(HTTPClientConfig{RequireHTTPS: true})
	if err != nil {
		t.Fatalf("NewHTTPClientWithConfig: %v", err)
	}
	if _, err := client.resolveEndpoint("http://gateway.test"); err == nil {
		t.Fatal("required HTTPS accepted a dynamic HTTP endpoint")
	}
	if _, err := NewHTTPClientWithConfig(HTTPClientConfig{
		BaseURL: "https://gateway.test", ClientCertFile: "/tmp/client.crt",
	}); err == nil {
		t.Fatal("partial mTLS configuration was accepted")
	}
}

func TestHTTPClientRejectsInvalidEndpointAuthorities(t *testing.T) {
	client, err := NewHTTPClientWithConfig(HTTPClientConfig{RequireHTTPS: true})
	if err != nil {
		t.Fatalf("NewHTTPClientWithConfig: %v", err)
	}
	for _, endpoint := range []string{
		"https://gateway.example:",
		"https://gateway.example:0",
		"https://gateway.example:65536",
		"https://gateway.example/path?secret=1",
		"https://gateway.example?",
		"https://user:pass@gateway.example",
		"https://[fe80::1%25eth0]:443",
	} {
		if _, err := client.resolveEndpoint(endpoint); err == nil {
			t.Errorf("invalid gateway endpoint %q was accepted", endpoint)
		}
	}
	for _, endpoint := range []string{"https://gateway.example", "https://[2001:db8::1]:443"} {
		if _, err := client.resolveEndpoint(endpoint); err != nil {
			t.Errorf("valid gateway endpoint %q rejected: %v", endpoint, err)
		}
	}
}

func TestHTTPClientRejectsTrailingOrUnknownGatewayResponse(t *testing.T) {
	for name, responseBody := range map[string]string{
		"trailing": `{"session_id":"s1","status":"running","process_id":"tcp-20000","listener_port":20000,"external_port":20000,"exposure_mode":"direct","exposure_ref":"direct/20000"}{}`,
		"unknown":  `{"session_id":"s1","status":"running","process_id":"tcp-20000","listener_port":20000,"external_port":20000,"exposure_mode":"direct","exposure_ref":"direct/20000","extra":true}`,
	} {
		t.Run(name, func(t *testing.T) {
			baseURL, err := url.Parse("https://gateway.test")
			if err != nil {
				t.Fatalf("parse URL: %v", err)
			}
			client := &HTTPClient{baseURL: baseURL, client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return responseWithJSON([]byte(responseBody)), nil
			})}}
			_, err = client.CreateSession(context.Background(), "", validClientCreateRequest("s1", "a1", 5432))
			if err == nil {
				t.Fatal("malformed gateway response was accepted")
			}
		})
	}
}

func TestHTTPClientRejectsInvalidDirectExposure(t *testing.T) {
	baseURL, err := url.Parse("https://gateway.test")
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}
	client := &HTTPClient{baseURL: baseURL, client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		response := validClientCreateResponse("s1")
		response.ExposureRef = "direct/20000\nforged"
		body, _ := json.Marshal(response)
		return responseWithJSON(body), nil
	})}}
	if _, err := client.CreateSession(context.Background(), "https://gateway.test", validClientCreateRequest("s1", "a1", 5432)); err == nil {
		t.Fatal("invalid gateway exposure was accepted")
	}
}

func TestHTTPClientRejectsMalformedCloseResponses(t *testing.T) {
	for name, responseBody := range map[string]string{
		"empty":      `{}`,
		"wrong_id":   `{"session_id":"other","status":"closed"}`,
		"failed":     `{"session_id":"s1","status":"failed"}`,
		"processing": `{"session_id":"s1","status":"stopping"}`,
	} {
		t.Run(name, func(t *testing.T) {
			baseURL, err := url.Parse("https://gateway.test")
			if err != nil {
				t.Fatalf("parse URL: %v", err)
			}
			client := &HTTPClient{baseURL: baseURL, client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return responseWithJSON([]byte(responseBody)), nil
			})}}
			if _, err := client.CloseSession(context.Background(), "https://gateway.test", "s1", "revoke-s1"); err == nil {
				t.Fatal("malformed close response was accepted")
			}
		})
	}
}

func TestHTTPClientAcceptsExplicitCloseTerminalStates(t *testing.T) {
	for _, status := range []string{"closed", "expired", "not_found"} {
		t.Run(status, func(t *testing.T) {
			baseURL, err := url.Parse("https://gateway.test")
			if err != nil {
				t.Fatalf("parse URL: %v", err)
			}
			client := &HTTPClient{baseURL: baseURL, client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				encoded, _ := json.Marshal(CloseSessionResponse{SessionID: "s1", Status: status})
				return responseWithJSON(encoded), nil
			})}}
			response, err := client.CloseSession(context.Background(), "https://gateway.test", "s1", "revoke-s1")
			if err != nil || response.Status != status {
				t.Fatalf("CloseSession response=%+v err=%v", response, err)
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func responseWithJSON(body []byte) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(bytes.NewReader(body)), Header: http.Header{"Content-Type": []string{"application/json"}}}
}

func validClientCreateRequest(sessionID, targetID string, targetPort int) CreateSessionRequest {
	if sessionID == "s1" {
		sessionID = clientTestSessionID
	}
	return CreateSessionRequest{
		ConnectionMode: ConnectionModeNative,
		SessionID:      sessionID, TargetID: targetID, TargetPort: targetPort,
		SourceIP: "127.0.0.1", TargetAccount: "readonly", TTLSeconds: 60,
		MaxConnections: MaxSessionConnections,
	}
}

func validClientCreateResponse(sessionID string) CreateSessionResponse {
	if sessionID == "s1" {
		sessionID = clientTestSessionID
	}
	startedAt := time.Now().UTC()
	return CreateSessionResponse{
		ConnectionMode: ConnectionModeNative,
		SessionID:      sessionID, Status: "running", ProcessID: "tcp-20000",
		ListenerPort: 20000, ExternalPort: 20000, ExposureMode: "direct", ExposureRef: "direct/20000",
		StartedAt: startedAt, ExpiresAt: startedAt.Add(time.Minute),
	}
}
