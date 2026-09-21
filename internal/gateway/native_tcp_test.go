package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
)

func TestNativeTCPClientRequiresExplicitModeAgreement(t *testing.T) {
	for _, mode := range []string{ConnectionModeNative, ConnectionModeDirect, ConnectionModeTunnel, "", "unknown"} {
		t.Run("response_"+mode, func(t *testing.T) {
			baseURL, _ := url.Parse("https://gateway.test")
			client := &HTTPClient{baseURL: baseURL, client: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				var body CreateSessionRequest
				if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				if body.ConnectionMode != ConnectionModeNative || body.ClientPublicKey != "" {
					t.Fatalf("native request did not explicitly disable tunnel identity: %+v", body)
				}
				response := validClientCreateResponse(body.SessionID)
				response.ConnectionMode = mode
				response.ServerCertificate = ""
				encoded, _ := json.Marshal(response)
				return responseWithJSON(encoded), nil
			})}}
			request := validClientCreateRequest("s1", "a1", 3306)
			request.ConnectionMode, request.ClientPublicKey = ConnectionModeNative, ""
			_, err := client.CreateSession(context.Background(), "", request)
			if (err != nil) != (mode != ConnectionModeNative) {
				t.Fatalf("response mode %q: %v", mode, err)
			}
		})
	}
}

func TestNativeTCPRejectsImplicitDowngradeAndMixedIdentity(t *testing.T) {
	for _, scenario := range []string{"missing mode", "unknown mode", "native with key", "legacy with no key", "legacy with key", "plaintext direct"} {
		t.Run(scenario, func(t *testing.T) {
			request := validClientCreateRequest("s1", "a1", 3306)
			switch scenario {
			case "missing mode":
				request.ConnectionMode = ""
			case "unknown mode":
				request.ConnectionMode = "unknown"
			case "native with key":
				request.ClientPublicKey = "retired-client-key"
			case "plaintext direct":
				request.ConnectionMode, request.ClientPublicKey = ConnectionModeDirect, ""
			case "legacy with key":
				request.ConnectionMode, request.ClientPublicKey = ConnectionModeTunnel, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
			case "legacy with no key":
				request.ConnectionMode, request.ClientPublicKey = ConnectionModeTunnel, ""
			}
			if err := ValidateCreateRequest(request); err == nil {
				t.Fatal("invalid connection authority accepted")
			}
		})
	}
	response := validClientCreateResponse("s1")
	response.ServerCertificate = "retired-certificate"
	if err := ValidateConnectionResponse(ConnectionModeNative, response); err == nil {
		t.Fatal("native mode accepted tunnel certificate")
	}
	response.ServerCertificate = ""
	if err := ValidateConnectionResponse(ConnectionModeTunnel, response); err == nil {
		t.Fatal("legacy request downgraded to native TCP")
	}
}
