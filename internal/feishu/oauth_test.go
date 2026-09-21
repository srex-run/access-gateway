package feishu

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestOAuthClientExchangeSendsCredentialsAndPreservesInactive(t *testing.T) {
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/app-token":
			var body map[string]string
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatalf("decode app token request: %v", err)
			}
			if body["app_id"] != "app-id" || body["app_secret"] != "app-secret" {
				t.Fatalf("unexpected app token request: %#v", body)
			}
			return jsonHTTPResponse(map[string]any{"code": 0, "app_access_token": "app-token"}), nil
		case "/token":
			if request.Header.Get("Content-Type") != "application/json" {
				t.Fatalf("token content type = %q", request.Header.Get("Content-Type"))
			}
			var body map[string]string
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatalf("decode token request: %v", err)
			}
			if body["app_id"] != "" || body["app_secret"] != "" || body["code"] != "oauth-code" || body["grant_type"] != "authorization_code" {
				t.Fatalf("unexpected token request: %#v", body)
			}
			if request.Header.Get("Authorization") != "Bearer app-token" {
				t.Fatalf("token authorization = %q", request.Header.Get("Authorization"))
			}
			return jsonHTTPResponse(map[string]any{"code": 0, "data": map[string]string{"access_token": "user-token"}}), nil
		case "/profile":
			if request.Header.Get("Authorization") != "Bearer user-token" {
				t.Fatalf("profile authorization = %q", request.Header.Get("Authorization"))
			}
			return jsonHTTPResponse(map[string]any{"code": 0, "data": map[string]any{
				"open_id": "ou-user", "union_id": "on-user", "tenant_key": "tenant-1", "name": "User", "en_name": "user", "active": false,
			}}), nil
		default:
			return &http.Response{StatusCode: http.StatusNotFound, Status: "404 Not Found", Body: http.NoBody}, nil
		}
	})

	client, err := NewOAuthClient(OAuthConfig{
		AppID: "app-id", AppSecret: "app-secret", RedirectURL: "https://console.example/callback",
		AuthorizeURL: "https://feishu.test/authorize", AppAccessTokenURL: "https://feishu.test/app-token",
		TokenURL: "https://feishu.test/token", UserInfoURL: "https://feishu.test/profile", TenantKey: "tenant-1",
	}, time.Second)
	if err != nil {
		t.Fatalf("NewOAuthClient: %v", err)
	}
	client.client = &http.Client{Transport: transport}
	profile, err := client.Exchange(context.Background(), "oauth-code")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if profile.OpenID != "ou-user" || profile.Nickname != "User" || profile.Username != "user" || profile.TenantKey != "tenant-1" || profile.Active {
		t.Fatalf("profile = %+v", profile)
	}

	authorizationURL, err := client.AuthorizationURL("state-value")
	if err != nil {
		t.Fatalf("AuthorizationURL: %v", err)
	}
	parsed, err := url.Parse(authorizationURL)
	if err != nil {
		t.Fatalf("parse authorization URL: %v", err)
	}
	if parsed.Query().Get("app_id") != "app-id" || parsed.Query().Get("response_type") != "code" || parsed.Query().Get("state") != "state-value" {
		t.Fatalf("authorization query = %v", parsed.Query())
	}
	if parsed.Query().Get("app_secret") != "" {
		t.Fatal("application secret leaked into authorization URL")
	}
}

func TestOAuthProfileDefaultsActiveOnlyWhenFieldMissing(t *testing.T) {
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/app-token" {
			return jsonHTTPResponse(map[string]any{"app_access_token": "app-token"}), nil
		}
		if request.URL.Path == "/token" {
			return jsonHTTPResponse(map[string]any{"access_token": "token"}), nil
		}
		return jsonHTTPResponse(map[string]any{"data": map[string]any{"open_id": "ou-user", "tenant_key": "tenant-1", "name": "User"}}), nil
	})
	client, err := NewOAuthClient(OAuthConfig{
		AppID: "app-id", AppSecret: "app-secret", RedirectURL: "https://console.example/callback",
		AuthorizeURL: "https://feishu.test/authorize", AppAccessTokenURL: "https://feishu.test/app-token",
		TokenURL: "https://feishu.test/token", UserInfoURL: "https://feishu.test/profile", TenantKey: "tenant-1",
	}, time.Second)
	if err != nil {
		t.Fatalf("NewOAuthClient: %v", err)
	}
	client.client = &http.Client{Transport: transport}
	profile, err := client.Exchange(context.Background(), "code")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if !profile.Active {
		t.Fatal("missing active field should default to active")
	}
}

func TestOAuthClientRejectsDifferentTenant(t *testing.T) {
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/app-token":
			return jsonHTTPResponse(map[string]any{"app_access_token": "app-token"}), nil
		case "/token":
			return jsonHTTPResponse(map[string]any{"access_token": "user-token"}), nil
		default:
			return jsonHTTPResponse(map[string]any{"data": map[string]any{"open_id": "ou-user", "tenant_key": "other-tenant", "name": "User"}}), nil
		}
	})
	client, err := NewOAuthClient(OAuthConfig{
		AppID: "app-id", AppSecret: "app-secret", RedirectURL: "https://console.example/callback",
		AuthorizeURL: "https://feishu.test/authorize", AppAccessTokenURL: "https://feishu.test/app-token",
		TokenURL: "https://feishu.test/token", UserInfoURL: "https://feishu.test/profile", TenantKey: "tenant-1",
	}, time.Second)
	if err != nil {
		t.Fatalf("NewOAuthClient: %v", err)
	}
	client.client = &http.Client{Transport: transport}
	if _, err := client.Exchange(context.Background(), "code"); err == nil {
		t.Fatal("different tenant was accepted")
	}
}
