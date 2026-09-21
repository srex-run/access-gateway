package settings

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestDefaultsAndIndependentFeishuChannels(t *testing.T) {
	config := Defaults()
	if !config.Auth.LocalEnabled || config.Feishu.LoginEnabled || config.Auth.OIDC.Enabled {
		t.Fatal("unsafe bootstrap defaults")
	}
	if err := config.Validate(Secrets{}); err != nil {
		t.Fatal(err)
	}
	config.Feishu = FeishuConfig{AppID: "app", TenantKey: "tenant", NotificationsEnabled: true}
	secrets := Secrets{FeishuApp: "app-secret"}
	snapshot, err := Build(config, secrets, 1, func(context.Context, string) (string, error) { return "", nil })
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.OAuth != nil || snapshot.CallbackSecret != "" || snapshot.Feishu.LoginEnabled {
		t.Fatal("notifications enabled an unrelated Feishu channel")
	}
	config.Feishu.CallbacksEnabled = true
	if err := config.Validate(secrets); err == nil {
		t.Fatal("callback enabled without signing secret")
	}
	secrets.FeishuCallback = strings.Repeat("s", 32)
	if err := config.Validate(secrets); err != nil {
		t.Fatal(err)
	}
}

type failingDiscoveryTransport struct{ calls int }

func (t *failingDiscoveryTransport) RoundTrip(*http.Request) (*http.Response, error) {
	t.calls++
	return nil, errors.New("identity service unavailable")
}

func TestOIDCDiscoveryFailureHasBoundedRetries(t *testing.T) {
	original := http.DefaultTransport
	transport := &failingDiscoveryTransport{}
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = original })
	config := Defaults()
	config.BaseURL = "https://console.example.test"
	config.Auth.OIDC.Enabled = true
	config.Auth.OIDC.Issuer, config.Auth.OIDC.ClientID = "https://identity.example.test", "client"
	snapshot, err := Build(config, Secrets{OIDC: "secret"}, 1, nil)
	if err != nil || transport.calls != 0 {
		t.Fatal("OIDC discovery prevented bootstrap")
	}
	provider := snapshot.RedirectProviders["oidc"]
	for range 2 {
		if _, err := provider.AuthorizationURL("state", "nonce", "verifier"); err == nil {
			t.Fatal("unavailable discovery succeeded")
		}
	}
	if transport.calls != 1 {
		t.Fatal("failed discovery requests were not bounded")
	}
	provider.(*lazyOIDC).retryAfter = time.Time{}
	if _, err := provider.AuthorizationURL("state", "nonce", "verifier"); err == nil || transport.calls != 2 {
		t.Fatal("discovery did not retry after backoff")
	}
}

func TestSecretsAreWriteOnlyAndChangesAreExplicit(t *testing.T) {
	secrets := Secrets{OIDC: "sensitive-oidc", LDAP: "sensitive-ldap"}
	clear, replacement := "", "new-secret"
	updated := secrets.Apply(SecretChanges{LDAP: &clear, OAuth2: &replacement})
	if updated.OIDC != secrets.OIDC || updated.LDAP != "" || updated.OAuth2 != replacement {
		t.Fatal("secret update lost tri-state semantics")
	}
	config := Defaults()
	config.Auth = config.Authentication(secrets)
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"sensitive-", "client_secret", "bind_password"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatal("configuration JSON exposed a secret")
		}
	}
}

func TestSettingsValidateProviderAndPlatformURLs(t *testing.T) {
	for _, base := range []string{"https://user:pass@example.test", "https://example.test/path", "https://example.test?redirect=evil", "https://example.test#fragment", "//example.test", "ftp://example.test"} {
		config := Defaults()
		config.BaseURL = base
		if err := config.Validate(Secrets{}); err == nil {
			t.Errorf("accepted platform URL %q", base)
		}
	}
	config := Defaults()
	config.BaseURL = "http://localhost:5173"
	config.Auth.AllowHTTP = true
	config.Auth.OIDC.Enabled = true
	config.Auth.OIDC.ClientID = "client"
	config.Auth.OIDC.Issuer = "http://localhost:5556"
	if err := config.Validate(Secrets{}); err == nil {
		t.Fatal("enabled OIDC without a secret")
	}
	snapshot, err := Build(config, Secrets{OIDC: "secret"}, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Auth.OIDC.RedirectURL != "http://localhost:5173/api/v1/auth/oidc/callback" {
		t.Fatal("callback did not use configured platform origin")
	}
	config.Auth.OIDC.Enabled, config.Auth.LocalEnabled = false, false
	config.Normalize()
	if err := config.Validate(Secrets{}); err != nil || !config.Auth.LocalEnabled {
		t.Fatal("local login was not retained")
	}
}
