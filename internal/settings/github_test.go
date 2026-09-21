package settings

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

func TestGitHubSettingsAndSecretLifecycle(t *testing.T) {
	config := Defaults()
	if config.Auth.GitHub.Enabled {
		t.Fatal("GitHub login enabled without configuration")
	}
	config.BaseURL = " https://console.example.test/ "
	config.Auth.LocalEnabled = false
	config.Auth.GitHub.Enabled, config.Auth.GitHub.Name, config.Auth.GitHub.ClientID = true, " GitHub ", " client "
	config.Normalize()
	if config.Auth.GitHub.ClientID != "client" || config.Auth.GitHub.Name != "GitHub" {
		t.Fatal("GitHub settings not normalized")
	}
	if err := config.Validate(Secrets{}); err == nil {
		t.Fatal("GitHub enabled without client secret")
	}
	secrets := Secrets{GitHub: "github-secret", OAuth2: "unrelated-secret"}
	snapshot, err := Build(config, secrets, 7, nil)
	if err != nil {
		t.Fatal(err)
	}
	provider := snapshot.RedirectProviders["github"]
	if provider == nil || !snapshot.Auth.Enabled() || snapshot.Auth.GitHub.ClientSecret != secrets.GitHub {
		t.Fatal("GitHub provider missing from runtime")
	}
	begin, err := provider.AuthorizationURL("state", "nonce", "verifier")
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(begin)
	if parsed.Query().Get("redirect_uri") != "https://console.example.test/api/v1/auth/github/callback" {
		t.Fatal("GitHub callback not derived from platform URL")
	}
	config.Auth = snapshot.Auth
	encoded, err := json.Marshal(config)
	if err != nil || strings.Contains(string(encoded), secrets.GitHub) || strings.Contains(string(encoded), "client_secret") {
		t.Fatal("GitHub secret exposed in configuration JSON")
	}
	if !secrets.Status().GitHub || secrets.Apply(SecretChanges{}).GitHub != secrets.GitHub {
		t.Fatal("GitHub secret status or preservation failed")
	}
	replacement, clear := "replacement", ""
	changed := secrets.Apply(SecretChanges{GitHub: &replacement})
	if changed.GitHub != replacement || changed.OAuth2 != secrets.OAuth2 {
		t.Fatal("GitHub secret replacement changed unrelated credentials")
	}
	changed = changed.Apply(SecretChanges{GitHub: &clear})
	if changed.Status().GitHub || changed.GitHub != "" || config.Validate(changed) == nil {
		t.Fatal("enabled GitHub allowed its only secret to be cleared")
	}
	config.BaseURL = ""
	if err := config.Validate(secrets); err == nil {
		t.Fatal("GitHub allowed an empty callback URL")
	}
}

func TestHTTPPublicURLDoesNotEnableHTTPIdentityProviders(t *testing.T) {
	config := Defaults()
	config.BaseURL = "http://localhost:9527"
	config.Auth.GitHub.Enabled, config.Auth.GitHub.ClientID = true, "github-client"
	secrets := Secrets{GitHub: "github-secret", OIDC: "oidc-secret"}
	snapshot, err := Build(config, secrets, 1, nil)
	if err != nil || snapshot.Auth.AllowHTTP || snapshot.Auth.GitHub.RedirectURL != "http://localhost:9527/api/v1/auth/github/callback" {
		t.Fatalf("HTTP callback requires an unrelated HTTP provider setting: %v", err)
	}
	config.Auth.OIDC.Enabled, config.Auth.OIDC.ClientID = true, "oidc-client"
	config.Auth.OIDC.Issuer = "http://identity.example.test"
	if err := config.Validate(secrets); err == nil {
		t.Fatal("HTTP public origin allowed an insecure identity provider")
	}
	config.Auth.AllowHTTP = true
	if err := config.Validate(secrets); err != nil {
		t.Fatal("explicit development provider HTTP setting was ignored", err)
	}
}
