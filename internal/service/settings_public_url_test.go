package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/secretstore"
	"github.com/srex-run/access-gateway/internal/security"
	"github.com/srex-run/access-gateway/internal/settings"
)

func TestSystemSettingsAlwaysUsePublicURL(t *testing.T) {
	ctx := context.Background()
	cipher, err := secretstore.NewAESGCM("test-encryption", security.DeriveKey(strings.Repeat("m", 32), "system-settings"))
	if err != nil {
		t.Fatal(err)
	}
	stored := settings.Defaults()
	stored.BaseURL = "https://obsolete.example.test"
	stored.Auth.GitHub.Enabled, stored.Auth.GitHub.ClientID = true, "github-client"
	stored.Feishu = settings.FeishuConfig{AppID: "app", TenantKey: "tenant", LoginEnabled: true}
	configJSON, err := json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := cipher.Encrypt(ctx, []byte(`{"github":"github-secret","feishu_app":"feishu-secret"}`), []byte(settingsAAD))
	if err != nil {
		t.Fatal(err)
	}
	for _, publicURL := range []string{"http://127.0.0.1:9527", "http://localhost", "https://access.example.test"} {
		t.Run(publicURL, func(t *testing.T) {
			// No database I/O: exercise decoding the bootstrap and an existing encrypted settings row.
			svc, err := NewSystemSettingsService(&sql.DB{}, cipher, publicURL+"/")
			if err != nil {
				t.Fatal(err)
			}
			for _, row := range []repository.SystemSettings{{}, {Revision: 1, ConfigJSON: configJSON, SecretsCiphertext: ciphertext}} {
				config, secrets, err := svc.decode(ctx, row)
				if err != nil || config.BaseURL != publicURL {
					t.Fatalf("PUBLIC_URL not applied to settings: %s, %v", config.BaseURL, err)
				}
				snapshot, err := settings.Build(config, secrets, row.Revision, nil)
				if err != nil || snapshot.BaseURL != publicURL || snapshot.Auth.GitHub.RedirectURL != publicURL+"/api/v1/auth/github/callback" {
					t.Fatalf("PUBLIC_URL not applied to callbacks and invitation links: %v", err)
				}
				if snapshot.Auth.AllowHTTP {
					t.Fatal("HTTP public origin enabled insecure identity-provider endpoints")
				}
				for name, callback := range map[string]string{"oidc": snapshot.Auth.OIDC.RedirectURL, "oauth2": snapshot.Auth.OAuth2.RedirectURL} {
					if callback != publicURL+"/api/v1/auth/"+name+"/callback" {
						t.Fatalf("%s callback ignored PUBLIC_URL", name)
					}
				}
				if snapshot.OAuth != nil {
					authorizationURL, err := snapshot.OAuth.AuthorizationURL("state")
					parsed, parseErr := url.Parse(authorizationURL)
					if err != nil || parseErr != nil || parsed.Query().Get("redirect_uri") != publicURL+"/api/v1/auth/feishu/callback" {
						t.Fatal("Feishu callback ignored PUBLIC_URL")
					}
				}
				result, err := (&AccessService{}).deliverInvitation(ctx, snapshot, repository.Invitation{}, "alice", "alice@example.test", "token")
				if err != nil || result.AcceptURL != publicURL+"/invite#token" {
					t.Fatal("invitation link ignored PUBLIC_URL")
				}
			}
		})
	}
}
