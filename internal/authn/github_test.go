package authn

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func TestGitHubAuthorizationAndPrivateEmail(t *testing.T) {
	verifier := oauth2.GenerateVerifier()
	config := GitHubConfig{ClientID: "github-client", ClientSecret: "github-secret", RedirectURL: "https://console.test/api/v1/auth/github/callback"}
	client := NewGitHub(config, time.Second)
	authorizationURL, err := client.AuthorizationURL("state", "nonce", verifier)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(authorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	if parsed.Scheme != "https" || parsed.Host != "github.com" || parsed.Path != "/login/oauth/authorize" ||
		query.Get("client_id") != config.ClientID || query.Get("redirect_uri") != config.RedirectURL || query.Get("state") != "state" ||
		query.Get("code_challenge") != oauth2.S256ChallengeFromVerifier(verifier) || query.Get("code_challenge_method") != "S256" ||
		query.Get("scope") != "read:user user:email" || strings.Contains(authorizationURL, config.ClientSecret) {
		t.Fatalf("unexpected authorization URL: %s", authorizationURL)
	}
	userJSON := `{"id":9007199254740993,"login":"octocat","name":null,"email":null}`
	emailJSON := `[{"email":"unverified@example.test","primary":true,"verified":false},{"email":"secondary@example.test","primary":false,"verified":true},{"email":"private@example.test","primary":true,"verified":true}]`
	useAuthTransport(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Host == "github.com" && r.URL.Path == "/login/oauth/access_token" {
			if r.Method != http.MethodPost || r.FormValue("client_id") != config.ClientID || r.FormValue("client_secret") != config.ClientSecret ||
				r.FormValue("code") != "code" || r.FormValue("code_verifier") != verifier || r.FormValue("redirect_uri") != config.RedirectURL {
				t.Error("GitHub token exchange lost client credentials, code, callback or PKCE")
			}
			// GitHub returns URL-encoded tokens unless JSON is explicitly requested.
			w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
			_, _ = w.Write([]byte("access_token=test-token&token_type=bearer&scope=read%3Auser%2Cuser%3Aemail"))
			return
		}
		if r.URL.Host != "api.github.com" || r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer test-token" ||
			r.Header.Get("Accept") != "application/vnd.github+json" || r.Header.Get("User-Agent") == "" || r.Header.Get("X-GitHub-Api-Version") == "" {
			t.Error("GitHub API request omitted required headers or used an unexpected destination")
		}
		switch r.URL.Path {
		case "/user":
			_, _ = w.Write([]byte(userJSON))
		case "/user/emails":
			_, _ = w.Write([]byte(emailJSON))
		default:
			t.Errorf("unexpected GitHub API path: %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	profile, err := client.Exchange(context.Background(), "code", "nonce", verifier)
	if err != nil || profile != (Profile{Provider: "github", Issuer: GitHubIssuer, Subject: "9007199254740993", Username: "octocat", Email: "private@example.test"}) {
		t.Fatalf("private-email profile = %+v, %v", profile, err)
	}
	userJSON = `{"id":9007199254740993,"login":"renamed","name":"New Name","email":"untrusted@example.test"}`
	emailJSON = `[{"email":"unverified@example.test","primary":true,"verified":false},{"email":"verified@example.test","verified":true}]`
	renamed, err := client.Exchange(context.Background(), "code", "nonce", verifier)
	if err != nil || renamed.Subject != profile.Subject || renamed.Nickname != "New Name" || renamed.Email != "verified@example.test" {
		t.Fatalf("rename changed identity or unverified email was used: %+v, %v", renamed, err)
	}
	emailJSON = `[{"email":"unverified@example.test","primary":true,"verified":false}]`
	withoutEmail, err := client.Exchange(context.Background(), "code", "nonce", verifier)
	if err != nil || withoutEmail.Email != "" {
		t.Fatalf("unverified public email was trusted: %+v, %v", withoutEmail, err)
	}
	for _, invalid := range []string{`{}`, `{"id":0,"login":"octocat"}`, `{"id":-1,"login":"octocat"}`, `{"id":1.5,"login":"octocat"}`, `{"id":1,"login":""}`} {
		userJSON = invalid
		if _, err := client.Exchange(context.Background(), "code", "nonce", verifier); err == nil {
			t.Errorf("invalid GitHub identity accepted: %s", invalid)
		}
	}
}

func TestGitHubRejectsAPIErrorAndDoesNotForwardTokensOnRedirect(t *testing.T) {
	for _, path := range []string{"/login/oauth/access_token", "/user", "/user/emails"} {
		for _, status := range []int{http.StatusUnauthorized, http.StatusTooManyRequests, http.StatusTemporaryRedirect} {
			t.Run(path+"/"+http.StatusText(status), func(t *testing.T) {
				useAuthTransport(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Host != "github.com" && r.URL.Host != "api.github.com" {
						t.Fatal("credentials followed a redirect to another host")
					}
					if r.URL.Path == path {
						w.Header().Set("Location", "https://other.example.test/steal")
						w.WriteHeader(status)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					if r.URL.Path == "/login/oauth/access_token" {
						_, _ = w.Write([]byte(`{"access_token":"test-token","token_type":"Bearer"}`))
					} else {
						_, _ = w.Write([]byte(`{"id":1,"login":"octocat"}`))
					}
				}))
				client := NewGitHub(GitHubConfig{ClientID: "client", ClientSecret: "secret"}, time.Second)
				if _, err := client.Exchange(context.Background(), "code", "nonce", oauth2.GenerateVerifier()); err == nil {
					t.Fatal("GitHub error response accepted as an identity")
				}
			})
		}
	}
}
