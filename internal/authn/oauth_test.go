package authn

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"
)

func TestOIDCVerifiesTokensAndPKCE(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var issuer, rawToken string
	verifier := oauth2.GenerateVerifier()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/keys":
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, Algorithm: "RS256", Use: "sig"}}})
		case "/token":
			if r.FormValue("code_verifier") != verifier || r.FormValue("grant_type") != "authorization_code" {
				t.Error("token exchange did not use PKCE authorization code")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access", "token_type": "Bearer", "id_token": rawToken})
		default:
			http.NotFound(w, r)
		}
	})
	issuer = "https://oidc.example.test"
	useAuthTransport(t, handler)
	client, err := NewOIDC(context.Background(), OIDCConfig{Issuer: issuer, ClientID: "client", ClientSecret: "secret", RedirectURL: "https://console.test/callback"}, time.Second, true)
	if err != nil {
		t.Fatal(err)
	}
	begin, _ := client.AuthorizationURL("state", "nonce", verifier)
	parsed, _ := url.Parse(begin)
	if parsed.Query().Get("nonce") != "nonce" || parsed.Query().Get("state") != "state" || parsed.Query().Get("code_challenge") != oauth2.S256ChallengeFromVerifier(verifier) || parsed.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("invalid authorization query: %s", parsed.RawQuery)
	}
	for _, test := range []struct {
		name   string
		mutate func(map[string]any)
		valid  bool
	}{
		{"valid", func(map[string]any) {}, true},
		{"wrong audience", func(c map[string]any) { c["aud"] = "another-client" }, false},
		{"wrong issuer", func(c map[string]any) { c["iss"] = "https://other.test" }, false},
		{"expired", func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() }, false},
		{"wrong nonce", func(c map[string]any) { c["nonce"] = "other-nonce" }, false},
		{"missing subject", func(c map[string]any) { delete(c, "sub") }, false},
		{"wrong access token hash", func(c map[string]any) { c["at_hash"] = "mismatch" }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			claims := map[string]any{"iss": issuer, "sub": "stable-user", "aud": "client", "exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix(), "nonce": "nonce", "name": "Example User", "preferred_username": "example", "email": "example@test.invalid"}
			test.mutate(claims)
			payload, _ := json.Marshal(claims)
			signed, err := signer.Sign(payload)
			if err != nil {
				t.Fatal(err)
			}
			rawToken, _ = signed.CompactSerialize()
			profile, err := client.Exchange(context.Background(), "code", "nonce", verifier)
			if (err == nil) != test.valid {
				t.Fatalf("Exchange error = %v, want valid %v", err, test.valid)
			}
			if test.valid && (profile.Subject != "stable-user" || profile.Provider != "oidc" || profile.Issuer != issuer || profile.Username != "example" || profile.Nickname != "Example User") {
				t.Fatalf("profile = %+v", profile)
			}
		})
	}
	issuer = "http://oidc.example.test"
	if _, err := NewOIDC(context.Background(), OIDCConfig{Issuer: issuer, ClientID: "client"}, time.Second, false); err == nil {
		t.Fatal("accepted insecure discovery endpoints")
	}
}

func TestOAuth2UsesConfiguredClaimsAndPreservesNumericSubjects(t *testing.T) {
	verifier := oauth2.GenerateVerifier()
	profileJSON := `{"data":{"id":9007199254740993,"login":"example","display_name":"Example","email":"same@example.test"}}`
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/token" {
			if r.FormValue("code_verifier") != verifier {
				t.Error("missing OAuth2 PKCE verifier")
			}
			_, _ = w.Write([]byte(`{"access_token":"test-token","token_type":"Bearer"}`))
			return
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Error("userinfo missing bearer token")
		}
		_, _ = w.Write([]byte(profileJSON))
	})
	useAuthTransport(t, handler)
	client := NewOAuth2(OAuth2Config{ClientID: "client", ClientSecret: "secret", AuthorizeURL: "https://oauth.example/authorize", TokenURL: "https://oauth.example/token", UserInfoURL: "https://oauth.example/profile", SubjectClaim: "data.id", UsernameClaim: "data.login", NameClaim: "data.display_name", EmailClaim: "data.email"}, time.Second, false)
	profile, err := client.Exchange(context.Background(), "code", "", verifier)
	if err != nil || profile.Subject != "9007199254740993" || profile.Nickname != "Example" || profile.Username != "example" {
		t.Fatalf("profile = %+v, error = %v", profile, err)
	}
	profileJSON = `{"data":{"id":9007199254740993},"preferred_username":"alice"}`
	client.usernameClaim = ""
	profile, err = client.Exchange(context.Background(), "code", "", verifier)
	if err != nil || profile.Username != "alice" || profile.Nickname != "" {
		t.Fatalf("default username mapping or missing nickname: %+v %v", profile, err)
	}
	profileJSON = `{"data":{"email":"same@example.test"}}`
	if _, err := client.Exchange(context.Background(), "code", "", verifier); err == nil {
		t.Fatal("missing immutable subject accepted")
	}
}

type authTransport struct{ handler http.Handler }

func (transport authTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response := httptest.NewRecorder()
	transport.handler.ServeHTTP(response, request)
	return response.Result(), nil
}

func useAuthTransport(t *testing.T, handler http.Handler) {
	t.Helper()
	previous := http.DefaultTransport
	http.DefaultTransport = authTransport{handler}
	t.Cleanup(func() { http.DefaultTransport = previous })
}
