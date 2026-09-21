package authn

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type Profile struct {
	Provider string
	Issuer   string
	Subject  string
	Nickname string
	Username string
	Email    string
}

type RedirectProvider interface {
	AuthorizationURL(state, nonce, verifier string) (string, error)
	Exchange(context.Context, string, string, string) (Profile, error)
}

type OAuthClient struct {
	config        oauth2.Config
	client        *http.Client
	provider      string
	issuer        string
	userInfoURL   string
	subjectClaim  string
	usernameClaim string
	nameClaim     string
	emailClaim    string
	verifier      *oidc.IDTokenVerifier
}

func authHTTPClient(timeout time.Duration, allowHTTP bool) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many authentication redirects")
			}
			return ValidateURL(request.URL.String(), allowHTTP)
		},
	}
}

func NewOIDC(ctx context.Context, config OIDCConfig, timeout time.Duration, allowHTTP bool) (*OAuthClient, error) {
	client := authHTTPClient(timeout, allowHTTP)
	ctx = oidc.ClientContext(ctx, client)
	provider, err := oidc.NewProvider(ctx, config.Issuer)
	if err != nil {
		return nil, fmt.Errorf("discover OIDC provider: %w", err)
	}
	endpoint := provider.Endpoint()
	var metadata struct {
		JWKSURL string `json:"jwks_uri"`
	}
	if err := provider.Claims(&metadata); err != nil {
		return nil, err
	}
	for _, raw := range []string{endpoint.AuthURL, endpoint.TokenURL, metadata.JWKSURL} {
		if err := ValidateURL(raw, allowHTTP); err != nil {
			return nil, fmt.Errorf("OIDC discovery endpoint: %w", err)
		}
	}
	scopes := []string{oidc.ScopeOpenID}
	for _, scope := range config.Scopes {
		if scope != oidc.ScopeOpenID {
			scopes = append(scopes, scope)
		}
	}
	return &OAuthClient{
		config: oauth2.Config{ClientID: config.ClientID, ClientSecret: config.ClientSecret, Endpoint: endpoint, RedirectURL: config.RedirectURL, Scopes: scopes},
		client: client, provider: "oidc", issuer: config.Issuer,
		verifier: provider.Verifier(&oidc.Config{ClientID: config.ClientID}),
	}, nil
}

func NewOAuth2(config OAuth2Config, timeout time.Duration, allowHTTP bool) *OAuthClient {
	return &OAuthClient{
		config: oauth2.Config{ClientID: config.ClientID, ClientSecret: config.ClientSecret,
			Endpoint: oauth2.Endpoint{AuthURL: config.AuthorizeURL, TokenURL: config.TokenURL}, RedirectURL: config.RedirectURL, Scopes: config.Scopes},
		client: authHTTPClient(timeout, allowHTTP), provider: "oauth2", issuer: config.UserInfoURL,
		userInfoURL: config.UserInfoURL, subjectClaim: config.SubjectClaim, usernameClaim: config.UsernameClaim, nameClaim: config.NameClaim, emailClaim: config.EmailClaim,
	}
}

func (c *OAuthClient) AuthorizationURL(state, nonce, verifier string) (string, error) {
	options := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(verifier)}
	if c.verifier != nil {
		options = append(options, oidc.Nonce(nonce))
	}
	return c.config.AuthCodeURL(state, options...), nil
}

func (c *OAuthClient) Exchange(ctx context.Context, code, nonce, verifier string) (Profile, error) {
	if code == "" {
		return Profile{}, fmt.Errorf("authorization code is required")
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, c.client)
	token, err := c.config.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return Profile{}, fmt.Errorf("exchange authorization code: %w", err)
	}
	profile := Profile{Provider: c.provider, Issuer: c.issuer}
	if c.verifier != nil {
		raw, ok := token.Extra("id_token").(string)
		if !ok {
			return Profile{}, fmt.Errorf("OIDC ID token is missing")
		}
		verified, err := c.verifier.Verify(ctx, raw)
		if err != nil {
			return Profile{}, fmt.Errorf("verify OIDC ID token: %w", err)
		}
		if nonce == "" || verified.Nonce != nonce {
			return Profile{}, fmt.Errorf("OIDC nonce does not match")
		}
		if verified.AccessTokenHash != "" {
			if err := verified.VerifyAccessToken(token.AccessToken); err != nil {
				return Profile{}, err
			}
		}
		var claims struct {
			Name     string `json:"name"`
			Email    string `json:"email"`
			Username string `json:"preferred_username"`
		}
		if err := verified.Claims(&claims); err != nil {
			return Profile{}, err
		}
		profile.Subject, profile.Username, profile.Nickname, profile.Email = verified.Subject, claims.Username, claims.Name, claims.Email
	} else if c.provider == "github" {
		profile, err = c.githubProfile(ctx, token)
		if err != nil {
			return Profile{}, err
		}
	} else {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.userInfoURL, nil)
		if err != nil {
			return Profile{}, err
		}
		token.SetAuthHeader(request)
		request.Header.Set("Accept", "application/json")
		response, err := c.client.Do(request)
		if err != nil {
			return Profile{}, fmt.Errorf("fetch OAuth2 profile: %w", err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return Profile{}, fmt.Errorf("OAuth2 user info returned status %d", response.StatusCode)
		}
		var claims map[string]any
		decoder := json.NewDecoder(io.LimitReader(response.Body, 1<<20))
		decoder.UseNumber()
		if err := decoder.Decode(&claims); err != nil {
			return Profile{}, fmt.Errorf("decode OAuth2 profile: %w", err)
		}
		profile.Subject = claimString(claims, c.subjectClaim)
		profile.Username = claimString(claims, c.usernameClaim)
		if c.usernameClaim == "" {
			for _, key := range []string{"preferred_username", "username", "login"} {
				if profile.Username = claimString(claims, key); strings.TrimSpace(profile.Username) != "" {
					break
				}
			}
		}
		profile.Nickname = claimString(claims, c.nameClaim)
		profile.Email = claimString(claims, c.emailClaim)
	}
	if profile.Subject == "" {
		return Profile{}, fmt.Errorf("provider subject is missing")
	}
	return profile, nil
}

func claimString(claims map[string]any, path string) string {
	var value any = claims
	for _, key := range strings.Split(path, ".") {
		object, ok := value.(map[string]any)
		if !ok {
			return ""
		}
		value = object[key]
	}
	switch value := value.(type) {
	case string:
		return value
	case json.Number:
		return value.String()
	default:
		return ""
	}
}
