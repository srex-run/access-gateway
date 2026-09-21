package feishu

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

type OAuthConfig struct {
	AppID             string
	AppSecret         string
	RedirectURL       string
	AuthorizeURL      string
	AppAccessTokenURL string
	TokenURL          string
	UserInfoURL       string
	TenantKey         string
}

type Profile struct {
	OpenID     string
	UnionID    string
	TenantKey  string
	Nickname   string
	Username   string
	Email      string
	Department string
	Active     bool
}

type OAuthClient struct {
	config OAuthConfig
	client *http.Client
}

func NewOAuthClient(config OAuthConfig, timeout time.Duration) (*OAuthClient, error) {
	if config.AppID == "" || config.AppSecret == "" || config.RedirectURL == "" || config.AuthorizeURL == "" || config.AppAccessTokenURL == "" || config.TokenURL == "" || config.UserInfoURL == "" || config.TenantKey == "" {
		return nil, fmt.Errorf("incomplete Feishu OAuth configuration")
	}
	for name, endpoint := range map[string]string{
		"authorize": config.AuthorizeURL, "app access token": config.AppAccessTokenURL,
		"token": config.TokenURL, "user info": config.UserInfoURL,
	} {
		parsed, err := url.Parse(strings.TrimSpace(endpoint))
		if err != nil || parsed.Host == "" || parsed.User != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") {
			return nil, fmt.Errorf("Feishu %s URL is invalid", name)
		}
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &OAuthClient{config: config, client: &http.Client{
		Timeout:   timeout,
		Transport: otelhttp.NewTransport(http.DefaultTransport),
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}, nil
}

func (c *OAuthClient) AuthorizationURL(state string) (string, error) {
	if state == "" {
		return "", fmt.Errorf("OAuth state is required")
	}
	parsed, err := url.Parse(c.config.AuthorizeURL)
	if err != nil {
		return "", fmt.Errorf("parse Feishu authorization URL: %w", err)
	}
	query := parsed.Query()
	query.Set("app_id", c.config.AppID)
	query.Set("redirect_uri", c.config.RedirectURL)
	query.Set("response_type", "code")
	query.Set("state", state)
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func (c *OAuthClient) Exchange(ctx context.Context, code string) (Profile, error) {
	if strings.TrimSpace(code) == "" {
		return Profile{}, fmt.Errorf("authorization code is required")
	}
	appAccessToken, err := c.appAccessToken(ctx)
	if err != nil {
		return Profile{}, err
	}
	payload, err := json.Marshal(map[string]string{
		"grant_type": "authorization_code",
		"code":       code,
	})
	if err != nil {
		return Profile{}, fmt.Errorf("encode Feishu token request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.config.TokenURL, bytes.NewReader(payload))
	if err != nil {
		return Profile{}, fmt.Errorf("build Feishu token request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+appAccessToken)
	response, err := c.client.Do(request)
	if err != nil {
		return Profile{}, fmt.Errorf("exchange Feishu code: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return Profile{}, fmt.Errorf("Feishu token endpoint returned %s", response.Status)
	}
	var token tokenResponse
	if err := decodeJSONResponse(response.Body, &token); err != nil {
		return Profile{}, fmt.Errorf("decode Feishu token response: %w", err)
	}
	if token.Code != 0 {
		return Profile{}, fmt.Errorf("Feishu token endpoint rejected request: code=%d message=%s", token.Code, token.Message)
	}
	accessToken := token.AccessToken
	if accessToken == "" {
		accessToken = token.Data.AccessToken
	}
	if accessToken == "" {
		return Profile{}, fmt.Errorf("Feishu token response did not contain an access token")
	}
	profile, err := c.fetchProfile(ctx, accessToken)
	if err != nil {
		return Profile{}, err
	}
	if profile.TenantKey == "" || profile.TenantKey != c.config.TenantKey {
		return Profile{}, fmt.Errorf("Feishu user belongs to an unauthorized tenant")
	}
	return profile, nil
}

func (c *OAuthClient) appAccessToken(ctx context.Context) (string, error) {
	payload, err := json.Marshal(map[string]string{
		"app_id":     c.config.AppID,
		"app_secret": c.config.AppSecret,
	})
	if err != nil {
		return "", fmt.Errorf("encode Feishu app token request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.config.AppAccessTokenURL, bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("build Feishu app token request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := c.client.Do(request)
	if err != nil {
		return "", fmt.Errorf("request Feishu app token: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", fmt.Errorf("Feishu app token endpoint returned %s", response.Status)
	}
	var result appTokenResponse
	if err := decodeJSONResponse(response.Body, &result); err != nil {
		return "", fmt.Errorf("decode Feishu app token response: %w", err)
	}
	if result.Code != 0 || result.AppAccessToken == "" {
		return "", fmt.Errorf("Feishu app token endpoint rejected request: code=%d message=%s", result.Code, result.Message)
	}
	return result.AppAccessToken, nil
}

func (c *OAuthClient) fetchProfile(ctx context.Context, accessToken string) (Profile, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.config.UserInfoURL, nil)
	if err != nil {
		return Profile{}, fmt.Errorf("build Feishu profile request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)
	response, err := c.client.Do(request)
	if err != nil {
		return Profile{}, fmt.Errorf("fetch Feishu profile: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return Profile{}, fmt.Errorf("Feishu profile endpoint returned %s", response.Status)
	}
	var payload profileResponse
	if err := decodeJSONResponse(response.Body, &payload); err != nil {
		return Profile{}, fmt.Errorf("decode Feishu profile response: %w", err)
	}
	if payload.Code != 0 {
		return Profile{}, fmt.Errorf("Feishu profile endpoint rejected request: code=%d message=%s", payload.Code, payload.Message)
	}
	profile := payload.Data
	if profile.OpenID == "" {
		profile = payload.Profile
	}
	if profile.OpenID == "" {
		return Profile{}, fmt.Errorf("Feishu profile did not contain open_id")
	}
	active := true
	if profile.Active != nil {
		active = *profile.Active
	}
	return Profile{OpenID: profile.OpenID, UnionID: profile.UnionID, TenantKey: profile.TenantKey, Username: profile.EnglishName, Nickname: profile.Name, Email: profile.Email, Department: profile.Department, Active: active}, nil
}

type appTokenResponse struct {
	Code           int    `json:"code"`
	Message        string `json:"msg"`
	AppAccessToken string `json:"app_access_token"`
}

type tokenResponse struct {
	Code        int       `json:"code"`
	Message     string    `json:"msg"`
	AccessToken string    `json:"access_token"`
	Data        tokenData `json:"data"`
}

type tokenData struct {
	AccessToken string `json:"access_token"`
}

type profileResponse struct {
	Code    int         `json:"code"`
	Message string      `json:"msg"`
	Data    profileData `json:"data"`
	Profile profileData `json:"profile"`
}

type profileData struct {
	OpenID      string `json:"open_id"`
	UnionID     string `json:"union_id"`
	TenantKey   string `json:"tenant_key"`
	Name        string `json:"name"`
	EnglishName string `json:"en_name"`
	Email       string `json:"email"`
	Department  string `json:"department"`
	Active      *bool  `json:"active"`
}

func decodeJSONResponse(reader io.Reader, target any) error {
	const limit = int64(1 << 20)
	encoded, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return err
	}
	defer clear(encoded)
	if int64(len(encoded)) > limit {
		return fmt.Errorf("response exceeds %d bytes", limit)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}
