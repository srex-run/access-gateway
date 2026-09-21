package authn

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

const GitHubIssuer = "https://github.com"

func NewGitHub(config GitHubConfig, timeout time.Duration) *OAuthClient {
	client := authHTTPClient(timeout, false)
	// These fixed API endpoints do not need redirects. Never forward a code or token elsewhere.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &OAuthClient{
		config: oauth2.Config{ClientID: config.ClientID, ClientSecret: config.ClientSecret,
			Endpoint:    oauth2.Endpoint{AuthURL: GitHubIssuer + "/login/oauth/authorize", TokenURL: GitHubIssuer + "/login/oauth/access_token", AuthStyle: oauth2.AuthStyleInParams},
			RedirectURL: config.RedirectURL, Scopes: []string{"read:user", "user:email"}},
		client: client, provider: "github", issuer: GitHubIssuer,
	}
}

func (c *OAuthClient) githubProfile(ctx context.Context, token *oauth2.Token) (Profile, error) {
	var user struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
		Name  string `json:"name"`
	}
	if err := c.githubJSON(ctx, token, "/user", &user); err != nil {
		return Profile{}, err
	}
	if user.ID <= 0 || strings.TrimSpace(user.Login) == "" {
		return Profile{}, fmt.Errorf("GitHub user identity is missing")
	}
	profile := Profile{Provider: "github", Issuer: GitHubIssuer, Subject: strconv.FormatInt(user.ID, 10), Username: user.Login, Nickname: strings.TrimSpace(user.Name)}
	// /user omits private email and does not report verification. Only use verified addresses.
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := c.githubJSON(ctx, token, "/user/emails?per_page=100", &emails); err != nil {
		return Profile{}, err
	}
	for _, email := range emails {
		if !email.Verified || strings.TrimSpace(email.Email) == "" {
			continue
		}
		if profile.Email == "" || email.Primary {
			profile.Email = strings.TrimSpace(email.Email)
		}
		if email.Primary {
			break
		}
	}
	return profile, nil
}

func (c *OAuthClient) githubJSON(ctx context.Context, token *oauth2.Token, path string, value any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com"+path, nil)
	if err != nil {
		return err
	}
	token.SetAuthHeader(request)
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("User-Agent", "Access-Gateway")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	response, err := c.client.Do(request)
	if err != nil {
		return fmt.Errorf("fetch GitHub profile: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("GitHub profile returned status %d", response.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(value); err != nil {
		return fmt.Errorf("decode GitHub profile: %w", err)
	}
	return nil
}
