package authn

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

type Config struct {
	// LocalEnabled is retained for stored configuration compatibility. Local
	// accounts are always enabled by the settings layer.
	LocalEnabled bool `json:"local_enabled"`
	AllowHTTP    bool `json:"allow_http"`
	// PUBLIC_URL may use HTTP locally without allowing HTTP identity-provider endpoints.
	AllowCallbackHTTP bool          `json:"-"`
	Timeout           time.Duration `json:"-"`
	OIDC              OIDCConfig    `json:"oidc"`
	OAuth2            OAuth2Config  `json:"oauth2"`
	GitHub            GitHubConfig  `json:"github"`
	LDAP              LDAPConfig    `json:"ldap"`
}

type OIDCConfig struct {
	Enabled      bool     `json:"enabled"`
	Name         string   `json:"name"`
	Issuer       string   `json:"issuer"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"-"`
	RedirectURL  string   `json:"-"`
	Scopes       []string `json:"scopes"`
}

type OAuth2Config struct {
	Enabled       bool     `json:"enabled"`
	Name          string   `json:"name"`
	ClientID      string   `json:"client_id"`
	ClientSecret  string   `json:"-"`
	AuthorizeURL  string   `json:"authorize_url"`
	TokenURL      string   `json:"token_url"`
	UserInfoURL   string   `json:"user_info_url"`
	RedirectURL   string   `json:"-"`
	Scopes        []string `json:"scopes"`
	SubjectClaim  string   `json:"subject_claim"`
	UsernameClaim string   `json:"username_claim"`
	NameClaim     string   `json:"name_claim"`
	EmailClaim    string   `json:"email_claim"`
}

type LDAPConfig struct {
	Enabled           bool   `json:"enabled"`
	Name              string `json:"name"`
	URL               string `json:"url"`
	BindDN            string `json:"bind_dn"`
	BindPassword      string `json:"-"`
	BaseDN            string `json:"base_dn"`
	UserFilter        string `json:"user_filter"`
	IDAttribute       string `json:"id_attribute"`
	UsernameAttribute string `json:"username_attribute"`
	NameAttribute     string `json:"name_attribute"`
	EmailAttribute    string `json:"email_attribute"`
	RootCAPEM         string `json:"root_ca_pem"`
}

type GitHubConfig struct {
	Enabled      bool   `json:"enabled"`
	Name         string `json:"name"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"-"`
	RedirectURL  string `json:"-"`
}

func (c LDAPConfig) Issuer() string { return c.URL + "/" + c.BaseDN }

func (c Config) Enabled() bool {
	return c.LocalEnabled || c.OIDC.Enabled || c.OAuth2.Enabled || c.GitHub.Enabled || c.LDAP.Enabled
}

func (c Config) Validate() error {
	if c.Timeout <= 0 || c.Timeout > time.Minute {
		return fmt.Errorf("authentication timeout must be between 0 and 1m")
	}
	endpoints := map[string]string{}
	callbacks := map[string]string{}
	if c.OIDC.Enabled {
		if c.OIDC.ClientID == "" || c.OIDC.ClientSecret == "" {
			return fmt.Errorf("OIDC client ID and client secret are required")
		}
		endpoints["OIDC issuer"] = c.OIDC.Issuer
		callbacks["OIDC callback URL"] = c.OIDC.RedirectURL
	}
	if c.OAuth2.Enabled {
		if c.OAuth2.ClientID == "" || c.OAuth2.ClientSecret == "" || c.OAuth2.SubjectClaim == "" {
			return fmt.Errorf("OAuth2 client ID, client secret and subject claim are required")
		}
		endpoints["OAuth2 authorization URL"] = c.OAuth2.AuthorizeURL
		endpoints["OAuth2 token URL"] = c.OAuth2.TokenURL
		endpoints["OAuth2 user info URL"] = c.OAuth2.UserInfoURL
		callbacks["OAuth2 callback URL"] = c.OAuth2.RedirectURL
	}
	if c.GitHub.Enabled {
		if c.GitHub.ClientID == "" || c.GitHub.ClientSecret == "" {
			return fmt.Errorf("GitHub Client ID 和 Client Secret 不能为空")
		}
		callbacks["GitHub callback URL"] = c.GitHub.RedirectURL
	}
	for name, endpoint := range endpoints {
		if err := ValidateURL(endpoint, c.AllowHTTP); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	for name, callback := range callbacks {
		if err := ValidateURL(callback, c.AllowHTTP || c.AllowCallbackHTTP); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if c.LDAP.Enabled {
		endpoint, err := url.Parse(c.LDAP.URL)
		if err != nil || endpoint.Host == "" || (endpoint.Scheme != "ldaps" && endpoint.Scheme != "ldap") || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || (endpoint.Path != "" && endpoint.Path != "/") {
			return fmt.Errorf("LDAP server must use ldaps:// or ldap:// with StartTLS")
		}
		if c.LDAP.BindDN == "" || c.LDAP.BindPassword == "" || c.LDAP.BaseDN == "" || c.LDAP.IDAttribute == "" || strings.Count(c.LDAP.UserFilter, "{username}") != 1 {
			return fmt.Errorf("LDAP bind DN, password, base DN, ID attribute and a user filter containing one {username} are required")
		}
	}
	return nil
}

func ValidateURL(raw string, allowHTTP bool) error {
	endpoint, err := url.Parse(raw)
	if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.Fragment != "" || (endpoint.Scheme != "https" && !(allowHTTP && endpoint.Scheme == "http")) {
		return fmt.Errorf("must be an HTTPS URL without credentials or fragment; HTTP requires the development HTTP setting")
	}
	return nil
}
