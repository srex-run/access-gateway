package settings

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/srex-run/access-gateway/internal/authn"
	"github.com/srex-run/access-gateway/internal/publicurl"
)

type Config struct {
	ClientAccessEnabled bool       `json:"client_access_enabled"`
	ClientAccessHost    string     `json:"client_access_host"`
	SMTP                SMTPConfig `json:"smtp"`
	MFA                 MFAConfig  `json:"mfa"`
	InvitationTTLHours  int        `json:"invitation_ttl_hours"`
	// Derived from deployment PUBLIC_URL; exposed for display, never persisted as a setting.
	BaseURL        string         `json:"base_url,omitempty"`
	TimeoutSeconds int            `json:"timeout_seconds"`
	Auth           authn.Config   `json:"auth"`
	Feishu         FeishuConfig   `json:"feishu"`
	AuditProfiles  []AuditProfile `json:"audit_profiles"`
}

type FeishuConfig struct {
	AppID                string `json:"app_id"`
	TenantKey            string `json:"tenant_key"`
	LoginEnabled         bool   `json:"login_enabled"`
	BindingEnabled       bool   `json:"binding_enabled"`
	NotificationsEnabled bool   `json:"notifications_enabled"`
	CallbacksEnabled     bool   `json:"callbacks_enabled"`
}

// Secrets never belong to config_json or an API response.
type Secrets struct {
	SMTPPassword   string               `json:"smtp_password"`
	OIDC           string               `json:"oidc"`
	OAuth2         string               `json:"oauth2"`
	GitHub         string               `json:"github"`
	LDAP           string               `json:"ldap"`
	FeishuApp      string               `json:"feishu_app"`
	FeishuCallback string               `json:"feishu_callback"`
	AuditProfiles  map[string]AuditKeys `json:"audit_profiles,omitempty"`
}

type SecretChanges struct {
	SMTPPassword   *string                    `json:"smtp_password"`
	OIDC           *string                    `json:"oidc"`
	OAuth2         *string                    `json:"oauth2"`
	GitHub         *string                    `json:"github"`
	LDAP           *string                    `json:"ldap"`
	FeishuApp      *string                    `json:"feishu_app"`
	FeishuCallback *string                    `json:"feishu_callback"`
	AuditProfiles  map[string]AuditKeyChanges `json:"audit_profiles,omitempty"`
}

type SecretStatus struct {
	SMTPPassword   bool                      `json:"smtp_password"`
	OIDC           bool                      `json:"oidc"`
	OAuth2         bool                      `json:"oauth2"`
	GitHub         bool                      `json:"github"`
	LDAP           bool                      `json:"ldap"`
	FeishuApp      bool                      `json:"feishu_app"`
	FeishuCallback bool                      `json:"feishu_callback"`
	AuditProfiles  map[string]AuditKeyStatus `json:"audit_profiles"`
}

func (s Secrets) Status() SecretStatus {
	status := SecretStatus{OIDC: s.OIDC != "", OAuth2: s.OAuth2 != "", LDAP: s.LDAP != "", FeishuApp: s.FeishuApp != "", FeishuCallback: s.FeishuCallback != "", AuditProfiles: map[string]AuditKeyStatus{}}
	status.SMTPPassword = s.SMTPPassword != ""
	status.GitHub = s.GitHub != ""
	for name, keys := range s.AuditProfiles {
		status.AuditProfiles[name] = AuditKeyStatus{keys.PrivateKey != "", keys.SSHHostKey != "", keys.TargetSSHKey != ""}
	}
	return status
}

func (s Secrets) Apply(changes SecretChanges) Secrets {
	for _, change := range []struct {
		from *string
		to   *string
	}{
		{changes.OIDC, &s.OIDC}, {changes.OAuth2, &s.OAuth2}, {changes.LDAP, &s.LDAP},
		{changes.GitHub, &s.GitHub},
		{changes.FeishuApp, &s.FeishuApp}, {changes.FeishuCallback, &s.FeishuCallback},
		{changes.SMTPPassword, &s.SMTPPassword},
	} {
		if change.from != nil {
			*change.to = *change.from
		}
	}
	return s
}

func Defaults() Config {
	return Config{SMTP: SMTPConfig{Port: 587, TLSMode: "starttls"}, MFA: MFAConfig{Mode: "off", Issuer: "Access Gateway"}, InvitationTTLHours: 72, TimeoutSeconds: 10, AuditProfiles: []AuditProfile{}, Auth: authn.Config{
		LocalEnabled: true,
		OIDC:         authn.OIDCConfig{Name: "OIDC", Scopes: []string{"profile", "email"}},
		OAuth2:       authn.OAuth2Config{Name: "OAuth2", Scopes: []string{}, SubjectClaim: "id", NameClaim: "name", EmailClaim: "email"},
		GitHub:       authn.GitHubConfig{Name: "GitHub"},
		LDAP:         authn.LDAPConfig{Name: "LDAP", UserFilter: "(uid={username})", IDAttribute: "entryUUID", NameAttribute: "displayName", EmailAttribute: "mail"},
	}}
}

func (c Config) CallbackURL(provider string) string {
	if c.BaseURL == "" {
		return ""
	}
	return c.BaseURL + "/api/v1/auth/" + provider + "/callback"
}

func (c Config) Authentication(secrets Secrets) authn.Config {
	auth := c.Auth
	// Local accounts are the recovery and bootstrap identity source. They stay
	// available even when an external provider is enabled.
	auth.LocalEnabled = true
	auth.Timeout = time.Duration(c.TimeoutSeconds) * time.Second
	auth.AllowCallbackHTTP = strings.HasPrefix(c.BaseURL, "http://")
	auth.OIDC.ClientSecret, auth.OAuth2.ClientSecret, auth.LDAP.BindPassword = secrets.OIDC, secrets.OAuth2, secrets.LDAP
	auth.OIDC.RedirectURL, auth.OAuth2.RedirectURL = c.CallbackURL("oidc"), c.CallbackURL("oauth2")
	auth.GitHub.ClientSecret, auth.GitHub.RedirectURL = secrets.GitHub, c.CallbackURL("github")
	return auth
}

func (c *Config) Normalize() {
	c.ClientAccessHost = strings.TrimSpace(c.ClientAccessHost)
	// The local account store is permanent; keep the legacy field true for
	// backwards-compatible configuration and API responses.
	c.Auth.LocalEnabled = true
	if c.MFA.Mode == "" {
		c.MFA = Defaults().MFA
	}
	if c.SMTP.TLSMode == "" {
		c.SMTP.TLSMode = "starttls"
	}
	if c.SMTP.Port == 0 {
		c.SMTP.Port = 587
	}
	if c.InvitationTTLHours == 0 {
		c.InvitationTTLHours = 72
	}
	c.SMTP.Host, c.SMTP.From, c.SMTP.Username = strings.TrimSpace(c.SMTP.Host), strings.TrimSpace(c.SMTP.From), strings.TrimSpace(c.SMTP.Username)
	c.MFA.Issuer = strings.TrimSpace(c.MFA.Issuer)
	c.BaseURL = strings.TrimRight(strings.TrimSpace(c.BaseURL), "/")
	for _, field := range []*string{&c.Auth.OIDC.Name, &c.Auth.OIDC.Issuer, &c.Auth.OIDC.ClientID,
		&c.Auth.GitHub.Name, &c.Auth.GitHub.ClientID,
		&c.Auth.OAuth2.Name, &c.Auth.OAuth2.ClientID, &c.Auth.OAuth2.AuthorizeURL, &c.Auth.OAuth2.TokenURL, &c.Auth.OAuth2.UserInfoURL,
		&c.Auth.OAuth2.UsernameClaim,
		&c.Auth.LDAP.Name, &c.Auth.LDAP.URL, &c.Auth.LDAP.BindDN, &c.Auth.LDAP.BaseDN,
		&c.Auth.LDAP.UsernameAttribute,
		&c.Feishu.AppID, &c.Feishu.TenantKey} {
		*field = strings.TrimSpace(*field)
	}
	if c.Auth.GitHub.Name == "" {
		c.Auth.GitHub.Name = "GitHub"
	}
}

func (c Config) Validate(secrets Secrets) error {
	if c.ClientAccessEnabled && !validClientAccessHost(c.ClientAccessHost) {
		return fmt.Errorf("客户端入口地址需填写可直达服务器的公网 IP 或 DNS 直连域名，不包含协议、端口或路径")
	}
	// Older rows may still contain local_enabled=false. Normalize the effective
	// configuration before validating so external providers can never disable
	// the local recovery login.
	c.Auth.LocalEnabled = true
	if err := c.validateIdentity(secrets); err != nil {
		return err
	}
	if c.TimeoutSeconds < 1 || c.TimeoutSeconds > 60 {
		return fmt.Errorf("认证请求超时必须为 1 到 60 秒")
	}
	if c.BaseURL != "" {
		if _, err := publicurl.Parse(c.BaseURL); err != nil {
			return err
		}
	}
	if !c.Auth.Enabled() && !c.Feishu.LoginEnabled {
		return fmt.Errorf("至少保留一种登录方式")
	}
	if err := c.Authentication(secrets).Validate(); err != nil {
		return err
	}
	for _, name := range []string{c.Auth.OIDC.Name, c.Auth.OAuth2.Name, c.Auth.GitHub.Name, c.Auth.LDAP.Name} {
		if name == "" || len(name) > 128 {
			return fmt.Errorf("登录方式名称不能为空或超过 128 字节")
		}
	}
	f := c.Feishu
	if f.LoginEnabled || f.BindingEnabled || f.NotificationsEnabled || f.CallbacksEnabled {
		if f.AppID == "" || f.TenantKey == "" || secrets.FeishuApp == "" {
			return fmt.Errorf("启用飞书集成前请填写应用 ID、应用密钥和租户标识")
		}
	}
	if (f.LoginEnabled || f.BindingEnabled) && c.BaseURL == "" {
		return fmt.Errorf("启用飞书登录或绑定前请配置 PUBLIC_URL")
	}
	if f.CallbacksEnabled && len(secrets.FeishuCallback) < 32 {
		return fmt.Errorf("飞书回调密钥至少需要 32 字节")
	}
	return nil
}

var clientHostPattern = regexp.MustCompile(`(?i)^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$`)

func validClientAccessHost(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return !ip.IsUnspecified() && !ip.IsMulticast()
	}
	return len(host) <= 253 && clientHostPattern.MatchString(host)
}
