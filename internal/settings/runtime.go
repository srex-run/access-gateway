package settings

import (
	"context"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/srex-run/access-gateway/internal/authn"
	"github.com/srex-run/access-gateway/internal/feishu"
	"github.com/srex-run/access-gateway/internal/mailer"
	"github.com/srex-run/access-gateway/internal/sessionproxy"
)

// A snapshot and its provider configuration are immutable after construction.
type Snapshot struct {
	ClientAccessEnabled bool
	ClientAccessHost    string
	BaseURL             string
	MFA                 MFAConfig
	InvitationTTLHours  int
	Mailer              mailer.Mailer
	Revision            int64
	Auth                authn.Config
	Feishu              FeishuConfig
	CallbackSecret      string
	OAuth               *feishu.OAuthClient
	RedirectProviders   map[string]authn.RedirectProvider
	LDAP                authn.PasswordProvider
	Notifier            feishu.Notifier
	AuditProfiles       *sessionproxy.Registry
}

type snapshotKey struct{}

func WithSnapshot(ctx context.Context, snapshot *Snapshot) context.Context {
	return context.WithValue(ctx, snapshotKey{}, snapshot)
}

func FromContext(ctx context.Context) *Snapshot {
	snapshot, _ := ctx.Value(snapshotKey{}).(*Snapshot)
	return snapshot
}

func Build(config Config, secrets Secrets, revision int64, resolve feishu.OpenIDResolver) (*Snapshot, error) {
	if err := config.Validate(secrets); err != nil {
		return nil, err
	}
	s := &Snapshot{Revision: revision, Auth: config.Authentication(secrets), Feishu: config.Feishu,
		ClientAccessEnabled: config.ClientAccessEnabled,
		ClientAccessHost:    config.ClientAccessHost,
		RedirectProviders:   make(map[string]authn.RedirectProvider), Notifier: feishu.NoopNotifier{}}
	s.BaseURL, s.MFA, s.InvitationTTLHours = config.BaseURL, config.MFA, config.InvitationTTLHours
	mail := mailer.New(zerolog.Nop())
	mail.SetConfig(config.MailConfig(secrets))
	s.Mailer = mail
	if s.Auth.OIDC.Enabled {
		s.RedirectProviders["oidc"] = &lazyOIDC{config: s.Auth}
	}
	if s.Auth.OAuth2.Enabled {
		s.RedirectProviders["oauth2"] = authn.NewOAuth2(s.Auth.OAuth2, s.Auth.Timeout, s.Auth.AllowHTTP)
	}
	if s.Auth.GitHub.Enabled {
		s.RedirectProviders["github"] = authn.NewGitHub(s.Auth.GitHub, s.Auth.Timeout)
	}
	var err error
	s.AuditProfiles, err = config.AuditRegistry(secrets)
	if err != nil {
		return nil, err
	}
	if s.Auth.LDAP.Enabled {
		s.LDAP, err = authn.NewLDAP(s.Auth.LDAP, s.Auth.Timeout)
		if err != nil {
			return nil, err
		}
	}
	if config.Feishu.LoginEnabled || config.Feishu.BindingEnabled {
		s.OAuth, err = feishu.NewOAuthClient(feishu.OAuthConfig{
			AppID: config.Feishu.AppID, AppSecret: secrets.FeishuApp, TenantKey: config.Feishu.TenantKey,
			RedirectURL:       config.CallbackURL("feishu"),
			AuthorizeURL:      "https://open.feishu.cn/open-apis/authen/v1/authorize",
			AppAccessTokenURL: "https://open.feishu.cn/open-apis/auth/v3/app_access_token/internal",
			TokenURL:          "https://open.feishu.cn/open-apis/authen/v1/access_token",
			UserInfoURL:       "https://open.feishu.cn/open-apis/authen/v1/user_info",
		}, s.Auth.Timeout)
		if err != nil {
			return nil, err
		}
	}
	if config.Feishu.CallbacksEnabled {
		s.CallbackSecret = secrets.FeishuCallback
	}
	if config.Feishu.NotificationsEnabled {
		s.Notifier, err = feishu.NewHTTPNotifier(feishu.NotifierConfig{AppID: config.Feishu.AppID, AppSecret: secrets.FeishuApp, PublicURL: config.BaseURL,
			WebApprovalOnly: !config.Feishu.CallbacksEnabled, ResolveOpenID: resolve})
		if err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Discovery is deferred so an unavailable identity provider cannot prevent local recovery login.
type lazyOIDC struct {
	mu         sync.Mutex
	config     authn.Config
	provider   authn.RedirectProvider
	retryAfter time.Time
	lastError  error
}

func (p *lazyOIDC) load(ctx context.Context) (authn.RedirectProvider, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.provider == nil {
		if time.Now().Before(p.retryAfter) {
			return nil, p.lastError
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		provider, err := authn.NewOIDC(ctx, p.config.OIDC, p.config.Timeout, p.config.AllowHTTP)
		if err != nil {
			p.retryAfter, p.lastError = time.Now().Add(5*time.Second), err
			return nil, err
		}
		p.provider = provider
	}
	return p.provider, nil
}

func (p *lazyOIDC) AuthorizationURL(state, nonce, verifier string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), p.config.Timeout)
	defer cancel()
	provider, err := p.load(ctx)
	if err != nil {
		return "", err
	}
	return provider.AuthorizationURL(state, nonce, verifier)
}

func (p *lazyOIDC) Exchange(ctx context.Context, code, nonce, verifier string) (authn.Profile, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	provider, err := p.load(ctx)
	if err != nil {
		return authn.Profile{}, err
	}
	return provider.Exchange(ctx, code, nonce, verifier)
}
