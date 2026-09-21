package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/srex-run/access-gateway/internal/authn"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/feishu"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/publicurl"
	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/secretstore"
	"github.com/srex-run/access-gateway/internal/sessionproxy"
	"github.com/srex-run/access-gateway/internal/settings"
)

const settingsAAD = "access-gateway/system-settings/secrets/v1"

type SettingsView struct {
	Config     settings.Config       `json:"config"`
	HasSecrets settings.SecretStatus `json:"has_secrets"`
	Revision   int64                 `json:"revision"`
	UpdatedAt  *time.Time            `json:"updated_at"`
}

type SettingsUpdate struct {
	Config   *settings.Config       `json:"config"`
	Secrets  settings.SecretChanges `json:"secrets"`
	Revision *int64                 `json:"revision"`
}

type SettingsValidationError struct{ Message string }

func (e *SettingsValidationError) Error() string { return e.Message }
func (e *SettingsValidationError) Unwrap() error { return ErrValidation }

type SystemSettingsService struct {
	db        *sql.DB
	publicURL string
	cipher    secretstore.Cipher
	repo      *repository.SystemSettingsRepository
	users     *repository.UserRepository
	audits    *repository.AuditEventRepository
	mu        sync.Mutex
	snapshot  atomic.Pointer[settings.Snapshot]
}

func NewSystemSettingsService(database *sql.DB, cipher secretstore.Cipher, publicURL string) (*SystemSettingsService, error) {
	if database == nil || cipher == nil {
		return nil, fmt.Errorf("system settings require database and encryption key")
	}
	origin, err := publicurl.Parse(publicURL)
	if err != nil {
		return nil, err
	}
	return &SystemSettingsService{db: database, publicURL: origin.String(), cipher: cipher, repo: &repository.SystemSettingsRepository{},
		users: repository.NewUserRepository(), audits: repository.NewAuditEventRepository()}, nil
}

func (s *SystemSettingsService) read(ctx context.Context, q repository.DBTX) (repository.SystemSettings, error) {
	row, err := s.repo.Get(ctx, q)
	if errors.Is(err, repository.ErrNotFound) {
		return repository.SystemSettings{}, nil
	}
	return row, err
}

func (s *SystemSettingsService) decode(ctx context.Context, row repository.SystemSettings) (settings.Config, settings.Secrets, error) {
	config, secrets := settings.Defaults(), settings.Secrets{}
	config.BaseURL = s.publicURL
	if row.Revision == 0 {
		return config, secrets, nil
	}
	if err := json.Unmarshal(row.ConfigJSON, &config); err != nil {
		return config, secrets, fmt.Errorf("invalid stored system settings")
	}
	config.Normalize()
	// Older settings may contain a base URL; the deployment origin always wins.
	config.BaseURL = s.publicURL
	plaintext, err := s.cipher.Decrypt(ctx, row.SecretsCiphertext, []byte(settingsAAD))
	if err != nil {
		return config, secrets, fmt.Errorf("decrypt system settings: check encryption key")
	}
	defer clear(plaintext)
	if err := json.Unmarshal(plaintext, &secrets); err != nil {
		return config, secrets, fmt.Errorf("invalid encrypted system settings")
	}
	config.RestoreAuditCertificates(secrets)
	return config, secrets, nil
}

func settingsView(row repository.SystemSettings, config settings.Config, secrets settings.Secrets) SettingsView {
	view := SettingsView{Config: config, HasSecrets: secrets.Status(), Revision: row.Revision}
	if row.Revision > 0 {
		view.UpdatedAt = &row.UpdatedAt
	}
	return view
}

func (s *SystemSettingsService) Get(ctx context.Context) (SettingsView, error) {
	row, err := s.read(ctx, s.db)
	if err != nil {
		return SettingsView{}, err
	}
	config, secrets, err := s.decode(ctx, row)
	return settingsView(row, config, secrets), err
}

func (s *SystemSettingsService) resolveOpenID(ctx context.Context, userID string) (string, error) {
	user, err := s.users.GetByID(ctx, s.db, userID)
	return user.FeishuOpenID, err
}

// Read the revision on every use, so another replica's committed changes are observed immediately.
func (s *SystemSettingsService) Current(ctx context.Context) (*settings.Snapshot, error) {
	row, err := s.read(ctx, s.db)
	if err != nil {
		return nil, err
	}
	if cached := s.snapshot.Load(); cached != nil && cached.Revision >= row.Revision {
		return cached, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if cached := s.snapshot.Load(); cached != nil && cached.Revision >= row.Revision {
		return cached, nil
	}
	config, secrets, err := s.decode(ctx, row)
	if err != nil {
		return nil, err
	}
	snapshot, err := settings.Build(config, secrets, row.Revision, s.resolveOpenID)
	if err != nil {
		return nil, fmt.Errorf("invalid stored system configuration")
	}
	s.snapshot.Store(snapshot)
	return snapshot, nil
}

func (s *SystemSettingsService) Save(ctx context.Context, actor string, update SettingsUpdate) (SettingsView, error) {
	if update.Config == nil || update.Revision == nil || *update.Revision < 0 {
		return SettingsView{}, &SettingsValidationError{"配置与版本号不能为空"}
	}
	row, err := s.read(ctx, s.db)
	if err != nil {
		return SettingsView{}, err
	}
	if row.Revision != *update.Revision {
		return SettingsView{}, ErrStateConflict
	}
	previous, secrets, err := s.decode(ctx, row)
	if err != nil {
		return SettingsView{}, err
	}
	config := *update.Config
	config.BaseURL = s.publicURL
	// Preserve newly added sections when an older console sends its complete configuration.
	if config.Auth.GitHub.Name == "" && config.Auth.GitHub.ClientID == "" && !config.Auth.GitHub.Enabled {
		config.Auth.GitHub = previous.Auth.GitHub
	}
	if config.MFA.Mode == "" {
		config.MFA = previous.MFA
	}
	if config.SMTP.TLSMode == "" {
		config.SMTP = previous.SMTP
	}
	if config.InvitationTTLHours == 0 {
		config.InvitationTTLHours = previous.InvitationTTLHours
	}
	config.Normalize()
	secrets = secrets.Apply(update.Secrets)
	if err := config.ApplyAudit(previous, &secrets, update.Secrets.AuditProfiles); err != nil {
		return SettingsView{}, &SettingsValidationError{err.Error()}
	}
	snapshot, err := settings.Build(config, secrets, row.Revision+1, s.resolveOpenID)
	if err != nil {
		return SettingsView{}, &SettingsValidationError{err.Error()}
	}
	storedConfig := config.StoreAuditCertificates(&secrets)
	storedConfig.BaseURL = ""
	configJSON, err := json.Marshal(storedConfig)
	if err != nil {
		return SettingsView{}, err
	}
	secretJSON, err := json.Marshal(secrets)
	if err != nil {
		return SettingsView{}, err
	}
	defer clear(secretJSON)
	if len(configJSON)+len(secretJSON) > 450<<10 {
		return SettingsView{}, &SettingsValidationError{"配置内容过长"}
	}
	ciphertext, err := s.cipher.Encrypt(ctx, secretJSON, []byte(settingsAAD))
	if err != nil {
		return SettingsView{}, fmt.Errorf("encrypt system settings failed")
	}
	err = InTx(ctx, s.db, func(q repository.DBTX) error {
		if err := s.repo.Lock(ctx, q); err != nil {
			return err
		}
		current, err := s.read(ctx, q)
		if err != nil {
			return err
		}
		if current.Revision != row.Revision {
			return ErrStateConflict
		}
		if (previous.Feishu.AppID != "" && previous.Feishu.AppID != config.Feishu.AppID) || (previous.Feishu.TenantKey != "" && previous.Feishu.TenantKey != config.Feishu.TenantKey) {
			bound, err := s.repo.HasFeishuBindings(ctx, q)
			if err != nil {
				return err
			}
			if bound {
				return &SettingsValidationError{"已有飞书账号绑定，不能直接更换应用或租户"}
			}
		}
		if err := s.ensureLogin(ctx, q, actor, config); err != nil {
			return err
		}
		row, err = s.repo.Save(ctx, q, repository.SystemSettings{ConfigJSON: configJSON, SecretsCiphertext: ciphertext, UpdatedBy: actor}, current.Revision)
		if err != nil {
			return err
		}
		return s.audits.Append(ctx, q, domain.AuditEvent{ID: id.New(), EventType: "system.settings_updated", ActorType: "user", ActorID: &actor,
			Result: stringPtr("success"), Metadata: map[string]any{"revision": row.Revision}})
	})
	if err != nil {
		return SettingsView{}, err
	}
	s.mu.Lock()
	if cached := s.snapshot.Load(); cached == nil || cached.Revision < snapshot.Revision {
		s.snapshot.Store(snapshot)
	}
	s.mu.Unlock()
	return settingsView(row, config, secrets), nil
}

func (s *SystemSettingsService) ensureLogin(ctx context.Context, q repository.DBTX, actor string, config settings.Config) error {
	user, err := s.users.GetByIDForUpdate(ctx, q, actor)
	if err != nil {
		return err
	}
	if user.Status != domain.UserStatusActive {
		return ErrForbidden
	}
	credential, err := s.users.LocalCredentialByUser(ctx, q, actor)
	if err == nil && credential.UserID != "" {
		return nil
	}
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		return err
	}
	if config.Feishu.LoginEnabled && user.FeishuOpenID != "" {
		return nil
	}
	for _, provider := range []struct {
		name, issuer string
		enabled      bool
	}{
		{"oidc", config.Auth.OIDC.Issuer, config.Auth.OIDC.Enabled},
		{"oauth2", config.Auth.OAuth2.UserInfoURL, config.Auth.OAuth2.Enabled},
		{"github", authn.GitHubIssuer, config.Auth.GitHub.Enabled},
		{"ldap", config.Auth.LDAP.Issuer(), config.Auth.LDAP.Enabled},
	} {
		if !provider.enabled {
			continue
		}
		exists, err := s.users.HasIdentityIssuer(ctx, q, actor, provider.name, provider.issuer)
		if err != nil {
			return err
		}
		if exists {
			return nil
		}
	}
	return &SettingsValidationError{"保存后当前管理员将没有可用的登录方式，请保留已关联的登录方式"}
}

func (s *SystemSettingsService) NotifyApproval(ctx context.Context, request domain.AccessRequest, approvals []domain.Approval) error {
	snapshot, err := s.Current(ctx)
	if err != nil {
		return err
	}
	return snapshot.Notifier.NotifyApproval(ctx, request, approvals)
}
func (s *SystemSettingsService) NotifyRequestResult(ctx context.Context, request domain.AccessRequest) error {
	snapshot, err := s.Current(ctx)
	if err != nil {
		return err
	}
	return snapshot.Notifier.NotifyRequestResult(ctx, request)
}
func (s *SystemSettingsService) NotifySessionReady(ctx context.Context, request domain.AccessRequest, session domain.Session) error {
	snapshot, err := s.Current(ctx)
	if err != nil {
		return err
	}
	return snapshot.Notifier.NotifySessionReady(ctx, request, session)
}
func (s *SystemSettingsService) NotifySessionClosed(ctx context.Context, request domain.AccessRequest, session domain.Session) error {
	snapshot, err := s.Current(ctx)
	if err != nil {
		return err
	}
	return snapshot.Notifier.NotifySessionClosed(ctx, request, session)
}

var _ feishu.Notifier = (*SystemSettingsService)(nil)

func (s *SystemSettingsService) AuditRegistry(ctx context.Context) (*sessionproxy.Registry, error) {
	snapshot, err := s.Current(ctx)
	if err != nil {
		return nil, err
	}
	return snapshot.AuditProfiles, nil
}

func (s *SystemSettingsService) auditRegistry(ctx context.Context, q repository.DBTX) (*sessionproxy.Registry, error) {
	row, err := s.read(ctx, q)
	if err != nil {
		return nil, err
	}
	config, secrets, err := s.decode(ctx, row)
	if err != nil {
		return nil, err
	}
	return config.AuditRegistry(secrets)
}
