package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/srex-run/access-gateway/internal/authn"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/feishu"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/security"
	"github.com/srex-run/access-gateway/internal/settings"
)

var ErrInvalidCredentials = errors.New("invalid credentials")

type Account struct {
	UserID      string   `json:"user_id"`
	Nickname    string   `json:"nickname"`
	Username    string   `json:"username"`
	Providers   []string `json:"providers"`
	FeishuBound bool     `json:"feishu_bound"`
}

func (s *AccessService) AuthenticateLocal(ctx context.Context, username, password string) (domain.User, error) {
	username, err := security.NormalizeUsername(username)
	if err != nil {
		security.CheckPassword("", password)
		return domain.User{}, ErrInvalidCredentials
	}
	credential, err := s.users.LocalCredential(ctx, s.db, username)
	if errors.Is(err, repository.ErrNotFound) {
		security.CheckPassword("", password)
		return domain.User{}, ErrInvalidCredentials
	}
	if err != nil {
		return domain.User{}, err
	}
	// Credentials and their session version come from the same database snapshot.
	user, err := s.users.GetByID(ctx, s.db, credential.UserID)
	if err != nil {
		return domain.User{}, err
	}
	if !security.CheckPassword(credential.PasswordHash, password) || user.Status != domain.UserStatusActive {
		return domain.User{}, ErrInvalidCredentials
	}
	user.AuthVersion = credential.AuthVersion
	return user, nil
}

func (s *AccessService) SyncExternalUser(ctx context.Context, profile authn.Profile) (domain.User, error) {
	if profile.Provider != "oidc" && profile.Provider != "oauth2" && profile.Provider != "github" && profile.Provider != "ldap" {
		return domain.User{}, ErrValidation
	}
	profile.Nickname = strings.TrimSpace(profile.Nickname)
	if profile.Issuer == "" || profile.Subject == "" || len(profile.Issuer) > 1024 || len(profile.Subject) > 512 || len(profile.Username) > 256 || len(profile.Nickname) > 128 || len(profile.Email) > 256 {
		return domain.User{}, ErrValidation
	}
	var user domain.User
	err := InTx(ctx, s.db, func(q repository.DBTX) error {
		if err := (repository.IAMRepository{}).Lock(ctx, q, false); err != nil {
			return err
		}
		key, _ := json.Marshal([]string{profile.Provider, profile.Issuer, profile.Subject})
		if err := s.users.LockIdentity(ctx, q, string(key)); err != nil {
			return err
		}
		var err error
		created := false
		user, err = s.users.GetByIdentity(ctx, q, profile.Provider, profile.Issuer, profile.Subject)
		if errors.Is(err, repository.ErrNotFound) {
			created = true
			user = domain.User{ID: id.New(), Username: security.ExternalUsername(profile.Username, profile.Email, profile.Provider, profile.Issuer+"\x00"+profile.Subject), Nickname: profile.Nickname, Status: domain.UserStatusActive}
			if profile.Email != "" {
				user.Email = stringPtr(profile.Email)
			}
			user, err = s.users.CreateExternal(ctx, q, user)
			if err != nil {
				return err
			}
			err = s.users.CreateIdentity(ctx, q, profile.Provider, profile.Issuer, profile.Subject, user.ID)
		}
		if err != nil {
			return err
		}
		if user.Status != domain.UserStatusActive {
			return ErrForbidden
		}
		if created {
			return s.appendAudit(ctx, q, domain.AuditEvent{EventType: "user.external_created", ActorType: "user", ActorID: stringPtr(user.ID), SubjectUserID: stringPtr(user.ID), Result: stringPtr("success"), Metadata: map[string]any{"provider": profile.Provider}})
		}
		return nil
	})
	return user, err
}

func (s *AccessService) ValidateBrowserSession(ctx context.Context, userID string, version int64) error {
	user, err := s.users.GetByID(ctx, s.db, userID)
	if errors.Is(err, repository.ErrNotFound) {
		return ErrInvalidCredentials
	}
	if err != nil {
		return err
	}
	if user.Status != domain.UserStatusActive || user.AuthVersion != version {
		return ErrInvalidCredentials
	}
	return nil
}

func (s *AccessService) GetAccount(ctx context.Context, userID string) (Account, error) {
	user, err := s.users.GetByID(ctx, s.db, userID)
	if err != nil {
		return Account{}, err
	}
	if user.Status != domain.UserStatusActive {
		return Account{}, ErrForbidden
	}
	providers, err := s.users.IdentityProviders(ctx, s.db, userID)
	if err != nil {
		return Account{}, err
	}
	account := Account{UserID: user.ID, Username: user.Username, Nickname: user.Nickname, FeishuBound: user.FeishuOpenID != "", Providers: providers}
	_, err = s.users.LocalCredentialByUser(ctx, s.db, userID)
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		return Account{}, err
	}
	if err == nil {
		account.Providers = append(account.Providers, "local")
	}
	if account.FeishuBound {
		account.Providers = append(account.Providers, "feishu")
	}
	return account, nil
}

func (s *AccessService) ChangePassword(ctx context.Context, userID, currentPassword, newPassword string) error {
	hash, err := security.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("%s: %w", err, ErrValidation)
	}
	return InTx(ctx, s.db, func(q repository.DBTX) error {
		user, err := s.users.GetByIDForUpdate(ctx, q, userID)
		if err != nil {
			return err
		}
		if user.Status != domain.UserStatusActive {
			return ErrForbidden
		}
		credential, err := s.users.LocalCredentialByUser(ctx, q, userID)
		if errors.Is(err, repository.ErrNotFound) {
			return ErrInvalidCredentials
		}
		if err != nil {
			return err
		}
		if !security.CheckPassword(credential.PasswordHash, currentPassword) {
			return ErrInvalidCredentials
		}
		if err := s.users.UpdateLocalPassword(ctx, q, userID, hash); err != nil {
			return err
		}
		return s.appendAudit(ctx, q, domain.AuditEvent{EventType: "user.password_changed", ActorType: "user", ActorID: stringPtr(userID), SubjectUserID: stringPtr(userID)})
	})
}

func (s *AccessService) BindFeishuUser(ctx context.Context, userID string, version int64, profile feishu.Profile) error {
	tenant, err := s.expectedFeishuTenant(ctx)
	if err != nil {
		return err
	}
	if !profile.Active || profile.OpenID == "" || len(profile.OpenID) > 128 || len(profile.UnionID) > 128 || tenant == "" || profile.TenantKey != tenant {
		return ErrForbidden
	}
	return InTx(ctx, s.db, func(q repository.DBTX) error {
		if err := (repository.IAMRepository{}).Lock(ctx, q, false); err != nil {
			return err
		}
		if err := s.validateFeishuSettings(ctx, q, tenant); err != nil {
			return err
		}
		bindingKey := profile.UnionID
		if bindingKey == "" {
			bindingKey = profile.OpenID
		}
		if err := s.users.LockIdentity(ctx, q, "feishu:"+bindingKey); err != nil {
			return err
		}
		user, err := s.users.GetByIDForUpdate(ctx, q, userID)
		if err != nil {
			return err
		}
		if user.Status != domain.UserStatusActive || user.AuthVersion != version {
			return ErrForbidden
		}
		_, err = s.users.BindFeishu(ctx, q, userID, profile.OpenID, profile.UnionID)
		if errors.Is(err, repository.ErrNotFound) || errors.Is(err, repository.ErrConflict) {
			return fmt.Errorf("Feishu account is already bound: %w", ErrStateConflict)
		}
		if err != nil {
			return err
		}
		return s.appendAudit(ctx, q, domain.AuditEvent{EventType: "user.feishu_bound", ActorType: "user", ActorID: stringPtr(userID), SubjectUserID: stringPtr(userID)})
	})
}

func (s *AccessService) expectedFeishuTenant(ctx context.Context) (string, error) {
	if snapshot := settings.FromContext(ctx); snapshot != nil {
		return snapshot.Feishu.TenantKey, nil
	}
	if s.systemSettings != nil {
		snapshot, err := s.systemSettings.Current(ctx)
		if err != nil {
			return "", err
		}
		return snapshot.Feishu.TenantKey, nil
	}
	return s.feishuTenantKey, nil
}

func (s *AccessService) validateFeishuSettings(ctx context.Context, q repository.DBTX, tenant string) error {
	if s.systemSettings == nil {
		return nil
	}
	if err := s.systemSettings.repo.Lock(ctx, q); err != nil {
		return err
	}
	row, err := s.systemSettings.read(ctx, q)
	if err != nil {
		return err
	}
	if snapshot := settings.FromContext(ctx); snapshot != nil {
		if row.Revision != snapshot.Revision {
			return ErrStateConflict
		}
		return nil
	}
	config, _, err := s.systemSettings.decode(ctx, row)
	if err != nil {
		return err
	}
	if tenant == "" || config.Feishu.TenantKey != tenant {
		return ErrForbidden
	}
	return nil
}

func (s *AccessService) UnbindFeishuUser(ctx context.Context, userID string, enabledIssuers map[string]string) error {
	return InTx(ctx, s.db, func(q repository.DBTX) error {
		if err := (repository.IAMRepository{}).Lock(ctx, q, false); err != nil {
			return err
		}
		before, err := s.explicitAdmins(ctx, q)
		if err != nil {
			return err
		}
		user, err := s.users.GetByIDForUpdate(ctx, q, userID)
		if err != nil {
			return err
		}
		if user.Status != domain.UserStatusActive {
			return ErrForbidden
		}
		local, err := s.users.LocalCredentialByUser(ctx, q, userID)
		if err != nil && !errors.Is(err, repository.ErrNotFound) {
			return err
		}
		hasAlternative := local.UserID != "" && enabledIssuers["local"] != ""
		for provider, issuer := range enabledIssuers {
			if provider == "local" || issuer == "" || hasAlternative {
				continue
			}
			hasAlternative, err = s.users.HasIdentityIssuer(ctx, q, userID, provider, issuer)
			if err != nil {
				return err
			}
		}
		if !hasAlternative {
			return fmt.Errorf("another enabled login method is required: %w", ErrStateConflict)
		}
		if err := s.users.UnbindFeishu(ctx, q, userID); err != nil {
			return err
		}
		after, err := s.explicitAdmins(ctx, q)
		if err != nil {
			return err
		}
		if before > 0 && after == 0 {
			return requestValidation("解绑前请为至少一个启用账户直接授予管理员角色")
		}
		return s.appendAudit(ctx, q, domain.AuditEvent{EventType: "user.feishu_unbound", ActorType: "user", ActorID: stringPtr(userID), SubjectUserID: stringPtr(userID)})
	})
}

func ValidAccountName(name string) bool { return strings.TrimSpace(name) != "" && len(name) <= 128 }
