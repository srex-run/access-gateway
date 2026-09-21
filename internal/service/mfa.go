package service

import (
	"context"
	"errors"
	"time"

	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/security"
	"github.com/srex-run/access-gateway/internal/settings"
)

var ErrMFAFailed = errors.New("验证码错误或验证已失效")

type PendingMFA struct {
	Stage     string    `json:"stage"`
	ExpiresAt time.Time `json:"expires_at"`
	Token     string    `json:"-"`
}

type MFAEnrollment struct {
	Secret string `json:"secret"`
	URI    string `json:"uri"`
}

type MFAStatus struct {
	Bound             bool `json:"bound"`
	RecoveryCodesLeft int  `json:"recovery_codes_left"`
	CanEnroll         bool `json:"can_enroll"`
	CanUnbind         bool `json:"can_unbind"`
}

type MFAResult struct {
	User  domain.User `json:"-"`
	Codes []string    `json:"codes,omitempty"`
}

func (s *AccessService) mfaPolicy(ctx context.Context, userID string) (settings.MFAConfig, bool, error) {
	runtime, err := s.identityRuntime(ctx)
	if err != nil {
		return settings.MFAConfig{}, false, err
	}
	admin := false
	if runtime.MFA.Mode == "admin" {
		err = s.Authorize(ctx, userID, authz.PermissionRoleManage)
		if err != nil && !errors.Is(err, ErrForbidden) {
			return settings.MFAConfig{}, false, err
		}
		admin = err == nil
	}
	return runtime.MFA, admin, nil
}

func (s *AccessService) BeginMFA(ctx context.Context, authenticated domain.User, selfEnroll bool) (*PendingMFA, error) {
	policy, admin, err := s.mfaPolicy(ctx, authenticated.ID)
	if err != nil {
		return nil, err
	}
	repo := repository.IdentitySecurityRepository{}
	var pending *PendingMFA
	err = InTx(ctx, s.db, func(q repository.DBTX) error {
		user, err := s.users.GetByIDForUpdate(ctx, q, authenticated.ID)
		if err != nil {
			return err
		}
		if user.Status != domain.UserStatusActive || user.AuthVersion != authenticated.AuthVersion {
			return ErrInvalidCredentials
		}
		_, err = repo.MFA(ctx, q, user.ID)
		bound := err == nil
		if err != nil && !errors.Is(err, repository.ErrNotFound) {
			return err
		}
		if selfEnroll && (policy.Mode == "off" || bound) {
			return ErrStateConflict
		}
		if !selfEnroll && !policy.Required(bound, admin) {
			return nil
		}
		if s.identityCipher == nil {
			return ErrNotConfigured
		}
		kind := "enroll"
		if bound {
			kind = "verify"
		}
		token, err := security.NewToken()
		if err != nil {
			return err
		}
		challenge, err := repo.CreateMFAChallenge(ctx, q, security.HashOpaqueToken(token), user.ID, user.AuthVersion, kind)
		if err != nil {
			return err
		}
		pending = &PendingMFA{Stage: "mfa-" + kind, ExpiresAt: challenge.ExpiresAt, Token: token}
		return nil
	})
	return pending, err
}

func mfaError(err error) error {
	if errors.Is(err, repository.ErrNotFound) || errors.Is(err, repository.ErrConflict) {
		return ErrMFAFailed
	}
	return err
}

func (s *AccessService) GetMFAChallenge(ctx context.Context, token string) (PendingMFA, error) {
	if !invitationTokenValid(token) {
		return PendingMFA{}, ErrMFAFailed
	}
	value, err := (repository.IdentitySecurityRepository{}).MFAChallenge(ctx, s.db, security.HashOpaqueToken(token))
	if err != nil {
		return PendingMFA{}, mfaError(err)
	}
	if err := s.ValidateBrowserSession(ctx, value.UserID, value.AuthVersion); err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			return PendingMFA{}, ErrMFAFailed
		}
		return PendingMFA{}, err
	}
	return PendingMFA{Stage: "mfa-" + value.Kind, ExpiresAt: value.ExpiresAt}, nil
}

func mfaAAD(userID string) []byte { return []byte("access-gateway/user-mfa/v1/" + userID) }

func (s *AccessService) StartMFAEnrollment(ctx context.Context, token string) (MFAEnrollment, error) {
	if s.identityCipher == nil {
		return MFAEnrollment{}, ErrNotConfigured
	}
	if !invitationTokenValid(token) {
		return MFAEnrollment{}, ErrMFAFailed
	}
	repo := repository.IdentitySecurityRepository{}
	hash := security.HashOpaqueToken(token)
	// Resolve the policy before opening the transaction. Some deployments use a
	// single database connection; calling a second query through s.db while a
	// transaction is holding that connection would otherwise deadlock.
	challenge, err := repo.MFAChallenge(ctx, s.db, hash)
	if err != nil {
		return MFAEnrollment{}, mfaError(err)
	}
	policy, _, err := s.mfaPolicy(ctx, challenge.UserID)
	if err != nil {
		return MFAEnrollment{}, err
	}
	var enrollment MFAEnrollment
	err = InTx(ctx, s.db, func(q repository.DBTX) error {
		// Keep the lock order (user, then challenge) consistent with CompleteMFA
		// so an enrollment request cannot deadlock a verification request.
		user, err := s.users.GetByIDForUpdate(ctx, q, challenge.UserID)
		if err != nil {
			return err
		}
		// Lock the challenge before reading or writing its secret. Without this,
		// two concurrent enrollment requests can each return a different QR code
		// while the last writer silently wins in the database.
		lockedChallenge, err := repo.LockMFAChallenge(ctx, q, hash)
		if err != nil {
			return err
		}
		if policy.Mode == "off" || lockedChallenge.Kind != "enroll" || lockedChallenge.Attempts >= 5 {
			return ErrMFAFailed
		}
		if lockedChallenge.UserID != user.ID || user.Status != domain.UserStatusActive || user.AuthVersion != lockedChallenge.AuthVersion {
			return ErrMFAFailed
		}
		secret := ""
		if len(lockedChallenge.SecretCiphertext) > 0 {
			plaintext, err := s.identityCipher.Decrypt(ctx, string(lockedChallenge.SecretCiphertext), mfaAAD(user.ID))
			if err != nil {
				return err
			}
			secret = string(plaintext)
			clear(plaintext)
		} else {
			secret, err = security.NewTOTPSecret()
			if err != nil {
				return err
			}
			ciphertext, err := s.identityCipher.Encrypt(ctx, []byte(secret), mfaAAD(user.ID))
			if err != nil {
				return err
			}
			if err := repo.SetMFAEnrollment(ctx, q, hash, []byte(ciphertext)); err != nil {
				return err
			}
		}
		enrollment = MFAEnrollment{Secret: secret, URI: security.TOTPURI(policy.Issuer, user.Username, secret)}
		return nil
	})
	if err != nil {
		return MFAEnrollment{}, mfaError(err)
	}
	return enrollment, nil
}

func (s *AccessService) CompleteMFA(ctx context.Context, token, code, kind string) (MFAResult, error) {
	if s.identityCipher == nil {
		return MFAResult{}, ErrNotConfigured
	}
	if !invitationTokenValid(token) || len(code) > 64 || code == "" || (kind != "enroll" && kind != "verify") {
		return MFAResult{}, ErrMFAFailed
	}
	repo := repository.IdentitySecurityRepository{}
	hash := security.HashOpaqueToken(token)
	// Persist attempts outside the verification transaction so failures cannot roll the counter back.
	attempt, err := repo.AttemptMFAChallenge(ctx, s.db, hash)
	if err != nil {
		return MFAResult{}, mfaError(err)
	}
	policy, _, err := s.mfaPolicy(ctx, attempt.UserID)
	if err != nil {
		return MFAResult{}, err
	}
	if err := s.limitMFAUser(ctx, attempt.UserID); err != nil {
		return MFAResult{}, err
	}
	var result MFAResult
	err = InTx(ctx, s.db, func(q repository.DBTX) error {
		user, err := s.users.GetByIDForUpdate(ctx, q, attempt.UserID)
		if err != nil {
			return err
		}
		challenge, err := repo.LockMFAChallenge(ctx, q, hash)
		if err != nil {
			return err
		}
		if user.Status != domain.UserStatusActive || user.AuthVersion != challenge.AuthVersion || challenge.Kind != kind {
			return ErrMFAFailed
		}
		if kind == "enroll" {
			if policy.Mode == "off" || len(challenge.SecretCiphertext) == 0 {
				return ErrMFAFailed
			}
			secret, err := s.identityCipher.Decrypt(ctx, string(challenge.SecretCiphertext), mfaAAD(user.ID))
			if err != nil {
				return err
			}
			defer clear(secret)
			step, valid := security.VerifyTOTP(string(secret), code, challenge.Now, 1)
			if !valid {
				return ErrMFAFailed
			}
			if err := repo.BindMFA(ctx, q, user.ID, challenge.SecretCiphertext, step); err != nil {
				return err
			}
			result.Codes, err = s.replaceRecoveryCodes(ctx, q, user.ID)
			if err != nil {
				return err
			}
			user, err = repo.BumpAuthVersion(ctx, q, user.ID)
			if err != nil {
				return err
			}
			if err := s.identityAudit(ctx, q, "user.mfa_bound", user.ID, user.ID); err != nil {
				return err
			}
		} else {
			if err := s.verifyMFAFactor(ctx, q, user.ID, code, challenge.Now); err != nil {
				return err
			}
		}
		if err := repo.ConsumeMFAChallenge(ctx, q, hash); err != nil {
			return err
		}
		result.User = user
		return nil
	})
	if err != nil {
		return MFAResult{}, mfaError(err)
	}
	return result, nil
}

// The caller holds the user row lock: factor consumption and session/account mutations share one transaction.
func (s *AccessService) verifyMFAFactor(ctx context.Context, q repository.DBTX, userID, code string, now time.Time) error {
	repo := repository.IdentitySecurityRepository{}
	binding, err := repo.MFA(ctx, q, userID)
	if err != nil {
		return mfaError(err)
	}
	if hash, valid := security.RecoveryCodeHash(userID, code); valid {
		if err := repo.ConsumeRecoveryCode(ctx, q, userID, hash); err != nil {
			return mfaError(err)
		}
		return s.identityAudit(ctx, q, "user.mfa_recovery_used", userID, userID)
	}
	secret, err := s.identityCipher.Decrypt(ctx, string(binding.SecretCiphertext), mfaAAD(userID))
	if err != nil {
		return err
	}
	defer clear(secret)
	step, valid := security.VerifyTOTP(string(secret), code, now, 1)
	if !valid || step <= binding.LastStep {
		return ErrMFAFailed
	}
	return mfaError(repo.AdvanceMFAStep(ctx, q, userID, step))
}

func (s *AccessService) replaceRecoveryCodes(ctx context.Context, q repository.DBTX, userID string) ([]string, error) {
	codes, hashes, err := security.NewRecoveryCodes(userID)
	if err != nil {
		return nil, err
	}
	if err := (repository.IdentitySecurityRepository{}).ReplaceRecoveryCodes(ctx, q, userID, hashes); err != nil {
		return nil, err
	}
	return codes, nil
}

func (s *AccessService) GetMFAStatus(ctx context.Context, userID string) (MFAStatus, error) {
	policy, admin, err := s.mfaPolicy(ctx, userID)
	if err != nil {
		return MFAStatus{}, err
	}
	repo := repository.IdentitySecurityRepository{}
	_, err = repo.MFA(ctx, s.db, userID)
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		return MFAStatus{}, err
	}
	bound := err == nil
	status := MFAStatus{Bound: bound, CanEnroll: !bound && policy.Mode != "off", CanUnbind: bound && !policy.Required(false, admin)}
	status.RecoveryCodesLeft, err = repo.RecoveryCodeCount(ctx, s.db, userID)
	return status, err
}

func (s *AccessService) ValidateMFASession(ctx context.Context, userID string, verified bool) error {
	policy, admin, err := s.mfaPolicy(ctx, userID)
	if err != nil {
		return err
	}
	_, err = (repository.IdentitySecurityRepository{}).MFA(ctx, s.db, userID)
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		return err
	}
	if policy.Required(err == nil, admin) && !verified {
		return ErrInvalidCredentials
	}
	return nil
}

func (s *AccessService) UpdateOwnMFA(ctx context.Context, userID string, version int64, code string, remove bool) (MFAResult, error) {
	if s.identityCipher == nil {
		return MFAResult{}, ErrNotConfigured
	}
	if code == "" || len(code) > 64 {
		return MFAResult{}, ErrMFAFailed
	}
	policy, admin, err := s.mfaPolicy(ctx, userID)
	if err != nil {
		return MFAResult{}, err
	}
	if remove && policy.Required(false, admin) {
		return MFAResult{}, requestValidation("当前策略要求启用 MFA，不能自行解绑")
	}
	if err := s.limitMFAUser(ctx, userID); err != nil {
		return MFAResult{}, err
	}
	var result MFAResult
	repo := repository.IdentitySecurityRepository{}
	err = InTx(ctx, s.db, func(q repository.DBTX) error {
		user, err := s.users.GetByIDForUpdate(ctx, q, userID)
		if err != nil {
			return err
		}
		if user.Status != domain.UserStatusActive || user.AuthVersion != version {
			return ErrInvalidCredentials
		}
		now, err := repo.Now(ctx, q)
		if err != nil {
			return err
		}
		if err := s.verifyMFAFactor(ctx, q, userID, code, now); err != nil {
			return err
		}
		event := "user.mfa_recovery_regenerated"
		if remove {
			event = "user.mfa_unbound"
			err = repo.DeleteMFA(ctx, q, userID)
		} else {
			result.Codes, err = s.replaceRecoveryCodes(ctx, q, userID)
		}
		if err != nil {
			return err
		}
		result.User, err = repo.BumpAuthVersion(ctx, q, userID)
		if err != nil {
			return err
		}
		return s.identityAudit(ctx, q, event, userID, userID)
	})
	if err != nil {
		return MFAResult{}, mfaError(err)
	}
	return result, nil
}

func (s *AccessService) ResetUserMFA(ctx context.Context, actor, target string) error {
	if actor == target {
		return requestValidation("请在账号设置中管理自己的 MFA")
	}
	if validateUUID(target, "user ID") != nil {
		return ErrValidation
	}
	return s.mutateIAM(ctx, actor, authz.PermissionRoleManage, func(q repository.DBTX) error {
		repo := repository.IdentitySecurityRepository{}
		if _, err := s.users.GetByIDForUpdate(ctx, q, target); err != nil {
			return err
		}
		if err := repo.DeleteMFA(ctx, q, target); err != nil {
			return err
		}
		if _, err := repo.BumpAuthVersion(ctx, q, target); err != nil {
			return err
		}
		return s.identityAdminAudit(ctx, q, "user.mfa_reset", actor, target)
	})
}

func (s *AccessService) limitMFAUser(ctx context.Context, userID string) error {
	allowed, err := (&repository.LoginAttemptRepository{}).Allow(ctx, s.db, security.HashOpaqueToken("mfa-user:"+userID), 10)
	if err != nil {
		return err
	}
	if !allowed {
		return ErrMFAFailed
	}
	return nil
}
