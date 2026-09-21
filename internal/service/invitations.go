package service

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/mailer"
	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/security"
	"github.com/srex-run/access-gateway/internal/settings"
)

var ErrInvitationUnavailable = errors.New("邀请链接无效或已失效")

type CreateInvitationInput struct {
	Username string `json:"username"`
	Nickname string `json:"nickname"`
	Email    string `json:"email"`
}

type CreatedInvitation struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Username  string    `json:"username"`
	ExpiresAt time.Time `json:"expires_at"`
	Sent      bool      `json:"sent"`
	Delivery  string    `json:"delivery"`
	AcceptURL string    `json:"accept_url,omitempty"`
}

type InvitationPreview struct {
	Username    string    `json:"username"`
	Nickname    string    `json:"nickname"`
	InviterName string    `json:"inviter_name"`
	ExpiresAt   time.Time `json:"expires_at"`
}

func (s *AccessService) identityRuntime(ctx context.Context) (*settings.Snapshot, error) {
	if snapshot := settings.FromContext(ctx); snapshot != nil {
		return snapshot, nil
	}
	if s.systemSettings != nil {
		return s.systemSettings.Current(ctx)
	}
	defaults := settings.Defaults()
	return &settings.Snapshot{BaseURL: s.publicURL, Auth: defaults.Authentication(settings.Secrets{}), MFA: defaults.MFA, InvitationTTLHours: defaults.InvitationTTLHours}, nil
}

func validateInvitationInput(input CreateInvitationInput) (CreateInvitationInput, error) {
	username, err := security.NormalizeUsername(input.Username)
	if err != nil {
		return input, requestValidation("用户名需为 3–64 位字母、数字、点、下划线或连字符")
	}
	input.Username, input.Nickname, input.Email = username, strings.TrimSpace(input.Nickname), strings.TrimSpace(input.Email)
	if input.Nickname == "" {
		input.Nickname = username
	}
	if !ValidAccountName(input.Nickname) {
		return input, requestValidation("请填写有效昵称，最多 128 字节")
	}
	address, err := mail.ParseAddress(input.Email)
	if err != nil || address.Address != input.Email || len(input.Email) > 254 || strings.ContainsAny(input.Email, "*\r\n") {
		return input, requestValidation("请填写有效邮箱地址")
	}
	return input, nil
}

func (s *AccessService) CreateInvitation(ctx context.Context, actor string, input CreateInvitationInput) (CreatedInvitation, error) {
	if err := s.Authorize(ctx, actor, authz.PermissionUserManage); err != nil {
		return CreatedInvitation{}, err
	}
	input, err := validateInvitationInput(input)
	if err != nil {
		return CreatedInvitation{}, err
	}
	runtime, err := s.invitationRuntime(ctx)
	if err != nil {
		return CreatedInvitation{}, err
	}
	token, err := security.NewToken()
	if err != nil {
		return CreatedInvitation{}, err
	}
	repo := repository.IdentitySecurityRepository{}
	var invitation repository.Invitation
	err = s.mutateIAM(ctx, actor, authz.PermissionUserManage, func(q repository.DBTX) error {
		user, err := s.users.Create(ctx, q, domain.User{ID: id.New(), Username: input.Username, Nickname: input.Nickname, Email: &input.Email, Status: domain.UserStatusInactive})
		if err != nil {
			return err
		}
		// Reserve the username. An empty hash is never a valid password, and the account remains inactive until acceptance.
		if err := s.users.CreateLocalCredential(ctx, q, repository.LocalCredential{UserID: user.ID, Username: input.Username}); err != nil {
			return err
		}
		invitation, err = repo.CreateInvitation(ctx, q, repository.Invitation{ID: id.New(), UserID: user.ID, InvitedBy: actor}, security.HashOpaqueToken(token), runtime.InvitationTTLHours)
		if err != nil {
			return err
		}
		return s.identityAdminAudit(ctx, q, "user.invitation_created", actor, user.ID)
	})
	if err != nil {
		return CreatedInvitation{}, err
	}
	return s.deliverInvitation(ctx, runtime, invitation, input.Username, input.Email, token)
}

func (s *AccessService) invitationRuntime(ctx context.Context) (*settings.Snapshot, error) {
	runtime, err := s.identityRuntime(ctx)
	if err != nil {
		return nil, err
	}
	if runtime.BaseURL == "" {
		return nil, requestValidation("请先配置 PUBLIC_URL")
	}
	return runtime, nil
}

func (s *AccessService) deliverInvitation(ctx context.Context, runtime *settings.Snapshot, invitation repository.Invitation, username, email, token string) (CreatedInvitation, error) {
	result := CreatedInvitation{ID: invitation.ID, UserID: invitation.UserID, Username: username, ExpiresAt: invitation.ExpiresAt,
		AcceptURL: runtime.BaseURL + "/invite#" + token, Delivery: "not_configured"}
	if runtime.Mailer == nil || !runtime.Mailer.Ready() {
		return result, nil
	}
	// Leave time to persist delivery status and return the fallback link within the console proxy's 15s timeout.
	deliveryCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	err := runtime.Mailer.Send(deliveryCtx, email, mailer.Message{Subject: "Access Gateway 账户邀请", Body: fmt.Sprintf("你受邀加入 Access Gateway。\n用户名：%s\n请打开以下链接设置密码并激活账户：\n%s\n链接有效至：%s\n如果你不认识邀请人，请忽略此邮件。", username, result.AcceptURL, invitation.ExpiresAt.UTC().Format(time.RFC3339))})
	result.Sent = err == nil
	result.Delivery = "failed"
	if result.Sent {
		result.AcceptURL, result.Delivery = "", "sent"
	}
	// Transport errors may contain SMTP credentials or recipient details; neither logs nor responses expose them.
	statusCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer stop()
	if err := (repository.IdentitySecurityRepository{}).MarkInvitationDelivery(statusCtx, s.db, invitation.ID, result.Sent); err != nil {
		return CreatedInvitation{}, err
	}
	return result, nil
}

func (s *AccessService) ListInvitations(ctx context.Context, actor string, limit, offset int) ([]repository.InvitationView, error) {
	if err := s.Authorize(ctx, actor, authz.PermissionUserRead); err != nil {
		return nil, err
	}
	if limit < 1 || limit > 100 || offset < 0 {
		return nil, ErrValidation
	}
	return (repository.IdentitySecurityRepository{}).ListInvitations(ctx, s.db, limit, offset)
}

func (s *AccessService) ResendInvitation(ctx context.Context, actor, invitationID string) (CreatedInvitation, error) {
	if err := s.Authorize(ctx, actor, authz.PermissionUserManage); err != nil {
		return CreatedInvitation{}, err
	}
	if validateUUID(invitationID, "invitation ID") != nil {
		return CreatedInvitation{}, ErrValidation
	}
	runtime, err := s.invitationRuntime(ctx)
	if err != nil {
		return CreatedInvitation{}, err
	}
	token, err := security.NewToken()
	if err != nil {
		return CreatedInvitation{}, err
	}
	repo := repository.IdentitySecurityRepository{}
	var invitation repository.Invitation
	var user domain.User
	var account repository.LocalCredential
	err = s.mutateIAM(ctx, actor, authz.PermissionUserManage, func(q repository.DBTX) error {
		previous, err := repo.GetInvitation(ctx, q, invitationID)
		if err != nil {
			return err
		}
		user, err = s.users.GetByIDForUpdate(ctx, q, previous.UserID)
		if err != nil {
			return err
		}
		account, err = s.users.LocalCredentialByUser(ctx, q, user.ID)
		if err != nil {
			return err
		}
		if previous.AcceptedAt != nil || user.Status != domain.UserStatusInactive || account.PasswordHash != "" || user.Email == nil {
			return ErrStateConflict
		}
		if _, err := repo.RevokeUserInvitations(ctx, q, user.ID); err != nil {
			return err
		}
		invitation, err = repo.CreateInvitation(ctx, q, repository.Invitation{ID: id.New(), UserID: user.ID, InvitedBy: actor}, security.HashOpaqueToken(token), runtime.InvitationTTLHours)
		if err != nil {
			return err
		}
		return s.identityAdminAudit(ctx, q, "user.invitation_resent", actor, user.ID)
	})
	if err != nil {
		return CreatedInvitation{}, err
	}
	return s.deliverInvitation(ctx, runtime, invitation, account.Username, *user.Email, token)
}

func (s *AccessService) RevokeInvitation(ctx context.Context, actor, invitationID string) error {
	if validateUUID(invitationID, "invitation ID") != nil {
		return ErrValidation
	}
	return s.mutateIAM(ctx, actor, authz.PermissionUserManage, func(q repository.DBTX) error {
		repo := repository.IdentitySecurityRepository{}
		invitation, err := repo.GetInvitation(ctx, q, invitationID)
		if err != nil {
			return err
		}
		if _, err := s.users.GetByIDForUpdate(ctx, q, invitation.UserID); err != nil {
			return err
		}
		if err := repo.RevokeInvitation(ctx, q, invitationID); err != nil {
			return err
		}
		return s.identityAdminAudit(ctx, q, "user.invitation_revoked", actor, invitation.UserID)
	})
}

func invitationTokenValid(token string) bool {
	return len(token) == 43 && strings.IndexFunc(token, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_')
	}) < 0
}

func invitationError(err error) error {
	if errors.Is(err, repository.ErrNotFound) {
		return ErrInvitationUnavailable
	}
	return err
}

func (s *AccessService) PreviewInvitation(ctx context.Context, token string) (InvitationPreview, error) {
	if !invitationTokenValid(token) {
		return InvitationPreview{}, ErrInvitationUnavailable
	}
	if _, err := s.invitationRuntime(ctx); err != nil {
		return InvitationPreview{}, err
	}
	invitation, err := (repository.IdentitySecurityRepository{}).LiveInvitation(ctx, s.db, security.HashOpaqueToken(token))
	if err != nil {
		return InvitationPreview{}, invitationError(err)
	}
	user, err := s.users.GetByID(ctx, s.db, invitation.UserID)
	if err != nil {
		return InvitationPreview{}, invitationError(err)
	}
	account, err := s.users.LocalCredentialByUser(ctx, s.db, user.ID)
	if err != nil {
		return InvitationPreview{}, invitationError(err)
	}
	if user.Status != domain.UserStatusInactive || account.PasswordHash != "" {
		return InvitationPreview{}, ErrInvitationUnavailable
	}
	inviter, err := s.users.GetByID(ctx, s.db, invitation.InvitedBy)
	if err != nil {
		return InvitationPreview{}, err
	}
	return InvitationPreview{Username: account.Username, Nickname: user.Nickname, InviterName: inviter.Nickname, ExpiresAt: invitation.ExpiresAt}, nil
}

func (s *AccessService) AcceptInvitation(ctx context.Context, token, password string) (domain.User, error) {
	if !invitationTokenValid(token) {
		return domain.User{}, ErrInvitationUnavailable
	}
	if _, err := s.invitationRuntime(ctx); err != nil {
		return domain.User{}, err
	}
	hash, err := security.HashPassword(password)
	if err != nil {
		return domain.User{}, requestValidation("密码需为 12–72 字节")
	}
	var user domain.User
	repo := repository.IdentitySecurityRepository{}
	err = InTx(ctx, s.db, func(q repository.DBTX) error {
		if err := (repository.IAMRepository{}).Lock(ctx, q, false); err != nil {
			return err
		}
		invitation, err := repo.LiveInvitation(ctx, q, security.HashOpaqueToken(token))
		if err != nil {
			return err
		}
		user, err = s.users.GetByIDForUpdate(ctx, q, invitation.UserID)
		if err != nil {
			return err
		}
		account, err := s.users.LocalCredentialByUser(ctx, q, user.ID)
		if err != nil {
			return err
		}
		if user.Status != domain.UserStatusInactive || account.PasswordHash != "" {
			return ErrInvitationUnavailable
		}
		if _, err := repo.ConsumeInvitation(ctx, q, security.HashOpaqueToken(token)); err != nil {
			return err
		}
		if err := s.users.UpdateLocalPassword(ctx, q, user.ID, hash); err != nil {
			return err
		}
		user, err = repo.ActivateInvitedUser(ctx, q, user.ID)
		if err != nil {
			return err
		}
		return s.identityAudit(ctx, q, "user.invitation_accepted", user.ID, user.ID)
	})
	return user, invitationError(err)
}

func (s *AccessService) identityAudit(ctx context.Context, q repository.DBTX, event, actor, target string) error {
	return s.appendAudit(ctx, q, domain.AuditEvent{EventType: event, ActorType: "user", ActorID: &actor, SubjectUserID: &target, Result: stringPtr("success")})
}

func (s *AccessService) identityAdminAudit(ctx context.Context, q repository.DBTX, event, actor, target string) error {
	return s.appendAudit(ctx, q, domain.AuditEvent{EventType: event, ActorType: "admin", ActorID: &actor, SubjectUserID: &target, Result: stringPtr("success")})
}
