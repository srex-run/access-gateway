//go:build integration

package integration_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"database/sql"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/gateway"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/mailer"
	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/secretstore"
	"github.com/srex-run/access-gateway/internal/security"
	"github.com/srex-run/access-gateway/internal/service"
	"github.com/srex-run/access-gateway/internal/settings"
)

func identityFixture(t *testing.T) (*sql.DB, *service.AccessService, domain.User, context.Context, *settings.Snapshot) {
	t.Helper()
	database := openDatabase(t)
	repos := newRepositories()
	cipher, err := secretstore.NewAESGCM("identity-test", []byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	svc, err := service.NewAccessService(service.ServiceOptions{DB: database, Users: repos.users, Regions: repos.regions, Gateways: repos.gateways, Assets: repos.assets, Requests: repos.requests, Approvals: repos.approvals, Sessions: repos.sessions, SessionEvents: repos.sessionEvents, Audits: repos.audits, Outbox: repos.outbox, Gateway: gateway.UnavailableClient{}, Logger: zerolog.Nop(), IdentityCipher: cipher, AdminUserIDs: map[string]struct{}{"admin-open-id": {}}})
	if err != nil {
		t.Fatal(err)
	}
	admin, err := repos.users.Create(context.Background(), database, domain.User{ID: id.New(), FeishuOpenID: "admin-open-id", Nickname: "Admin", Status: domain.UserStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	config := settings.Defaults()
	config.BaseURL, config.MFA.Mode = "https://access.example.com", "optional"
	runtime, err := settings.Build(config, settings.Secrets{}, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := settings.WithSnapshot(context.Background(), runtime)
	return database, svc, admin, ctx, runtime
}

func TestIdentityInvitationLifecycleAndAtomicAcceptance(t *testing.T) {
	database, svc, admin, ctx, _ := identityFixture(t)
	created, err := svc.CreateInvitation(ctx, admin.ID, service.CreateInvitationInput{Username: "invitee", Nickname: "Invitee", Email: "invitee@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Split(created.AcceptURL, "#")[1]
	preview, err := svc.PreviewInvitation(ctx, token)
	if err != nil || preview.Username != "invitee" || preview.Nickname != "Invitee" || preview.InviterName != admin.Nickname || !preview.ExpiresAt.Equal(created.ExpiresAt) {
		t.Fatalf("preview: %+v %v", preview, err)
	}
	if _, err := svc.AuthenticateLocal(ctx, "invitee", "pending-password"); !errors.Is(err, service.ErrInvalidCredentials) {
		t.Fatal("pending user could log in")
	}
	if _, err := svc.CreateInvitation(ctx, admin.ID, service.CreateInvitationInput{Username: "invitee", Nickname: "Duplicate", Email: "other@example.com"}); !errors.Is(err, repository.ErrConflict) {
		t.Fatal("username not reserved")
	}
	var accepted atomic.Int32
	var wait sync.WaitGroup
	for range 4 {
		wait.Go(func() {
			_, err := svc.AcceptInvitation(ctx, token, "invitation-password")
			if err == nil {
				accepted.Add(1)
			} else if !errors.Is(err, service.ErrInvitationUnavailable) {
				t.Errorf("acceptance: %v", err)
			}
		})
	}
	wait.Wait()
	if accepted.Load() != 1 {
		t.Fatalf("acceptances = %d", accepted.Load())
	}
	user, err := svc.AuthenticateLocal(ctx, "invitee", "invitation-password")
	if err != nil || user.ID != created.UserID || user.Status != domain.UserStatusActive {
		t.Fatalf("activated account: %+v %v", user, err)
	}
	if _, err := svc.PreviewInvitation(ctx, token); !errors.Is(err, service.ErrInvitationUnavailable) {
		t.Fatal("consumed invitation still available")
	}
	repo := repository.IdentitySecurityRepository{}
	record, err := repo.GetInvitation(ctx, database, created.ID)
	if err != nil || record.ID != created.ID || record.UserID != created.UserID || record.InvitedBy != admin.ID || !record.ExpiresAt.Equal(created.ExpiresAt) || record.AcceptedAt == nil || record.RevokedAt != nil || record.SentAt != nil || record.CreatedAt.IsZero() {
		t.Fatalf("invitation scan: %+v %v", record, err)
	}
	values, err := svc.ListInvitations(ctx, admin.ID, 10, 0)
	if err != nil || len(values) != 1 || values[0].Status != "accepted" || values[0].Username != "invitee" || values[0].Nickname != "Invitee" || values[0].InviterName != admin.Nickname {
		t.Fatalf("invitation view scan: %+v %v", values, err)
	}
	if _, err := svc.ResendInvitation(ctx, admin.ID, created.ID); !errors.Is(err, service.ErrStateConflict) {
		t.Fatal("accepted invite resent")
	}
	other, err := svc.CreateInvitation(ctx, admin.ID, service.CreateInvitationInput{Username: "resend-user", Nickname: "Resend", Email: "resend@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := svc.ResendInvitation(ctx, admin.ID, other.ID)
	if err != nil || renewed.ID == other.ID {
		t.Fatalf("resend: %+v %v", renewed, err)
	}
	if _, err := svc.PreviewInvitation(ctx, strings.Split(other.AcceptURL, "#")[1]); !errors.Is(err, service.ErrInvitationUnavailable) {
		t.Fatal("old invite survived resend")
	}
	if err := svc.RevokeInvitation(ctx, admin.ID, renewed.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AcceptInvitation(ctx, strings.Split(renewed.AcceptURL, "#")[1], "invitation-password"); !errors.Is(err, service.ErrInvitationUnavailable) {
		t.Fatal("revoked invite accepted")
	}
}

func totpAt(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(at.Unix()/30))
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 15
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[offset:offset+4])&0x7fffffff)%1000000)
}

func TestIdentityMFAEnrollmentReplayRecoveryAndReset(t *testing.T) {
	database, svc, admin, ctx, runtime := identityFixture(t)
	local, err := svc.CreateLocalUser(ctx, admin.ID, service.CreateLocalUserInput{Username: "mfa-user", Nickname: "MFA User", Password: "mfa-user-password"})
	if err != nil {
		t.Fatal(err)
	}
	user, err := svc.AuthenticateLocal(ctx, "mfa-user", "mfa-user-password")
	if err != nil {
		t.Fatal(err)
	}
	pending, err := svc.BeginMFA(ctx, user, true)
	if err != nil || pending.Stage != "mfa-enroll" {
		t.Fatalf("enrollment challenge: %+v %v", pending, err)
	}
	// Simultaneous requests and retries must keep the QR code usable.
	enrollCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var enrollments [4]service.MFAEnrollment
	var enrollmentErrors [4]error
	var starts sync.WaitGroup
	for i := range enrollments {
		starts.Go(func() { enrollments[i], enrollmentErrors[i] = svc.StartMFAEnrollment(enrollCtx, pending.Token) })
	}
	starts.Wait()
	enrollment := enrollments[0]
	for i, value := range enrollments {
		if enrollmentErrors[i] != nil || value.Secret == "" || value != enrollment {
			t.Fatalf("concurrent enrollment %d returned inconsistent material: %v", i, enrollmentErrors[i])
		}
	}
	repo := repository.IdentitySecurityRepository{}
	challenge, err := repo.MFAChallenge(ctx, database, security.HashOpaqueToken(pending.Token))
	if err != nil || challenge.UserID != local.ID || challenge.AuthVersion != user.AuthVersion || challenge.Kind != "enroll" || challenge.Attempts != 0 || !challenge.ExpiresAt.Equal(pending.ExpiresAt) || challenge.Now.IsZero() || len(challenge.SecretCiphertext) == 0 || strings.Contains(string(challenge.SecretCiphertext), enrollment.Secret) {
		t.Fatalf("challenge scan: %+v %v", challenge, err)
	}
	code := totpAt(t, enrollment.Secret, challenge.Now)
	bound, err := svc.CompleteMFA(ctx, pending.Token, code, "enroll")
	if err != nil || len(bound.Codes) != 10 {
		t.Fatalf("bind: %v", err)
	}
	binding, err := repo.MFA(ctx, database, user.ID)
	if err != nil || binding.UserID != user.ID || binding.LastStep != challenge.Now.Unix()/30 || binding.CreatedAt.IsZero() || string(binding.SecretCiphertext) != string(challenge.SecretCiphertext) {
		t.Fatalf("binding scan: %+v %v", binding, err)
	}
	if err := svc.ValidateBrowserSession(ctx, user.ID, user.AuthVersion); !errors.Is(err, service.ErrInvalidCredentials) {
		t.Fatal("old session survived enrollment")
	}
	if err := svc.ValidateMFASession(ctx, user.ID, false); !errors.Is(err, service.ErrInvalidCredentials) {
		t.Fatal("unverified full session accepted")
	}
	if err := svc.ValidateMFASession(ctx, user.ID, true); err != nil {
		t.Fatal(err)
	}
	runtime.MFA.Mode = "off"
	verify, err := svc.BeginMFA(ctx, bound.User, false)
	if err != nil || verify.Stage != "mfa-verify" {
		t.Fatal("disabling policy bypassed bound MFA")
	}
	if _, err := svc.CompleteMFA(ctx, verify.Token, code, "verify"); !errors.Is(err, service.ErrMFAFailed) {
		t.Fatal("TOTP replay accepted")
	}
	second, err := svc.BeginMFA(ctx, bound.User, false)
	if err != nil {
		t.Fatal(err)
	}
	var successes atomic.Int32
	var wait sync.WaitGroup
	for _, token := range []string{verify.Token, second.Token} {
		wait.Go(func() {
			if _, err := svc.CompleteMFA(ctx, token, bound.Codes[0], "verify"); err == nil {
				successes.Add(1)
			} else if !errors.Is(err, service.ErrMFAFailed) {
				t.Errorf("recovery: %v", err)
			}
		})
	}
	wait.Wait()
	if successes.Load() != 1 {
		t.Fatalf("recovery accepted %d times", successes.Load())
	}
	regenerated, err := svc.UpdateOwnMFA(ctx, user.ID, bound.User.AuthVersion, bound.Codes[1], false)
	if err != nil || len(regenerated.Codes) != 10 {
		t.Fatalf("regenerate: %v", err)
	}
	newPending, err := svc.BeginMFA(ctx, regenerated.User, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CompleteMFA(ctx, newPending.Token, bound.Codes[2], "verify"); !errors.Is(err, service.ErrMFAFailed) {
		t.Fatal("old recovery code survived regeneration")
	}
	runtime.MFA.Mode = "all"
	if _, err := svc.UpdateOwnMFA(ctx, user.ID, regenerated.User.AuthVersion, regenerated.Codes[0], true); !errors.Is(err, service.ErrValidation) {
		t.Fatal("forced MFA could be unbound")
	}
	if err := svc.ResetUserMFA(ctx, user.ID, admin.ID); !errors.Is(err, service.ErrForbidden) {
		t.Fatal("ordinary user reset admin MFA")
	}
	if err := svc.ResetUserMFA(ctx, admin.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CompleteMFA(ctx, newPending.Token, regenerated.Codes[0], "verify"); !errors.Is(err, service.ErrMFAFailed) {
		t.Fatal("pending challenge survived reset")
	}
	status, err := svc.GetMFAStatus(ctx, user.ID)
	if err != nil || status.Bound || status.RecoveryCodesLeft != 0 {
		t.Fatalf("MFA reset: %+v %v", status, err)
	}
}

type invitationMailStub struct {
	ready bool
	fail  bool
	calls int
	last  mailer.Message
}

func (m *invitationMailStub) Ready() bool { return m.ready }
func (m *invitationMailStub) Send(context.Context, string, mailer.Message) error {
	m.calls++
	if m.fail {
		return errors.New("smtp unavailable")
	}
	return nil
}

func TestIdentityInvitationMailAndExpiryAndMFALimits(t *testing.T) {
	database, svc, admin, ctx, runtime := identityFixture(t)
	mail := &invitationMailStub{ready: true}
	runtime.Mailer = mail
	created, err := svc.CreateInvitation(ctx, admin.ID, service.CreateInvitationInput{Username: "mailed", Nickname: "Mailed", Email: "mail@example.com"})
	if err != nil || !created.Sent || created.AcceptURL != "" || mail.calls != 1 {
		t.Fatalf("sent invite: %+v %v", created, err)
	}
	repo := repository.IdentitySecurityRepository{}
	row, err := repo.GetInvitation(ctx, database, created.ID)
	if err != nil || row.SentAt == nil {
		t.Fatal("delivery timestamp missing")
	}
	mail.fail = true
	failed, err := svc.ResendInvitation(ctx, admin.ID, created.ID)
	if err != nil || failed.Sent || failed.AcceptURL == "" || failed.Delivery != "failed" {
		t.Fatalf("delivery fallback: %+v %v", failed, err)
	}
	if _, err := database.ExecContext(ctx, `UPDATE user_invitations SET expires_at = NOW() - INTERVAL '1 second' WHERE id = $1`, failed.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AcceptInvitation(ctx, strings.Split(failed.AcceptURL, "#")[1], "invitation-password"); !errors.Is(err, service.ErrInvitationUnavailable) {
		t.Fatal("expired invite accepted")
	}
	user, err := repository.NewUserRepository().GetByID(ctx, database, admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := svc.BeginMFA(ctx, user, true)
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := svc.StartMFAEnrollment(ctx, pending.Token)
	if err != nil {
		t.Fatal(err)
	}
	for range 5 {
		if _, err := svc.CompleteMFA(ctx, pending.Token, "invalid", "enroll"); !errors.Is(err, service.ErrMFAFailed) {
			t.Fatal("invalid code accepted")
		}
	}
	now, _ := repo.Now(ctx, database)
	if _, err := svc.CompleteMFA(ctx, pending.Token, totpAt(t, enrollment.Secret, now), "enroll"); !errors.Is(err, service.ErrMFAFailed) {
		t.Fatal("exhausted challenge accepted")
	}
	if _, err := svc.StartMFAEnrollment(ctx, pending.Token); !errors.Is(err, service.ErrMFAFailed) {
		t.Fatal("exhausted challenge exposed enrollment material")
	}
	next, err := svc.BeginMFA(ctx, user, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `UPDATE mfa_challenges SET expires_at = NOW() - INTERVAL '1 second' WHERE token_hash = $1`, security.HashOpaqueToken(next.Token)); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.GetMFAChallenge(ctx, next.Token); !errors.Is(err, service.ErrMFAFailed) {
		t.Fatal("expired MFA challenge accepted")
	}
}
