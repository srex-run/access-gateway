package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/security"
	"github.com/srex-run/access-gateway/internal/settings"
)

func TestInvitationValidationRejectsHeaderInjection(t *testing.T) {
	value := CreateInvitationInput{Username: " Alice ", Nickname: " Alice ", Email: " alice@example.com "}
	got, err := validateInvitationInput(value)
	if err != nil || got.Username != "alice" || got.Nickname != "Alice" || got.Email != "alice@example.com" {
		t.Fatalf("normalization: %+v %v", got, err)
	}
	value.Nickname = "  "
	got, err = validateInvitationInput(value)
	if err != nil || got.Nickname != "alice" {
		t.Fatalf("nickname fallback: %+v %v", got, err)
	}
	for _, email := range []string{"bad", "a***@example.com", "alice@example.com\r\nBcc: other@example.com", "Alice <alice@example.com>"} {
		value.Email = email
		if _, err := validateInvitationInput(value); !errors.Is(err, ErrValidation) {
			t.Fatalf("email accepted: %q", email)
		}
	}
	token, _ := security.NewToken()
	if !invitationTokenValid(token) {
		t.Fatal("generated token rejected")
	}
	for _, invalid := range []string{"", token + "x", strings.Repeat("!", 43), strings.Repeat("a", 42)} {
		if invitationTokenValid(invalid) {
			t.Fatal("malformed token accepted")
		}
	}
}

func TestInvitationWithoutSMTPReturnsOnlyOneTimeFragmentLink(t *testing.T) {
	s := &AccessService{}
	runtime := &settings.Snapshot{BaseURL: "https://access.example.com"}
	result, err := s.deliverInvitation(context.Background(), runtime, repository.Invitation{ID: "invite", UserID: "user", ExpiresAt: time.Now().Add(time.Hour)}, "alice", "alice@example.com", "token")
	if err != nil || result.Sent || result.Delivery != "not_configured" || result.AcceptURL != "https://access.example.com/invite#token" {
		t.Fatalf("fallback: %+v %v", result, err)
	}
	if strings.Contains(result.AcceptURL, "alice@example.com") {
		t.Fatal("PII in invitation URL")
	}
}

func TestMFAAndInvitationInvalidTokensFailBeforeDatabase(t *testing.T) {
	s := &AccessService{}
	if _, err := s.AcceptInvitation(context.Background(), "bad", "password"); !errors.Is(err, ErrInvitationUnavailable) {
		t.Fatal(err)
	}
	if _, err := s.PreviewInvitation(context.Background(), "bad"); !errors.Is(err, ErrInvitationUnavailable) {
		t.Fatal(err)
	}
	if _, err := s.GetMFAChallenge(context.Background(), "bad"); !errors.Is(err, ErrMFAFailed) {
		t.Fatal(err)
	}
	if err := s.ResetUserMFA(context.Background(), "user", "user"); !errors.Is(err, ErrValidation) {
		t.Fatal("admin self reset allowed")
	}
}
