package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/operationaudit"
)

func TestTerminalDemoDefaultsRequiresAuthorizationInEveryMode(t *testing.T) {
	for _, demoMode := range []bool{false, true} {
		s := &AccessService{demoMode: demoMode}
		value, err := s.GetTerminalDemoDefaults(context.Background(), "invalid-actor", "invalid-session")
		if !errors.Is(err, ErrForbidden) || value != (TerminalDemoDefaults{}) {
			t.Fatalf("unauthorized demo defaults for mode %t: value=%+v err=%v", demoMode, value, err)
		}
	}
}

func TestWebAccessDefaultsAndProtocolRequirements(t *testing.T) {
	s := &AccessService{}
	if enabled, err := s.clientAccessEnabled(context.Background()); err != nil || enabled {
		t.Fatal("client access must be opt-in")
	}
	request := domain.AccessRequest{}
	if validateWebAccess(request, operationaudit.Policy{}) == nil {
		t.Fatal("unaudited web access allowed")
	}
	for _, protocol := range []string{"ssh", "mysql", "postgresql", "redis", "mongodb", "http"} {
		if err := validateWebAccess(request, operationaudit.Policy{Profile: protocol, Protocol: protocol}); err != nil {
			t.Fatalf("%s: %v", protocol, err)
		}
		if validateWebAccess(request, operationaudit.Policy{Protocol: protocol}) == nil {
			t.Fatalf("%s allowed without audit profile", protocol)
		}
	}
	if validateWebAccess(request, operationaudit.Policy{Profile: "other", Protocol: "tcp"}) == nil {
		t.Fatal("unknown client allowed")
	}
	source := "192.0.2.1"
	request.SourceIP = &source
	if err := validateWebAccess(request, operationaudit.Policy{}); err != nil {
		t.Fatal("existing native client access changed")
	}
}

func TestWebTerminalOwnerApprovalAndExpiry(t *testing.T) {
	for _, protocol := range []string{"ssh", "mysql", "postgresql", "redis", "mongodb", "http"} {
		t.Run(protocol, func(t *testing.T) {
			now := time.Now()
			expires := now.Add(time.Minute)
			request := domain.AccessRequest{ApplicantID: "owner", Status: domain.AccessRequestApproved}
			session := domain.Session{ConnectionMode: "audit", AuditPolicy: operationaudit.Policy{Protocol: protocol}, Status: domain.SessionRunning, ExpiresAt: &expires}
			if !canUseWebTerminal("owner", session, request, now) {
				t.Fatal("owner cannot connect")
			}
			if canUseWebTerminal("admin", session, request, now) {
				t.Fatal("admin read access granted terminal ownership")
			}
			if canUseWebTerminal("owner", session, request, expires) {
				t.Fatal("expired grant allowed")
			}
			request.Status = domain.AccessRequestCancelled
			if canUseWebTerminal("owner", session, request, now) {
				t.Fatal("cancelled request allowed")
			}
			request.Status = domain.AccessRequestApproved
			for _, status := range []domain.SessionStatus{domain.SessionProvisioning, domain.SessionRevoking, domain.SessionClosed, domain.SessionExpired, domain.SessionFailed} {
				session.Status = status
				if canUseWebTerminal("owner", session, request, now) {
					t.Fatalf("terminal accepted state %s", status)
				}
			}
		})
	}
}
