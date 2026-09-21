//go:build integration

package integration_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/iam"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/service"
)

func TestDemoModeAccessRequests(t *testing.T) {
	database := openDatabase(t)
	ctx := context.Background()
	repos := newRepositories()
	admin, err := repos.users.Create(ctx, database, domain.User{ID: id.New(), Nickname: "Demo administrator", Status: domain.UserStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	options := service.ServiceOptions{
		SystemSettings: clientAccessFixture(t, database, admin.ID, nil, "sessions.example.com"),
		DB:             database, Users: repos.users, Regions: repos.regions, Gateways: repos.gateways, Assets: repos.assets,
		Requests: repos.requests, Approvals: repos.approvals, Sessions: repos.sessions, SessionEvents: repos.sessionEvents,
		Audits: repos.audits, Outbox: repos.outbox, Gateway: &sessionRuntimeStub{}, Logger: zerolog.Nop(),
		DefaultTTL: time.Hour, MaxTTL: time.Hour, AdminUserIDs: map[string]struct{}{admin.ID: {}},
		Clock: func() time.Time { return now },
	}
	normal, err := service.NewAccessService(options)
	if err != nil {
		t.Fatal(err)
	}
	options.DemoMode = true
	demo, err := service.NewAccessService(options)
	if err != nil {
		t.Fatal(err)
	}
	user, err := normal.CreateLocalUser(ctx, admin.ID, service.CreateLocalUserInput{Nickname: "Demo visitor", Username: "demo-visitor", Password: "temporary-demo-test-password"})
	if err != nil {
		t.Fatal(err)
	}
	role, err := normal.SaveIAMRole(ctx, admin.ID, iam.Role{Name: "demo-requester", Enabled: true, Permissions: []authz.Permission{authz.PermissionRequestManage}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := normal.GrantRole(ctx, admin.ID, service.GrantRoleInput{UserID: user.ID, Role: role.Name}); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []struct {
		svc     *service.AccessService
		enabled bool
	}{{normal, false}, {demo, true}} {
		value, err := mode.svc.GetAccessOptions(ctx, user.ID)
		if err != nil || value.DemoMode != mode.enabled || value.DemoSessionTTLSeconds != 300 {
			t.Fatalf("browser demo policy: %+v / %v", value, err)
		}
	}
	region, err := repos.regions.Create(ctx, database, domain.Region{ID: id.New(), Code: "demo-test", Name: "Demo", Status: domain.ResourceStatusEnabled})
	if err != nil {
		t.Fatal(err)
	}
	gw, err := repos.gateways.Create(ctx, database, domain.Gateway{ID: id.New(), RegionID: region.ID, Name: "Demo", ManagementEndpoint: "https://gateway.test:8090", PublicEndpoint: "sessions.example.com:20000", MaxSessions: 10, Status: domain.ResourceStatusEnabled})
	if err != nil {
		t.Fatal(err)
	}
	newInput := func(ttl, maxTTL int) service.CreateRequestInput {
		t.Helper()
		assetID := id.New()
		asset, err := repos.assets.Create(ctx, database, domain.Asset{ID: assetID, RegionID: region.ID, GatewayID: gw.ID, Name: "demo-db-" + assetID, AssetType: "mysql", TargetCiphertext: "test-fixture-ciphertext", RiskLevel: domain.RiskLevelNormal, MaxTTLSeconds: maxTTL, Status: domain.ResourceStatusEnabled})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := repos.assets.CreatePort(ctx, database, domain.AssetPort{ID: id.New(), AssetID: asset.ID, Port: 3306, Protocol: "tcp", Enabled: true}); err != nil {
			t.Fatal(err)
		}
		return service.CreateRequestInput{ApplicantID: user.ID, RegionID: region.ID, AssetID: asset.ID, TargetPort: 3306, SourceIP: "127.0.0.1", TargetAccount: "readonly", Reason: "Try the demo", TTLSeconds: ttl, IdempotencyKey: id.New()}
	}

	for _, ttl := range []int{0, 60, 3600} {
		t.Run(fmt.Sprintf("requested_%d_seconds", ttl), func(t *testing.T) {
			input := newInput(ttl, 3600)
			// Normal mode either waits for its configured approvers or rejects
			// an incomplete workflow; it must never create an approved grant.
			normalInput := input
			normalInput.IdempotencyKey = id.New()
			pending, err := normal.CreateAccessRequest(ctx, normalInput)
			if err == nil {
				if pending.ApprovalMode != "required" || pending.Status != domain.AccessRequestPendingApproval {
					t.Fatalf("normal request bypassed approval: %+v", pending)
				}
				if _, err := repos.sessions.GetByRequestID(ctx, database, pending.ID); !errors.Is(err, repository.ErrNotFound) {
					t.Fatalf("unapproved normal request has a session: %v", err)
				}
			} else if !errors.Is(err, service.ErrValidation) {
				t.Fatalf("normal approval flow: %v", err)
			}
			created, err := demo.CreateAccessRequest(ctx, input)
			if err != nil {
				t.Fatal(err)
			}
			if created.ApprovalMode != "demo" || created.Status != domain.AccessRequestApproved || created.TTLSeconds != 300 {
				t.Fatalf("demo grant: %+v", created)
			}
			session, err := repos.sessions.GetByRequestID(ctx, database, created.ID)
			if err != nil || session.Status != domain.SessionProvisioning || session.ExpiresAt == nil || !session.ExpiresAt.Equal(now.Add(5*time.Minute)) {
				t.Fatalf("demo session deadline: %+v / %v", session, err)
			}
			approvals, err := repos.approvals.ListByRequest(ctx, database, created.ID)
			if err != nil || len(approvals) != 0 {
				t.Fatalf("demo request generated human approvals: %+v / %v", approvals, err)
			}
			audits, err := repos.audits.List(ctx, database, domain.AuditFilter{RequestID: created.ID, EventType: "access_request.demo_auto_approved", Limit: 10})
			if err != nil || len(audits) != 1 || audits[0].ActorType != "system" || audits[0].ActorID != nil {
				t.Fatalf("missing system approval audit: %+v / %v", audits, err)
			}
			retried, err := demo.CreateAccessRequest(ctx, input)
			if err != nil || retried.ID != created.ID {
				t.Fatalf("demo retry created another request: %+v / %v", retried, err)
			}
			linked, err := repos.sessions.GetByRequestID(ctx, database, retried.ID)
			if err != nil || linked.ID != session.ID || linked.ExpiresAt == nil || !linked.ExpiresAt.Equal(*session.ExpiresAt) {
				t.Fatalf("demo retry renewed or replaced the session: %+v / %v", linked, err)
			}
			events, err := repos.outbox.ClaimPending(ctx, database, 100, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			provisions := 0
			for _, event := range events {
				if event.AggregateType == "session" && event.AggregateID == session.ID && event.EventType == "session.provision" {
					provisions++
				}
			}
			if provisions != 1 {
				t.Fatalf("expected one durable provisioning command, got %d", provisions)
			}
			input.IdempotencyKey = id.New()
			if _, err := demo.CreateAccessRequest(ctx, input); !errors.Is(err, repository.ErrConflict) {
				t.Fatalf("duplicate active session accepted: %v", err)
			}
			historical, err := normal.GetAccessRequest(ctx, user.ID, created.ID)
			if err != nil || historical.ApprovalMode != "demo" || historical.TTLSeconds != 300 {
				t.Fatalf("disabling demo rewrote the old grant: %+v / %v", historical, err)
			}
			invalid := created
			invalid.ID, invalid.IdempotencyKey, invalid.TTLSeconds = id.New(), id.New(), 301
			if _, err := repos.requests.Create(ctx, database, invalid); err == nil {
				t.Fatal("database accepted a demo grant longer than five minutes")
			}
		})
	}

	t.Run("authorization and access limits", func(t *testing.T) {
		input := newInput(600, 3600)
		if _, err := demo.CreateTestAccessRequest(ctx, input); !errors.Is(err, service.ErrForbidden) {
			t.Fatalf("demo visitor acquired administrator test permission: %v", err)
		}
		input.SourceIP = ""
		if _, err := demo.CreateAccessRequest(ctx, input); !errors.Is(err, service.ErrValidation) {
			t.Fatalf("demo bypassed required web audit configuration: %v", err)
		}
		input.SourceIP, input.TargetPort = "127.0.0.1", 22
		if _, err := demo.CreateAccessRequest(ctx, input); !errors.Is(err, service.ErrValidation) {
			t.Fatalf("demo accepted an unconfigured port: %v", err)
		}
		if _, err := demo.CreateAccessRequest(ctx, newInput(60, 299)); !errors.Is(err, service.ErrValidation) {
			t.Fatalf("demo exceeded asset duration limit: %v", err)
		}
		limitedOptions := options
		limitedOptions.DefaultTTL, limitedOptions.MaxTTL = time.Minute, 299*time.Second
		limited, err := service.NewAccessService(limitedOptions)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := limited.CreateAccessRequest(ctx, newInput(60, 3600)); !errors.Is(err, service.ErrValidation) {
			t.Fatalf("demo exceeded platform duration limit: %v", err)
		}
		input = newInput(600, 3600)
		input.ApplicantID = admin.ID
		created, err := demo.CreateTestAccessRequest(ctx, input)
		if err != nil || created.ApprovalMode != "admin_test" || created.TTLSeconds != 300 {
			t.Fatalf("administrator demo session duration: %+v / %v", created, err)
		}
		if err := repos.users.UpdateStatus(ctx, database, user.ID, domain.UserStatusInactive); err != nil {
			t.Fatal(err)
		}
		if _, err := demo.CreateAccessRequest(ctx, newInput(300, 3600)); !errors.Is(err, service.ErrForbidden) {
			t.Fatalf("inactive user received a demo grant: %v", err)
		}
	})
}
