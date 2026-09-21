//go:build integration

package integration_test

import (
	"context"
	"errors"
	"testing"

	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/service"
)

func TestUserAuditFiltersBeforePagination(t *testing.T) {
	database := openDatabase(t)
	ctx := context.Background()
	repos := newRepositories()
	admin, err := repos.users.Create(ctx, database, domain.User{ID: id.New(), FeishuOpenID: "admin-open-id", Nickname: "Admin", Status: domain.UserStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	svc := authenticationService(t, database)
	for _, event := range []struct{ actor, event string }{
		{"admin", "asset.created"}, {"user", "asset.updated"}, {"admin", "rbac.role_revoked"},
		{"user", "user.login"}, {"user", "asset.get"}, {"admin", "gateway.catalog_exported"},
		{"system", "asset.updated"}, {"system", "session.started"}, {"gateway", "connection.backend_connected"},
	} {
		err := repos.audits.Append(ctx, database, domain.AuditEvent{ID: id.New(), EventType: event.event, ActorType: event.actor, ActorID: &admin.ID, Result: stringPointer("success")})
		if err != nil {
			t.Fatal(err)
		}
	}
	values, err := svc.ListAuditEvents(ctx, admin.ID, domain.AuditFilter{Limit: 20})
	if err != nil || len(values) != 3 {
		t.Fatalf("mutations: %+v %v", values, err)
	}
	for i, want := range values {
		if want.ActorName != admin.Nickname || want.ActorUsername != admin.Username {
			t.Fatalf("external actor name missing: %+v", want)
		}
		page, err := svc.ListAuditEvents(ctx, admin.ID, domain.AuditFilter{Limit: 1, Offset: i})
		if err != nil || len(page) != 1 || page[0].ID != want.ID {
			t.Fatalf("sparse page %d: %+v %v", i, page, err)
		}
	}
	for _, filter := range []domain.AuditFilter{
		{Category: "resources", Action: "create"}, {Category: "permissions", Action: "delete"},
		{EventType: "asset.updated", ActorID: admin.ID},
	} {
		found, err := svc.ListAuditEvents(ctx, admin.ID, filter)
		if err != nil || len(found) != 1 {
			t.Fatalf("filter %+v: %+v %v", filter, found, err)
		}
	}
	for _, filter := range []domain.AuditFilter{{EventType: "user.login"}, {EventType: "asset.get"}, {Category: "users"}, {Offset: 3}} {
		found, err := svc.ListAuditEvents(ctx, admin.ID, filter)
		if err != nil || len(found) != 0 {
			t.Fatalf("excluded filter %+v: %+v %v", filter, found, err)
		}
	}
	for _, filter := range []domain.AuditFilter{{Category: "unknown"}, {Action: "get"}} {
		if _, err := svc.ListAuditEvents(ctx, admin.ID, filter); !errors.Is(err, service.ErrValidation) {
			t.Fatalf("invalid category accepted: %v", err)
		}
	}
	// Internal evidence stays available to its dedicated readers.
	raw, err := repository.NewAuditEventRepository().List(ctx, database, domain.AuditFilter{EventType: "session.started"})
	if err != nil || len(raw) != 1 {
		t.Fatalf("runtime evidence lost: %+v %v", raw, err)
	}
	if raw[0].ActorName != "" || raw[0].ActorUsername != "" {
		t.Fatal("system event was attributed to a user with the same ID")
	}
	if err := repos.users.CreateLocalCredential(ctx, database, repository.LocalCredential{UserID: admin.ID, Username: "audit-admin", PasswordHash: "test-password-hash-not-used-for-login"}); err != nil {
		t.Fatal(err)
	}
	localEvents, err := svc.ListAuditEvents(ctx, admin.ID, domain.AuditFilter{Limit: 1})
	if err != nil || len(localEvents) != 1 || localEvents[0].ActorUsername != "audit-admin" || localEvents[0].ActorName != admin.Nickname {
		t.Fatalf("local actor username missing: %+v %v", localEvents, err)
	}
	for _, actorID := range []*string{nil, stringPointer(id.New())} {
		if err := repos.audits.Append(ctx, database, domain.AuditEvent{ID: id.New(), EventType: "test.absent_actor", ActorType: "user", ActorID: actorID}); err != nil {
			t.Fatal(err)
		}
	}
	missingActors, err := repos.audits.List(ctx, database, domain.AuditFilter{EventType: "test.absent_actor"})
	if err != nil || len(missingActors) != 2 {
		t.Fatalf("events without user records were lost: %+v %v", missingActors, err)
	}
	for _, event := range missingActors {
		if event.ActorName != "" || event.ActorUsername != "" {
			t.Fatalf("unresolved actor has a name: %+v", event)
		}
	}
}
