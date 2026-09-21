//go:build integration

package integration_test

import (
	"context"
	"errors"
	"testing"

	"github.com/rs/zerolog"
	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/gateway"
	"github.com/srex-run/access-gateway/internal/iam"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/service"
)

func TestIAMRoleListRequiresRoleManagement(t *testing.T) {
	db := openDatabase(t)
	seedLegacyRoles(t, db)
	ctx := context.Background()
	repos := newRepositories()
	makeUser := func(name string) domain.User {
		t.Helper()
		user, err := repos.users.Create(ctx, db, domain.User{ID: id.New(), Nickname: name, Status: domain.UserStatusActive})
		if err != nil {
			t.Fatal(err)
		}
		return user
	}
	admin := makeUser("Role administrator")
	svc, err := service.NewAccessService(service.ServiceOptions{
		DB: db, Users: repos.users, Regions: repos.regions, Gateways: repos.gateways, Assets: repos.assets,
		Requests: repos.requests, Approvals: repos.approvals, Sessions: repos.sessions, SessionEvents: repos.sessionEvents,
		Audits: repos.audits, Outbox: repos.outbox, Gateway: gateway.UnavailableClient{}, Logger: zerolog.Nop(),
		AdminUserIDs: map[string]struct{}{admin.ID: {}},
	})
	if err != nil {
		t.Fatal(err)
	}
	role, err := svc.SaveIAMRole(ctx, admin.ID, iam.Role{
		Name: "role-manager", Enabled: true, Permissions: []authz.Permission{authz.PermissionRoleManage},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		role    string
		allowed bool
	}{
		{string(authz.RoleAdmin), true},
		{role.Name, true},
		{string(authz.RoleSRE), false},
		{string(authz.RoleCatalogAdmin), false},
		{string(authz.RoleUser), false},
	} {
		t.Run(test.role, func(t *testing.T) {
			actor := makeUser(test.role)
			if _, err := svc.GrantRole(ctx, admin.ID, service.GrantRoleInput{UserID: actor.ID, Role: test.role}); err != nil {
				t.Fatal(err)
			}
			roles, err := svc.ListIAMRoles(ctx, actor.ID)
			if test.allowed {
				if err != nil || len(roles) == 0 {
					t.Fatalf("authorized role list: len=%d, err=%v", len(roles), err)
				}
			} else if !errors.Is(err, service.ErrForbidden) || len(roles) != 0 {
				t.Fatalf("unauthorized role list: len=%d, err=%v", len(roles), err)
			}
			if test.role == string(authz.RoleSRE) || test.role == string(authz.RoleCatalogAdmin) {
				if _, err := svc.GetManagedUser(ctx, actor.ID, admin.ID); err != nil {
					t.Fatalf("user:read must still allow user role details: %v", err)
				}
			}
		})
	}
}
