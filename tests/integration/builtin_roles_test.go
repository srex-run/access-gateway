//go:build integration

package integration_test

import (
	"context"
	"database/sql"
	"errors"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/gateway"
	"github.com/srex-run/access-gateway/internal/iam"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/label"
	"github.com/srex-run/access-gateway/internal/operationaudit"
	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/service"
)

func builtinRoleService(t *testing.T) (*sql.DB, *service.AccessService, domain.User) {
	return builtinRoleServiceWithDatabase(t, openDatabase(t))
}

func builtinRoleServiceWithDatabase(t *testing.T, database *sql.DB) (*sql.DB, *service.AccessService, domain.User) {
	t.Helper()
	repos := newRepositories()
	admin, err := repos.users.Create(context.Background(), database, domain.User{ID: id.New(), Nickname: "Administrator", Status: domain.UserStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := service.NewAccessService(service.ServiceOptions{
		SystemSettings: clientAccessFixture(t, database, admin.ID, nil, "sessions.example.com"),
		DB:             database, Users: repos.users, Regions: repos.regions, Gateways: repos.gateways, Assets: repos.assets,
		Requests: repos.requests, Approvals: repos.approvals, Sessions: repos.sessions, SessionEvents: repos.sessionEvents,
		Audits: repos.audits, Outbox: repos.outbox, Gateway: gateway.UnavailableClient{}, Logger: zerolog.Nop(),
		AdminUserIDs: map[string]struct{}{admin.ID: {}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return database, svc, admin
}

// Migration fixtures use the schema that existed before unified account names.
func legacyUser(t *testing.T, database *sql.DB, nickname string) domain.User {
	t.Helper()
	user := domain.User{ID: id.New(), Nickname: nickname, Status: domain.UserStatusActive}
	if _, err := database.ExecContext(context.Background(), `INSERT INTO users (id, name, status) VALUES ($1, $2, 'active')`, user.ID, user.Nickname); err != nil {
		t.Fatal(err)
	}
	return user
}

func storedRole(t *testing.T, database *sql.DB, name string) iam.Role {
	t.Helper()
	roles, err := (repository.IAMRepository{}).ListRoles(context.Background(), database)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range roles {
		if role.Name == name {
			return role
		}
	}
	t.Fatalf("missing stored role %s", name)
	return iam.Role{}
}

// Compatibility scenarios explicitly provision legacy custom roles. A fresh
// installation must not acquire them just because other tests still use them.
func seedLegacyRoles(t *testing.T, database *sql.DB) {
	t.Helper()
	_, err := database.ExecContext(context.Background(), `INSERT INTO iam_roles (name, description, permissions, labels, revision) VALUES
		('sre', '运维工程师', '["directory:read","request:manage","approval:manage","session:manage","catalog:manage","audit:read","user:read","workflow:manage"]', '{"access-gateway.io/role":"sre","access-gateway.io/approval":"platform"}', 2),
		('catalog_admin', '目录管理员', '["directory:read","request:manage","approval:manage","session:manage","catalog:manage","user:read"]', '{"access-gateway.io/role":"catalog_admin"}', 2),
		('security_admin', '安全管理员', '["directory:read","request:manage","approval:manage","session:manage","audit:read"]', '{"access-gateway.io/role":"security_admin"}', 2)`)
	if err != nil {
		t.Fatal(err)
	}
}

func readRole(t *testing.T, svc *service.AccessService, actor, name string) iam.Role {
	t.Helper()
	roles, err := svc.ListIAMRoles(context.Background(), actor)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range roles {
		if role.Name == name {
			return role
		}
	}
	t.Fatalf("role %s not found", name)
	return iam.Role{}
}

func TestBuiltinRoleEditsPersistAndChangeAuthorization(t *testing.T) {
	database, svc, admin := builtinRoleService(t)
	ctx := context.Background()
	ordinary, err := svc.CreateLocalUser(ctx, admin.ID, service.CreateLocalUserInput{Nickname: "Ordinary", Username: "role-edit-user", Password: "initial-password-12345"})
	if err != nil {
		t.Fatal(err)
	}
	baseline := readRole(t, svc, admin.ID, "user")
	if err := svc.Authorize(ctx, ordinary.ID, authz.PermissionSessionManage); err != nil {
		t.Fatal(err)
	}
	input := baseline
	input.Description = "可查看审计的默认用户"
	input.Permissions = []authz.Permission{authz.PermissionDirectoryRead, authz.PermissionRequestManage, authz.PermissionAuditRead}
	input.Labels = maps.Clone(baseline.Labels)
	input.Labels["team"] = "all-users"
	input.BuiltIn = false // A client cannot change a stored role's classification.
	updated, err := svc.SaveIAMRole(ctx, admin.ID, input)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Name != baseline.Name || updated.Description != input.Description || !updated.Enabled || !updated.BuiltIn || updated.Revision != baseline.Revision+1 || !updated.CreatedAt.Equal(baseline.CreatedAt) || updated.UpdatedAt.Before(baseline.UpdatedAt) || !reflect.DeepEqual(updated.Permissions, input.Permissions) || !reflect.DeepEqual(updated.Labels, input.Labels) {
		t.Fatalf("updated role fields: %+v", updated)
	}
	if err := svc.Authorize(ctx, ordinary.ID, authz.PermissionSessionManage); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("removed baseline permission still grants access: %v", err)
	}
	if err := svc.Authorize(ctx, ordinary.ID, authz.PermissionAuditRead); err != nil {
		t.Fatalf("new baseline permission ineffective: %v", err)
	}
	permissions, err := svc.EffectivePermissions(ctx, ordinary.ID)
	if err != nil || !slices.Contains(permissions, authz.PermissionAuditRead) || slices.Contains(permissions, authz.PermissionSessionManage) {
		t.Fatalf("identity disagrees with saved role: %v, %v", permissions, err)
	}
	if _, err := svc.SaveIAMRole(ctx, admin.ID, input); !errors.Is(err, service.ErrStateConflict) {
		t.Fatalf("stale role save overwrote edits: %v", err)
	}
	if _, err := svc.SaveIAMRole(ctx, ordinary.ID, updated); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("ordinary account edited its role: %v", err)
	}
	updated.Enabled = false
	if _, err := (repository.IAMRepository{}).SaveRole(ctx, database, updated); !errors.Is(err, repository.ErrConstraint) {
		t.Fatalf("database allowed disabling baseline role: %v", err)
	}
}

func TestBuiltinRoleMigrationPreservesLegacyRoleGrants(t *testing.T) {
	database := openDatabaseAtVersion(t, 28)
	ctx := context.Background()
	operator := legacyUser(t, database, "Operator")
	if _, err := repository.NewRoleRepository().Create(ctx, database, domain.RoleAssignment{ID: id.New(), UserID: operator.ID, Role: "sre", GrantedBy: operator.ID}); err != nil {
		t.Fatal(err)
	}
	resetSchema(t, database)
	_, svc, admin := builtinRoleServiceWithDatabase(t, database)
	roles, err := svc.ListIAMRoles(ctx, admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	builtins := []string{}
	for _, role := range roles {
		if role.BuiltIn {
			builtins = append(builtins, role.Name)
		}
		if role.Name != "admin" && slices.Contains(role.Permissions, authz.PermissionSessionOverride) {
			t.Fatalf("ineffective legacy permission was retained: %s", role.Name)
		}
	}
	if !slices.Equal(builtins, []string{"admin", "auditor", "user"}) {
		t.Fatalf("built-in roles = %v", builtins)
	}
	if len(roles) != 4 {
		t.Fatalf("only the referenced legacy role should remain: %+v", roles)
	}
	if err := svc.Authorize(ctx, operator.ID, authz.PermissionWorkflowManage); err != nil {
		t.Fatalf("legacy SRE grant lost its permissions: %v", err)
	}
	sre := readRole(t, svc, admin.ID, "sre")
	sre.Permissions = []authz.Permission{authz.PermissionAuditRead}
	sre.Description = "自定义运维审计"
	sre, err = svc.SaveIAMRole(ctx, admin.ID, sre)
	if err != nil || sre.BuiltIn || sre.Labels["access-gateway.io/role"] != "sre" || sre.Labels["access-gateway.io/approval"] != "platform" {
		t.Fatalf("legacy role edit: %+v, %v", sre, err)
	}
	if err := svc.Authorize(ctx, operator.ID, authz.PermissionWorkflowManage); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("original SRE permissions override saved permissions: %v", err)
	}
	if err := svc.Authorize(ctx, operator.ID, authz.PermissionAuditRead); err != nil {
		t.Fatal(err)
	}
	sre.Labels["access-gateway.io/role"] = "admin"
	if _, err := svc.SaveIAMRole(ctx, admin.ID, sre); !errors.Is(err, service.ErrValidation) {
		t.Fatalf("managed label was editable: %v", err)
	}
}

func TestFreshInstallHasThreeBuiltinRoles(t *testing.T) {
	_, svc, admin := builtinRoleService(t)
	ctx := context.Background()
	roles, err := svc.ListIAMRoles(ctx, admin.ID)
	if err != nil || len(roles) != 3 {
		t.Fatalf("fresh role catalog: %+v %v", roles, err)
	}
	for index, name := range []string{"admin", "auditor", "user"} {
		if roles[index].Name != name || !roles[index].BuiltIn || !roles[index].Enabled {
			t.Fatalf("unexpected built-in role: %+v", roles[index])
		}
	}
	auditor := roles[1]
	auditor.Enabled = false
	if updated, err := svc.SaveIAMRole(ctx, admin.ID, auditor); err != nil || !updated.BuiltIn || updated.Enabled {
		t.Fatalf("built-in auditor cannot be disabled: %+v %v", updated, err)
	}
	custom, err := svc.SaveIAMRole(ctx, admin.ID, iam.Role{Name: "sre", Enabled: true, Permissions: []authz.Permission{authz.PermissionSessionOverride}})
	if err != nil || custom.BuiltIn {
		t.Fatalf("legacy names should remain available for custom roles: %+v %v", custom, err)
	}
}

func TestAuditorPromotionPreservesSavedPermissionsAndDisabledState(t *testing.T) {
	database := openDatabaseAtVersion(t, 28)
	ctx := context.Background()
	auditor := storedRole(t, database, "auditor")
	auditor.Description = "自定义审计职责"
	auditor.Permissions = []authz.Permission{authz.PermissionAuditRead}
	auditor.Labels["team"] = "security"
	auditor.Enabled = false
	auditor, err := (repository.IAMRepository{}).SaveRole(ctx, database, auditor)
	if err != nil {
		t.Fatal(err)
	}
	resetSchema(t, database)
	_, svc, admin := builtinRoleServiceWithDatabase(t, database)
	updated := readRole(t, svc, admin.ID, "auditor")
	if !updated.BuiltIn || updated.Enabled || updated.Description != auditor.Description || !reflect.DeepEqual(updated.Permissions, auditor.Permissions) || !reflect.DeepEqual(updated.Labels, auditor.Labels) || updated.Revision != auditor.Revision+1 {
		t.Fatalf("auditor promotion changed saved access: before=%+v after=%+v", auditor, updated)
	}
	updated.Description = "保持停用的审计员"
	if _, err := svc.SaveIAMRole(ctx, admin.ID, updated); err != nil {
		t.Fatalf("disabled built-in auditor cannot be edited: %v", err)
	}
}

func TestBuiltinRoleCleanupPreservesEditedRolesAndRevokedGrants(t *testing.T) {
	database := openDatabaseAtVersion(t, 28)
	ctx := context.Background()
	operator := legacyUser(t, database, "Security")
	grant, err := repository.NewRoleRepository().Create(ctx, database, domain.RoleAssignment{ID: id.New(), UserID: operator.ID, Role: "security_admin", GrantedBy: operator.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.NewRoleRepository().Revoke(ctx, database, grant.ID); err != nil {
		t.Fatal(err)
	}
	catalog := storedRole(t, database, "catalog_admin")
	catalog.Permissions = append(catalog.Permissions, authz.PermissionSessionOverride)
	catalog, err = (repository.IAMRepository{}).SaveRole(ctx, database, catalog)
	if err != nil {
		t.Fatal(err)
	}
	resetSchema(t, database)
	_, svc, admin := builtinRoleServiceWithDatabase(t, database)
	updated := readRole(t, svc, admin.ID, "catalog_admin")
	if updated.BuiltIn || !reflect.DeepEqual(updated.Permissions, catalog.Permissions) || updated.Revision != catalog.Revision {
		t.Fatalf("cleanup changed an edited custom role: %+v", updated)
	}
	if role := readRole(t, svc, admin.ID, "security_admin"); role.BuiltIn {
		t.Fatal("historically granted role should remain custom")
	}
	var revoked bool
	if err := database.QueryRowContext(ctx, `SELECT revoked_at IS NOT NULL FROM role_assignments WHERE id=$1`, grant.ID).Scan(&revoked); err != nil || !revoked {
		t.Fatalf("cleanup removed historical grant: %v", err)
	}
}

func TestBuiltinRoleCleanupPreservesRolesReferencedByBindings(t *testing.T) {
	database := openDatabaseAtVersion(t, 28)
	ctx := context.Background()
	if _, err := (repository.IAMRepository{}).SaveBinding(ctx, database, iam.Binding{ID: id.New(), Name: "Future operations users", UserSelector: "team=operations", RoleSelector: "access-gateway.io/role in (sre,catalog_admin)", Enabled: false}); err != nil {
		t.Fatal(err)
	}
	resetSchema(t, database)
	_, svc, admin := builtinRoleServiceWithDatabase(t, database)
	for _, name := range []string{"sre", "catalog_admin", "security_admin"} {
		if role := readRole(t, svc, admin.ID, name); role.BuiltIn {
			t.Fatalf("legacy role %s should remain custom", name)
		}
	}
}

func TestBuiltinAdministratorEditsRetainRecoveryAccess(t *testing.T) {
	database, svc, admin := builtinRoleService(t)
	ctx := context.Background()
	role := readRole(t, svc, admin.ID, "admin")
	role.Description = "平台值班管理员"
	role.Permissions = []authz.Permission{authz.PermissionRoleManage, authz.PermissionUserRead, authz.PermissionUserManage}
	role, err := svc.SaveIAMRole(ctx, admin.ID, role)
	if err != nil || !role.BuiltIn || !role.Enabled {
		t.Fatalf("administrator edit: %+v, %v", role, err)
	}
	if err := svc.Authorize(ctx, admin.ID, authz.PermissionAuditRead); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("fixed administrator defaults restored removed audit permission: %v", err)
	}
	invalid := role
	invalid.Permissions = []authz.Permission{authz.PermissionAuditRead}
	if _, err := svc.SaveIAMRole(ctx, admin.ID, invalid); !errors.Is(err, service.ErrValidation) {
		t.Fatalf("administrator lost role management: %v", err)
	}
	if _, err := (repository.IAMRepository{}).SaveRole(ctx, database, invalid); !errors.Is(err, repository.ErrConstraint) {
		t.Fatalf("database did not protect administrator role management: %v", err)
	}
	invalid = role
	invalid.Enabled = false
	if _, err := svc.SaveIAMRole(ctx, admin.ID, invalid); !errors.Is(err, service.ErrValidation) {
		t.Fatalf("administrator could be disabled: %v", err)
	}
	profile, err := svc.GetManagedUser(ctx, admin.ID, admin.ID)
	if err != nil || !profile.CanEdit {
		t.Fatalf("administrator user cannot be edited: %+v, %v", profile, err)
	}
	updated, err := svc.UpdateManagedUser(ctx, admin.ID, admin.ID, service.UpdateUserInput{Nickname: "值班管理员", Email: "admin@example.test", Department: "Operations", Status: domain.UserStatusActive, Labels: profile.Labels, Revision: profile.Revision})
	if err != nil || updated.Nickname != "值班管理员" || updated.Email != "admin@example.test" || updated.Department != "Operations" || !updated.CanEdit || updated.Revision != profile.Revision+1 {
		t.Fatalf("administrator user edit: %+v, %v", updated, err)
	}
	if _, err := svc.UpdateManagedUser(ctx, admin.ID, admin.ID, service.UpdateUserInput{Nickname: updated.Nickname, Status: domain.UserStatusInactive, Labels: updated.Labels, Revision: updated.Revision}); !errors.Is(err, service.ErrValidation) {
		t.Fatalf("administrator disabled its own account: %v", err)
	}
}

func TestCustomAdministratorPermissionsFollowGrantsAndBindings(t *testing.T) {
	database, svc, admin := builtinRoleService(t)
	ctx := context.Background()
	operator, err := newRepositories().users.Create(ctx, database, domain.User{ID: id.New(), Nickname: "Custom administrator", Status: domain.UserStatusActive, Labels: label.Labels{"team": "operations"}})
	if err != nil {
		t.Fatal(err)
	}
	permissions := make([]authz.Permission, 0, len(authz.Catalog()))
	for _, permission := range authz.Catalog() {
		permissions = append(permissions, permission.Key)
	}
	role, err := svc.SaveIAMRole(ctx, admin.ID, iam.Role{Name: "custom-administrator", Enabled: true, Permissions: permissions, Labels: label.Labels{"privilege": "administrator"}})
	if err != nil || role.BuiltIn {
		t.Fatalf("create custom administrator: %+v %v", role, err)
	}
	assertOverride := func(want bool) {
		t.Helper()
		err := svc.Authorize(ctx, operator.ID, authz.PermissionSessionOverride)
		if (want && err != nil) || (!want && !errors.Is(err, service.ErrForbidden)) {
			t.Fatalf("force-close authorization: want=%v err=%v", want, err)
		}
	}
	assertOverride(false)
	grant, err := svc.GrantRole(ctx, admin.ID, service.GrantRoleInput{UserID: operator.ID, Role: role.Name})
	if err != nil {
		t.Fatal(err)
	}
	assertOverride(true)
	effective, err := svc.EffectivePermissions(ctx, operator.ID)
	if err != nil || !slices.Equal(effective, permissions) {
		t.Fatalf("custom administrator permissions: %v %v", effective, err)
	}
	for _, permission := range permissions {
		if err := svc.Authorize(ctx, operator.ID, permission); err != nil {
			t.Fatalf("custom administrator cannot use %s: %v", permission, err)
		}
	}
	if _, err := svc.ListIAMRoles(ctx, operator.ID); err != nil {
		t.Fatalf("custom administrator cannot manage roles: %v", err)
	}
	if _, err := svc.RevokeRole(ctx, admin.ID, grant.ID); err != nil {
		t.Fatal(err)
	}
	assertOverride(false)
	if _, err := svc.SaveIAMBinding(ctx, admin.ID, iam.Binding{Name: "Operations administrators", UserSelector: "team=operations", RoleSelector: "privilege=administrator", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	assertOverride(true)
	role.Enabled = false
	role, err = svc.SaveIAMRole(ctx, admin.ID, role)
	if err != nil {
		t.Fatal(err)
	}
	assertOverride(false)
	role.Enabled = true
	role.Permissions = []authz.Permission{authz.PermissionRoleManage}
	if _, err := svc.SaveIAMRole(ctx, admin.ID, role); err != nil {
		t.Fatal(err)
	}
	assertOverride(false)
}

func TestCustomForceCloseRoleCanSelectOpenSessionsWithoutAuditAccess(t *testing.T) {
	database, svc, admin := builtinRoleService(t)
	ctx := context.Background()
	repos := newRepositories()
	baseline := readRole(t, svc, admin.ID, "user")
	baseline.Permissions = []authz.Permission{authz.PermissionDirectoryRead}
	if _, err := svc.SaveIAMRole(ctx, admin.ID, baseline); err != nil {
		t.Fatal(err)
	}
	operator, err := repos.users.Create(ctx, database, domain.User{ID: id.New(), Nickname: "Recovery operator", Status: domain.UserStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	role, err := svc.SaveIAMRole(ctx, admin.ID, iam.Role{Name: "recovery-operator", Enabled: true, Permissions: []authz.Permission{authz.PermissionSessionOverride}})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := svc.GrantRole(ctx, admin.ID, service.GrantRoleInput{UserID: operator.ID, Role: role.Name})
	if err != nil {
		t.Fatal(err)
	}
	region, err := repos.regions.Create(ctx, database, domain.Region{ID: id.New(), Code: "force-close", Name: "Recovery", Status: domain.ResourceStatusEnabled})
	if err != nil {
		t.Fatal(err)
	}
	gw, err := repos.gateways.Create(ctx, database, domain.Gateway{ID: id.New(), RegionID: region.ID, Name: "Gateway", ManagementEndpoint: "https://gateway.test", PublicEndpoint: "gateway.test:20000", MaxSessions: 10, Status: domain.ResourceStatusEnabled})
	if err != nil {
		t.Fatal(err)
	}
	asset, err := repos.assets.Create(ctx, database, domain.Asset{ID: id.New(), RegionID: region.ID, GatewayID: gw.ID, Name: "Recovery MySQL", AssetType: "mysql", TargetCiphertext: "unused", RiskLevel: domain.RiskLevelNormal, MaxTTLSeconds: 600, Status: domain.ResourceStatusEnabled})
	if err != nil {
		t.Fatal(err)
	}
	var sessions []domain.Session
	for index := range 2 {
		request, err := repos.requests.Create(ctx, database, domain.AccessRequest{ID: id.New(), ApplicantID: admin.ID, AssetID: asset.ID, TargetPort: 3306, Reason: "Recovery test", TTLSeconds: 600, Status: domain.AccessRequestApproved, IdempotencyKey: id.New()})
		if err != nil {
			t.Fatal(err)
		}
		session, err := repos.sessions.Create(ctx, database, domain.Session{ID: id.New(), RequestID: request.ID, GatewayID: gw.ID, Status: domain.SessionProvisioning, ConnectionMode: gateway.ConnectionModeAudit, AuditPolicy: operationaudit.Policy{Profile: "mysql", Revision: strings.Repeat("a", 64), Protocol: "mysql"}})
		if err != nil {
			t.Fatal(err)
		}
		if index == 0 {
			now := time.Now().UTC()
			session, err = repos.sessions.MarkDirectRunning(ctx, database, session.ID, session.Version, "agent", 20000, 20000, "direct", "gateway", now, now.Add(time.Hour), "", "")
		} else {
			err = repos.sessions.MarkProvisionFailed(ctx, database, session.ID, session.Version, "already ended")
		}
		if err != nil {
			t.Fatal(err)
		}
		sessions = append(sessions, session)
	}
	open, err := svc.ListSessionRecords(ctx, operator.ID, domain.SessionRecordFilter{Status: "open", Limit: 20})
	if err != nil || len(open) != 1 || open[0].ID != sessions[0].ID {
		t.Fatalf("force-close operator cannot select another user's open session: %+v %v", open, err)
	}
	for _, status := range []string{"", "running", "closed", "failed"} {
		if _, err := svc.ListSessionRecords(ctx, operator.ID, domain.SessionRecordFilter{Status: status, ReadAll: true, ActorID: admin.ID}); !errors.Is(err, service.ErrForbidden) {
			t.Fatalf("force-close role gained general record access with status %q: %v", status, err)
		}
	}
	for _, session := range sessions {
		if _, err := svc.GetSessionRecord(ctx, operator.ID, session.ID, false); !errors.Is(err, service.ErrForbidden) {
			t.Fatalf("force-close role gained audit detail access: %v", err)
		}
		if _, err := svc.GetSessionRecord(ctx, operator.ID, session.RequestID, true); !errors.Is(err, service.ErrForbidden) {
			t.Fatalf("force-close role gained request record access: %v", err)
		}
		if _, err := svc.ListSessionTrace(ctx, operator.ID, session.ID, "", 20, 0); !errors.Is(err, service.ErrForbidden) {
			t.Fatalf("force-close role gained audit trace access: %v", err)
		}
	}
	closed, err := svc.ForceCloseSession(ctx, operator.ID, sessions[0].ID, "custom administrator requested recovery")
	if err != nil || closed.Status != domain.SessionRevoking {
		t.Fatalf("custom role cannot queue force-close: %+v %v", closed, err)
	}
	if _, err := svc.RevokeRole(ctx, admin.ID, grant.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ListSessionRecords(ctx, operator.ID, domain.SessionRecordFilter{Status: "open"}); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("revoked operator can still select open sessions: %v", err)
	}
	if _, err := svc.ForceCloseSession(ctx, operator.ID, sessions[0].ID, "revoked"); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("revoked operator can still force-close: %v", err)
	}
}
