//go:build integration

package integration_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pressly/goose/v3"
	"github.com/rs/zerolog"

	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/cmdb"
	_ "github.com/srex-run/access-gateway/internal/db"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/feishu"
	"github.com/srex-run/access-gateway/internal/gateway"
	"github.com/srex-run/access-gateway/internal/gatewayagent"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/secretstore"
	"github.com/srex-run/access-gateway/internal/service"
	"github.com/srex-run/access-gateway/migrations"
)

const testDSNEnv = "POSTGRES_TEST_DSN"

func TestGatewayFailoverSessionLifecycle(t *testing.T) {
	database := openDatabase(t)
	ctx := context.Background()
	secret := "0123456789abcdef0123456789abcdef"

	var primaryReady atomic.Bool
	primaryReady.Store(true)
	var primaryCreates atomic.Int32
	primary := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		if request.URL.Path == "/readyz" && request.Method == http.MethodGet {
			if !primaryReady.Load() {
				response.WriteHeader(http.StatusServiceUnavailable)
				_, _ = response.Write([]byte(`{"status":"unavailable"}`))
				return
			}
			_, _ = response.Write([]byte(`{"status":"ready"}`))
			return
		}
		if request.Method == http.MethodPost {
			primaryCreates.Add(1)
		}
		response.WriteHeader(http.StatusServiceUnavailable)
		_, _ = response.Write([]byte(`{"error":"unavailable"}`))
	}))
	defer primary.Close()

	controller := &lifecycleController{}
	store := &memoryStateStore{}
	assetID := id.New()
	catalog, err := gatewayagent.NewAssetCatalog([]gatewayagent.AssetCatalogEntry{{TargetID: assetID, Ports: []int{5432}}})
	if err != nil {
		t.Fatalf("create gateway catalog: %v", err)
	}
	manager, err := gatewayagent.NewManager(controller, store, catalog, time.Hour, zerolog.Nop())
	if err != nil {
		t.Fatalf("create gateway manager: %v", err)
	}
	agent, err := gatewayagent.NewServer(manager, secret, zerolog.Nop())
	if err != nil {
		t.Fatalf("create gateway server: %v", err)
	}
	backup := httptest.NewServer(agent.Container())
	defer backup.Close()

	gatewayClient, err := gateway.NewHTTPClientWithConfig(gateway.HTTPClientConfig{
		Timeout: time.Second, InternalSecret: secret, RequireHTTPS: false,
	})
	if err != nil {
		t.Fatalf("create gateway client: %v", err)
	}
	repos := newRepositories()
	svc, err := service.NewAccessService(service.ServiceOptions{
		DB: database, Users: repos.users, Regions: repos.regions, Gateways: repos.gateways,
		Assets: repos.assets, Requests: repos.requests, Approvals: repos.approvals,
		Sessions: repos.sessions, SessionEvents: repos.sessionEvents, Audits: repos.audits,
		Outbox: repos.outbox, Gateway: gatewayClient, Notifier: feishu.NoopNotifier{},
		GatewayHeartbeatMaxAge: time.Minute, Logger: zerolog.Nop(),
	})
	if err != nil {
		t.Fatalf("create access service: %v", err)
	}

	user, err := repos.users.Create(ctx, database, domain.User{ID: id.New(), FeishuOpenID: "ou-e2e-user", Nickname: "E2E User", Status: domain.UserStatusActive})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	region, err := repos.regions.Create(ctx, database, domain.Region{ID: id.New(), Code: "e2e-region", Name: "E2E Region", Status: domain.ResourceStatusEnabled})
	if err != nil {
		t.Fatalf("create region: %v", err)
	}
	primaryGateway, err := repos.gateways.Create(ctx, database, domain.Gateway{
		ID: id.New(), RegionID: region.ID, Name: "primary", ManagementEndpoint: primary.URL,
		PublicEndpoint: primary.URL, Status: domain.ResourceStatusEnabled, MaxSessions: 10,
	})
	if err != nil {
		t.Fatalf("create primary gateway: %v", err)
	}
	backupGateway, err := repos.gateways.Create(ctx, database, domain.Gateway{
		ID: id.New(), RegionID: region.ID, Name: "backup", ManagementEndpoint: backup.URL,
		PublicEndpoint: backup.URL, Status: domain.ResourceStatusEnabled, MaxSessions: 10,
	})
	if err != nil {
		t.Fatalf("create backup gateway: %v", err)
	}
	asset, err := repos.assets.Create(ctx, database, domain.Asset{
		ID: assetID, RegionID: region.ID, GatewayID: primaryGateway.ID, Name: "e2e-database",
		AssetType: "postgres", TargetCiphertext: "kms-ciphertext", RiskLevel: domain.RiskLevelSensitive,
		MaxTTLSeconds: 300, Status: domain.ResourceStatusEnabled,
	})
	if err != nil {
		t.Fatalf("create asset: %v", err)
	}
	if err := repos.gateways.BindAsset(ctx, database, asset.ID, primaryGateway.ID, 0); err != nil {
		t.Fatalf("bind primary gateway: %v", err)
	}
	if err := repos.gateways.BindAsset(ctx, database, asset.ID, backupGateway.ID, 10); err != nil {
		t.Fatalf("bind backup gateway: %v", err)
	}
	if _, err := repos.assets.CreatePort(ctx, database, domain.AssetPort{ID: id.New(), AssetID: asset.ID, Port: 5432, Protocol: "tcp", Enabled: true}); err != nil {
		t.Fatalf("create asset port: %v", err)
	}

	results, err := svc.ProbeGateways(ctx)
	if err != nil || len(results) != 2 {
		t.Fatalf("initial gateway probes: results=%+v err=%v", results, err)
	}
	for _, result := range results {
		if result.Err != nil {
			t.Fatalf("initial gateway %s probe: %v", result.GatewayID, result.Err)
		}
	}
	primaryReady.Store(false)
	request, err := repos.requests.Create(ctx, database, domain.AccessRequest{
		ID: id.New(), ApplicantID: user.ID, AssetID: asset.ID, TargetPort: 5432,
		Reason: "integration failover", TTLSeconds: 120, Status: domain.AccessRequestApproved,
		IdempotencyKey: "e2e-failover-request", SourceIP: stringPointer("127.0.0.1"),
		TargetAccount: stringPointer("readonly"),
	})
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	session, err := repos.sessions.Create(ctx, database, domain.Session{
		ID: id.New(), RequestID: request.ID, GatewayID: primaryGateway.ID, Status: domain.SessionProvisioning,
		ConnectionMode: gateway.ConnectionModeNative,
	})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	session, err = svc.ProvisionSession(ctx, session.ID)
	if err != nil {
		t.Fatalf("provision with failover: %v", err)
	}
	if session.Status != domain.SessionRunning || session.GatewayID != backupGateway.ID || controller.startCalls() != 1 || primaryCreates.Load() != 0 {
		t.Fatalf("failover session=%+v backup_starts=%d primary_creates=%d", session, controller.startCalls(), primaryCreates.Load())
	}
	// Construct a fresh service instance to model a request reaching another
	// replica after the provisioning worker returned on this one.
	secondReplica, err := service.NewAccessService(service.ServiceOptions{
		DB: database, Users: repos.users, Regions: repos.regions, Gateways: repos.gateways,
		Assets: repos.assets, Requests: repos.requests, Approvals: repos.approvals,
		Sessions: repos.sessions, SessionEvents: repos.sessionEvents, Audits: repos.audits,
		Outbox: repos.outbox, Gateway: gatewayClient, Notifier: feishu.NoopNotifier{},
		GatewayHeartbeatMaxAge: time.Minute, Logger: zerolog.Nop(),
	})
	if err != nil {
		t.Fatalf("create second access service replica: %v", err)
	}
	view, err := secondReplica.GetSession(ctx, user.ID, session.ID)
	if err != nil || view.GatewayPort != 32001 || view.GatewayHost == "" || view.GatewayEndpoint == "" {
		t.Fatalf("read direct session through second replica: view=%+v err=%v", view, err)
	}
	if view.Session.ConnectionMode != gateway.ConnectionModeNative || !view.CanConnect {
		t.Fatalf("native session not connectable through second replica: %+v", view)
	}
	other, err := repos.users.Create(ctx, database, domain.User{ID: id.New(), FeishuOpenID: "ou-other-session", Nickname: "Other", Status: domain.UserStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.GetSession(ctx, other.ID, session.ID); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("non-owner session access: %v", err)
	}
	adminService, err := service.NewAccessService(service.ServiceOptions{
		DB: database, Users: repos.users, Regions: repos.regions, Gateways: repos.gateways, Assets: repos.assets,
		Requests: repos.requests, Approvals: repos.approvals, Sessions: repos.sessions, SessionEvents: repos.sessionEvents, Audits: repos.audits,
		Gateway: gatewayClient, AdminUserIDs: map[string]struct{}{other.ID: {}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if adminView, err := adminService.GetSession(ctx, other.ID, session.ID); err != nil || adminView.CanConnect || adminView.CanWebConnect {
		t.Fatalf("admin session view grants connection access: %+v, %v", adminView, err)
	}
	if err := repos.users.UpdateStatus(ctx, database, user.ID, domain.UserStatusInactive); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.GetSession(ctx, user.ID, session.ID); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("disabled applicant accessed session: %v", err)
	}
	if err := repos.users.UpdateStatus(ctx, database, user.ID, domain.UserStatusActive); err != nil {
		t.Fatal(err)
	}
	session, err = svc.RevokeSession(ctx, session.ID, "e2e_complete")
	if err != nil || session.Status != domain.SessionClosed || controller.stopCalls() != 1 {
		t.Fatalf("revoke session=%+v stops=%d err=%v", session, controller.stopCalls(), err)
	}
	if closedView, err := secondReplica.GetSession(ctx, user.ID, session.ID); err != nil || closedView.CanConnect || closedView.CanWebConnect {
		t.Fatalf("closed session still permits connections: %+v, %v", closedView, err)
	}
}

func TestCMDBAuthoritativeSyncReconcilesCatalog(t *testing.T) {
	database := openDatabase(t)
	ctx := context.Background()
	repos := newRepositories()
	region, err := repos.regions.Create(ctx, database, domain.Region{ID: id.New(), Code: "cmdb-region", Name: "CMDB Region", Status: domain.ResourceStatusEnabled})
	if err != nil {
		t.Fatalf("create region: %v", err)
	}
	firstGateway, err := repos.gateways.Create(ctx, database, domain.Gateway{ID: id.New(), RegionID: region.ID, Name: "cmdb-gw-1", ManagementEndpoint: "https://gw-1.example", PublicEndpoint: "gw-1.example:443", Status: domain.ResourceStatusEnabled, MaxSessions: 10})
	if err != nil {
		t.Fatalf("create first gateway: %v", err)
	}
	secondGateway, err := repos.gateways.Create(ctx, database, domain.Gateway{ID: id.New(), RegionID: region.ID, Name: "cmdb-gw-2", ManagementEndpoint: "https://gw-2.example", PublicEndpoint: "gw-2.example:443", Status: domain.ResourceStatusEnabled, MaxSessions: 10})
	if err != nil {
		t.Fatalf("create second gateway: %v", err)
	}
	client := &staticCMDBClient{snapshot: cmdb.Snapshot{Authoritative: true, Revision: "revision-1", Assets: []cmdb.Asset{
		{ExternalID: "db-1", RegionCode: region.Code, GatewayIDs: []string{firstGateway.ID, secondGateway.ID}, Name: "CMDB DB 1", AssetType: "postgres", Target: "10.0.0.1", RiskLevel: "sensitive", MaxTTLSeconds: 900, Status: "enabled", Ports: []cmdb.Port{{Port: 5432, Protocol: "tcp"}}},
		{ExternalID: "db-2", RegionCode: region.Code, GatewayIDs: []string{secondGateway.ID}, Name: "CMDB DB 2", AssetType: "mysql", Target: "10.0.0.2", RiskLevel: "normal", MaxTTLSeconds: 600, Status: "enabled", Ports: []cmdb.Port{{Port: 3306, Protocol: "tcp"}}},
	}}}
	svc, err := service.NewAccessService(service.ServiceOptions{
		DB: database, Users: repos.users, Regions: repos.regions, Gateways: repos.gateways, Assets: repos.assets,
		Requests: repos.requests, Approvals: repos.approvals, Sessions: repos.sessions, SessionEvents: repos.sessionEvents,
		Audits: repos.audits, Outbox: repos.outbox, Gateway: gateway.UnavailableClient{}, Notifier: feishu.NoopNotifier{},
		CMDB: client, CMDBSource: "primary-cmdb", AssetEncryptor: testCMDBEncryptor{}, Logger: zerolog.Nop(),
	})
	if err != nil {
		t.Fatalf("create CMDB service: %v", err)
	}
	result, err := svc.SyncCMDB(ctx)
	if err != nil || result.Created != 2 || result.Updated != 0 || result.Disabled != 0 || result.Revision != "revision-1" {
		t.Fatalf("first CMDB sync result=%+v err=%v", result, err)
	}
	first, err := repos.assets.GetByExternalIdentity(ctx, database, "primary-cmdb", "db-1")
	if err != nil || first.Status != domain.ResourceStatusEnabled || first.ExternalID == nil || first.LastSyncedAt == nil || first.TargetCiphertext != "encrypted:10.0.0.1" {
		t.Fatalf("synced first asset=%+v err=%v", first, err)
	}
	bindings, err := repos.gateways.ListAssetBindings(ctx, database, first.ID)
	if err != nil || len(bindings) != 2 || bindings[0].GatewayID != firstGateway.ID || bindings[1].GatewayID != secondGateway.ID {
		t.Fatalf("synced bindings=%+v err=%v", bindings, err)
	}
	client.snapshot = cmdb.Snapshot{Authoritative: true, Revision: "revision-2", Assets: []cmdb.Asset{{
		ExternalID: "db-1", RegionCode: region.Code, GatewayIDs: []string{secondGateway.ID}, Name: "CMDB DB 1 updated", AssetType: "postgres", Target: "10.0.0.10", RiskLevel: "critical", MaxTTLSeconds: 1200, Status: "enabled", Ports: []cmdb.Port{{Port: 5433, Protocol: "tcp"}},
	}}}
	result, err = svc.SyncCMDB(ctx)
	if err != nil || result.Created != 0 || result.Updated != 1 || result.Disabled != 1 || result.Revision != "revision-2" {
		t.Fatalf("second CMDB sync result=%+v err=%v", result, err)
	}
	first, err = repos.assets.GetByID(ctx, database, first.ID)
	if err != nil || first.Name != "CMDB DB 1 updated" || first.TargetCiphertext != "encrypted:10.0.0.10" || first.RiskLevel != domain.RiskLevelCritical {
		t.Fatalf("updated first asset=%+v err=%v", first, err)
	}
	second, err := repos.assets.GetByExternalIdentity(ctx, database, "primary-cmdb", "db-2")
	if err != nil || second.Status != domain.ResourceStatusDisabled {
		t.Fatalf("missing second asset=%+v err=%v", second, err)
	}
}

func TestAssetDisableQueuesEverySessionAcrossBatches(t *testing.T) {
	database := openDatabase(t)
	ctx := context.Background()
	repos := newRepositories()
	admin, err := repos.users.Create(ctx, database, domain.User{ID: id.New(), FeishuOpenID: "ou-batch-admin", Nickname: "Batch Admin", Status: domain.UserStatusActive})
	if err != nil {
		t.Fatalf("create batch admin: %v", err)
	}
	applicant, err := repos.users.Create(ctx, database, domain.User{ID: id.New(), FeishuOpenID: "ou-batch-user", Nickname: "Batch User", Status: domain.UserStatusActive})
	if err != nil {
		t.Fatalf("create batch applicant: %v", err)
	}
	region, err := repos.regions.Create(ctx, database, domain.Region{ID: id.New(), Code: "batch-region", Name: "Batch Region", Status: domain.ResourceStatusEnabled})
	if err != nil {
		t.Fatalf("create batch region: %v", err)
	}
	gatewayRecord, err := repos.gateways.Create(ctx, database, domain.Gateway{
		ID: id.New(), RegionID: region.ID, Name: "batch-gateway", ManagementEndpoint: "https://batch-gateway.example",
		PublicEndpoint: "batch-gateway.example:443", Status: domain.ResourceStatusEnabled, MaxSessions: 1000,
	})
	if err != nil {
		t.Fatalf("create batch gateway: %v", err)
	}
	asset, err := repos.assets.Create(ctx, database, domain.Asset{
		ID: id.New(), RegionID: region.ID, GatewayID: gatewayRecord.ID, Name: "batch-asset", AssetType: "postgres",
		TargetCiphertext: "encrypted", RiskLevel: domain.RiskLevelNormal, MaxTTLSeconds: 300, Status: domain.ResourceStatusEnabled,
	})
	if err != nil {
		t.Fatalf("create batch asset: %v", err)
	}
	if err := repos.gateways.BindAsset(ctx, database, asset.ID, gatewayRecord.ID, 0); err != nil {
		t.Fatalf("bind batch gateway: %v", err)
	}

	svc, err := service.NewAccessService(service.ServiceOptions{
		DB: database, Users: repos.users, Regions: repos.regions, Gateways: repos.gateways, Assets: repos.assets,
		Requests: repos.requests, Approvals: repos.approvals, Sessions: repos.sessions, SessionEvents: repos.sessionEvents,
		Audits: repos.audits, Outbox: repos.outbox, Gateway: gateway.UnavailableClient{}, Notifier: feishu.NoopNotifier{},
		AdminUserIDs: map[string]struct{}{admin.ID: {}}, Logger: zerolog.Nop(),
	})
	if err != nil {
		t.Fatalf("create batch service: %v", err)
	}

	const sessionCount = 101
	sessionIDs := make([]string, 0, sessionCount)
	for index := 0; index < sessionCount; index++ {
		request, createErr := repos.requests.Create(ctx, database, domain.AccessRequest{
			ID: id.New(), ApplicantID: applicant.ID, AssetID: asset.ID, TargetPort: 5432,
			Reason: "batch resource shutdown", TTLSeconds: 300, Status: domain.AccessRequestApproved,
			IdempotencyKey: fmt.Sprintf("batch-revoke-%03d", index),
		})
		if createErr != nil {
			t.Fatalf("create request %d: %v", index, createErr)
		}
		session, createErr := repos.sessions.Create(ctx, database, domain.Session{
			ID: id.New(), RequestID: request.ID, GatewayID: gatewayRecord.ID, Status: domain.SessionProvisioning,
		})
		if createErr != nil {
			t.Fatalf("create session %d: %v", index, createErr)
		}
		now := time.Now().UTC()
		session, createErr = repos.sessions.MarkRunning(ctx, database, session.ID, 0, "batch-token-hash", fmt.Sprintf("process-%03d", index), now, now.Add(5*time.Minute))
		if createErr != nil {
			t.Fatalf("mark session %d running: %v", index, createErr)
		}
		sessionIDs = append(sessionIDs, session.ID)
	}

	updated, err := svc.UpdateAssetStatus(ctx, admin.ID, asset.ID, domain.ResourceStatusDisabled)
	if err != nil || updated.Status != domain.ResourceStatusDisabled {
		t.Fatalf("disable asset: asset=%+v err=%v", updated, err)
	}
	for _, sessionID := range sessionIDs {
		session, getErr := repos.sessions.GetByID(ctx, database, sessionID)
		if getErr != nil || session.Status != domain.SessionRevoking {
			t.Fatalf("queued session %s: status=%s err=%v", sessionID, session.Status, getErr)
		}
	}
	remaining, err := repos.sessions.ListRevocationsToQueueByAsset(ctx, database, asset.ID, 500)
	if err != nil || len(remaining) != 0 {
		t.Fatalf("unqueued asset sessions: count=%d err=%v", len(remaining), err)
	}
}

func TestPersistentRBACEnforcesAndRevokesSpecializedRoles(t *testing.T) {
	database := openDatabase(t)
	seedLegacyRoles(t, database)
	ctx := context.Background()
	repos := newRepositories()
	createUser := func(openID, name string) domain.User {
		user, err := repos.users.Create(ctx, database, domain.User{ID: id.New(), FeishuOpenID: openID, Nickname: name, Status: domain.UserStatusActive})
		if err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		return user
	}
	admin := createUser("ou-rbac-admin", "RBAC Admin")
	auditor := createUser("ou-rbac-auditor", "RBAC Auditor")
	catalogAdmin := createUser("ou-rbac-catalog", "RBAC Catalog")
	securityAdmin := createUser("ou-rbac-security", "RBAC Security")
	svc, err := service.NewAccessService(service.ServiceOptions{
		DB: database, Users: repos.users, Regions: repos.regions, Gateways: repos.gateways, Assets: repos.assets,
		Requests: repos.requests, Approvals: repos.approvals, Sessions: repos.sessions, SessionEvents: repos.sessionEvents,
		Audits: repos.audits, Outbox: repos.outbox, Gateway: gateway.UnavailableClient{}, Notifier: feishu.NoopNotifier{},
		AdminUserIDs: map[string]struct{}{admin.ID: {}}, Logger: zerolog.Nop(),
	})
	if err != nil {
		t.Fatalf("create RBAC service: %v", err)
	}
	auditorAssignment, err := svc.GrantRole(ctx, admin.ID, service.GrantRoleInput{UserID: auditor.ID, Role: string(authz.RoleAuditor)})
	if err != nil {
		t.Fatalf("grant auditor: %v", err)
	}
	if _, err := svc.GrantRole(ctx, admin.ID, service.GrantRoleInput{UserID: catalogAdmin.ID, Role: string(authz.RoleCatalogAdmin)}); err != nil {
		t.Fatalf("grant catalog admin: %v", err)
	}
	if _, err := svc.GrantRole(ctx, admin.ID, service.GrantRoleInput{UserID: securityAdmin.ID, Role: string(authz.RoleSecurityAdmin)}); err != nil {
		t.Fatalf("grant security admin: %v", err)
	}

	for _, check := range []struct {
		userID     string
		permission authz.Permission
	}{
		{auditor.ID, authz.PermissionAuditRead},
		{auditor.ID, authz.PermissionRequestManage},
		{catalogAdmin.ID, authz.PermissionCatalogManage},
		{securityAdmin.ID, authz.PermissionAuditRead},
		{admin.ID, authz.PermissionSessionOverride},
	} {
		if err := svc.Authorize(ctx, check.userID, check.permission); err != nil {
			t.Fatalf("authorize %s for %s: %v", check.userID, check.permission, err)
		}
	}
	for _, check := range []struct {
		userID     string
		permission authz.Permission
	}{
		{auditor.ID, authz.PermissionCatalogManage},
		{catalogAdmin.ID, authz.PermissionAuditRead},
		{securityAdmin.ID, authz.PermissionRoleManage},
		{securityAdmin.ID, authz.PermissionSessionOverride},
	} {
		if err := svc.Authorize(ctx, check.userID, check.permission); !errors.Is(err, service.ErrForbidden) {
			t.Fatalf("unexpected authorization %s for %s: %v", check.userID, check.permission, err)
		}
	}
	if _, err := svc.RevokeRole(ctx, admin.ID, auditorAssignment.ID); err != nil {
		t.Fatalf("revoke auditor: %v", err)
	}
	if err := svc.Authorize(ctx, auditor.ID, authz.PermissionAuditRead); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("revoked auditor authorization = %v", err)
	}
}

func TestGatewayCatalogExportEnforcesRBACAndGatewayState(t *testing.T) {
	database := openDatabase(t)
	seedLegacyRoles(t, database)
	ctx := context.Background()
	repos := newRepositories()
	createUser := func(openID, name string) domain.User {
		user, err := repos.users.Create(ctx, database, domain.User{ID: id.New(), FeishuOpenID: openID, Nickname: name, Status: domain.UserStatusActive})
		if err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		return user
	}
	admin := createUser("ou-catalog-admin", "Catalog Bootstrap Admin")
	catalogAdmin := createUser("ou-catalog-publisher", "Catalog Publisher")
	ordinaryUser := createUser("ou-catalog-user", "Catalog User")
	svc, err := service.NewAccessService(service.ServiceOptions{
		DB: database, Users: repos.users, Regions: repos.regions, Gateways: repos.gateways, Assets: repos.assets,
		Requests: repos.requests, Approvals: repos.approvals, Sessions: repos.sessions, SessionEvents: repos.sessionEvents,
		Audits: repos.audits, Outbox: repos.outbox, Gateway: gateway.UnavailableClient{}, Notifier: feishu.NoopNotifier{},
		AdminUserIDs: map[string]struct{}{admin.ID: {}}, Logger: zerolog.Nop(),
	})
	if err != nil {
		t.Fatalf("create catalog service: %v", err)
	}
	if _, err := svc.GrantRole(ctx, admin.ID, service.GrantRoleInput{UserID: catalogAdmin.ID, Role: string(authz.RoleCatalogAdmin)}); err != nil {
		t.Fatalf("grant catalog publisher role: %v", err)
	}

	region, err := repos.regions.Create(ctx, database, domain.Region{ID: id.New(), Code: "catalog-export", Name: "Catalog Export", Status: domain.ResourceStatusEnabled})
	if err != nil {
		t.Fatalf("create catalog export region: %v", err)
	}
	gatewayRecord, err := repos.gateways.Create(ctx, database, domain.Gateway{
		ID: id.New(), RegionID: region.ID, Name: "catalog-export-gateway",
		ManagementEndpoint: "https://catalog-export-gateway.example", PublicEndpoint: "catalog-export-gateway.example:443",
		Status: domain.ResourceStatusEnabled, MaxSessions: 10,
	})
	if err != nil {
		t.Fatalf("create catalog export gateway: %v", err)
	}
	disabledGateway, err := repos.gateways.Create(ctx, database, domain.Gateway{
		ID: id.New(), RegionID: region.ID, Name: "disabled-export-gateway",
		ManagementEndpoint: "https://disabled-export-gateway.example", PublicEndpoint: "disabled-export-gateway.example:443",
		Status: domain.ResourceStatusDisabled, MaxSessions: 10,
	})
	if err != nil {
		t.Fatalf("create disabled export gateway: %v", err)
	}
	source, externalID, generation := "primary-cmdb", "cmdb-postgres-01", id.New()
	asset, err := repos.assets.UpsertExternal(ctx, database, domain.Asset{
		ID: id.New(), RegionID: region.ID, GatewayID: gatewayRecord.ID, Name: "catalog-postgres",
		AssetType: "postgres", TargetCiphertext: "encrypted-target", RiskLevel: domain.RiskLevelSensitive,
		MaxTTLSeconds: 600, Status: domain.ResourceStatusEnabled,
		ExternalSource: &source, ExternalID: &externalID, SyncGeneration: &generation,
	})
	if err != nil {
		t.Fatalf("create catalog export asset: %v", err)
	}
	if err := repos.gateways.BindAsset(ctx, database, asset.ID, gatewayRecord.ID, 0); err != nil {
		t.Fatalf("bind catalog export asset: %v", err)
	}
	for _, port := range []int{6432, 5432} {
		if _, err := repos.assets.CreatePort(ctx, database, domain.AssetPort{ID: id.New(), AssetID: asset.ID, Port: port, Protocol: "tcp", Enabled: true}); err != nil {
			t.Fatalf("create catalog export port: %v", err)
		}
	}

	entries, err := svc.ListGatewayCatalog(ctx, catalogAdmin.ID, gatewayRecord.ID)
	if err != nil || len(entries) != 1 || entries[0].TargetID != asset.ID || entries[0].ExternalSource == nil || *entries[0].ExternalSource != source || entries[0].ExternalID == nil || *entries[0].ExternalID != externalID || len(entries[0].Ports) != 2 || entries[0].Ports[0] != 5432 || entries[0].Ports[1] != 6432 {
		t.Fatalf("catalog admin export: entries=%+v err=%v", entries, err)
	}
	if entries, err = svc.ListGatewayCatalog(ctx, admin.ID, gatewayRecord.ID); err != nil || len(entries) != 1 {
		t.Fatalf("bootstrap admin export: entries=%+v err=%v", entries, err)
	}
	if _, err := svc.ListGatewayCatalog(ctx, ordinaryUser.ID, gatewayRecord.ID); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("ordinary user catalog export error=%v", err)
	}
	if _, err := svc.ListGatewayCatalog(ctx, catalogAdmin.ID, "not-a-uuid"); !errors.Is(err, service.ErrValidation) {
		t.Fatalf("invalid gateway catalog export error=%v", err)
	}
	if _, err := svc.ListGatewayCatalog(ctx, catalogAdmin.ID, disabledGateway.ID); !errors.Is(err, service.ErrValidation) {
		t.Fatalf("disabled gateway catalog export error=%v", err)
	}
}

type staticCMDBClient struct {
	snapshot cmdb.Snapshot
}

func (c *staticCMDBClient) FetchSnapshot(context.Context) (cmdb.Snapshot, error) {
	return c.snapshot, nil
}

type testCMDBEncryptor struct{}

func (testCMDBEncryptor) Encrypt(_ context.Context, plaintext, _ []byte) (string, error) {
	return "encrypted:" + string(plaintext), nil
}

var _ cmdb.Client = (*staticCMDBClient)(nil)
var _ secretstore.Encryptor = testCMDBEncryptor{}

func stringPointer(value string) *string {
	return &value
}

type repositories struct {
	users         *repository.UserRepository
	regions       *repository.RegionRepository
	gateways      *repository.GatewayRepository
	assets        *repository.AssetRepository
	requests      *repository.AccessRequestRepository
	approvals     *repository.ApprovalRepository
	sessions      *repository.SessionRepository
	sessionEvents *repository.SessionEventRepository
	audits        *repository.AuditEventRepository
	outbox        *repository.OutboxEventRepository
}

func newRepositories() repositories {
	return repositories{
		users: repository.NewUserRepository(), regions: repository.NewRegionRepository(),
		gateways: repository.NewGatewayRepository(), assets: repository.NewAssetRepository(),
		requests: repository.NewAccessRequestRepository(), approvals: repository.NewApprovalRepository(),
		sessions: repository.NewSessionRepository(), sessionEvents: repository.NewSessionEventRepository(),
		audits: repository.NewAuditEventRepository(), outbox: repository.NewOutboxEventRepository(),
	}
}

type lifecycleController struct {
	mu     sync.Mutex
	starts int
	stops  int
	modes  map[string]string
}

func (c *lifecycleController) Start(_ context.Context, request gateway.CreateSessionRequest) (gateway.CreateSessionResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.starts++
	now := time.Now().UTC()
	expires := now.Add(time.Duration(request.TTLSeconds) * time.Second)
	if request.ExpiresAt != nil {
		expires = *request.ExpiresAt
	}
	if c.modes == nil {
		c.modes = make(map[string]string)
	}
	c.modes[request.SessionID] = request.ConnectionMode
	return gateway.CreateSessionResponse{
		ConnectionMode: request.ConnectionMode,
		SessionID:      request.SessionID, Status: "running", ProcessID: "e2e-process",
		ListenerPort: 20000, ExternalPort: 32001, ExposureMode: "kubernetes_nodeport",
		ExposureRef: "kubernetes/service/access-gateway/ag-e2e",
		StartedAt:   now, ExpiresAt: expires,
	}, nil
}

func (c *lifecycleController) Stop(_ context.Context, sessionID string) (gateway.CloseSessionResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stops++
	return gateway.CloseSessionResponse{SessionID: sessionID, Status: "closed", ClosedAt: time.Now().UTC()}, nil
}

func (c *lifecycleController) Status(_ context.Context, sessionID string) (gateway.SessionStatusResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return gateway.SessionStatusResponse{SessionID: sessionID, Status: "running", ConnectionMode: c.modes[sessionID]}, nil
}

func (c *lifecycleController) startCalls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.starts
}

func (c *lifecycleController) stopCalls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stops
}

type memoryStateStore struct {
	mu       sync.Mutex
	sessions []gatewayagent.SessionRecord
}

func (s *memoryStateStore) Load(context.Context) ([]gatewayagent.SessionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]gatewayagent.SessionRecord(nil), s.sessions...), nil
}

func (s *memoryStateStore) Save(_ context.Context, sessions []gatewayagent.SessionRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions = append([]gatewayagent.SessionRecord(nil), sessions...)
	return nil
}

func openDatabase(t *testing.T) *sql.DB {
	return openDatabaseAtVersion(t, 0)
}

func openDatabaseAtVersion(t *testing.T, version int64) *sql.DB {
	t.Helper()
	baseDSN := os.Getenv(testDSNEnv)
	if baseDSN == "" {
		t.Skipf("%s is not set", testDSNEnv)
	}
	admin, err := sql.Open("pgx", baseDSN)
	if err != nil {
		t.Fatalf("open integration admin database: %v", err)
	}
	admin.SetMaxOpenConns(1)
	admin.SetMaxIdleConns(1)
	admin.SetConnMaxLifetime(5 * time.Minute)
	if err := admin.PingContext(context.Background()); err != nil {
		_ = admin.Close()
		t.Fatalf("ping integration admin database: %v", err)
	}

	schema := "access_gateway_flow_" + strings.ReplaceAll(id.New(), "-", "")
	if _, err := admin.ExecContext(context.Background(), `CREATE SCHEMA `+schema); err != nil {
		_ = admin.Close()
		t.Fatalf("create integration schema: %v", err)
	}
	var database *sql.DB
	t.Cleanup(func() {
		if database != nil {
			_ = database.Close()
		}
		if _, err := admin.ExecContext(context.Background(), `DROP SCHEMA IF EXISTS `+schema+` CASCADE`); err != nil {
			t.Errorf("drop integration schema: %v", err)
		}
		_ = admin.Close()
	})

	isolatedDSN, err := integrationDSNWithSearchPath(baseDSN, schema)
	if err != nil {
		t.Fatalf("build isolated integration DSN: %v", err)
	}
	t.Setenv(testDSNEnv, isolatedDSN)
	database, err = sql.Open("pgx", isolatedDSN)
	if err != nil {
		t.Fatalf("open isolated integration database: %v", err)
	}
	database.SetMaxOpenConns(4)
	database.SetMaxIdleConns(4)
	database.SetConnMaxLifetime(5 * time.Minute)
	if err := database.PingContext(context.Background()); err != nil {
		database.Close()
		t.Fatalf("ping database: %v", err)
	}
	migrateSchemaTo(t, database, version)
	return database
}

func resetSchema(t *testing.T, database *sql.DB) {
	migrateSchemaTo(t, database, 0)
}

func migrateSchemaTo(t *testing.T, database *sql.DB, version int64) {
	t.Helper()
	goose.SetBaseFS(migrations.GooseFS())
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatalf("configure migration dialect: %v", err)
	}
	var err error
	if version > 0 {
		err = goose.UpToContext(context.Background(), database, ".", version)
	} else {
		err = goose.UpContext(context.Background(), database, ".")
	}
	if err != nil {
		t.Fatalf("apply migrations with goose: %v", err)
	}
}

func integrationDSNWithSearchPath(dsn, schema string) (string, error) {
	if !strings.Contains(dsn, "://") {
		return strings.TrimSpace(dsn) + " search_path=" + schema, nil
	}
	parsed, err := url.Parse(dsn)
	if err != nil {
		return "", fmt.Errorf("parse PostgreSQL DSN: %w", err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

var _ gatewayagent.Controller = (*lifecycleController)(nil)
var _ gatewayagent.StateStore = (*memoryStateStore)(nil)

func TestMain(m *testing.M) {
	if os.Getenv(testDSNEnv) == "" {
		fmt.Fprintf(os.Stderr, "skipping backend integration tests: %s is not set\n", testDSNEnv)
		os.Exit(0)
	}
	os.Exit(m.Run())
}
