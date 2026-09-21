//go:build integration

package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pressly/goose/v3"

	_ "github.com/srex-run/access-gateway/internal/db"

	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/migrations"
)

const testDSNEnv = "POSTGRES_TEST_DSN"

func testContext() context.Context { return context.Background() }

func TestMain(m *testing.M) {
	if os.Getenv(testDSNEnv) == "" {
		fmt.Fprintf(os.Stderr, "skipping repository integration tests: %s is not set\n", testDSNEnv)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func openIntegrationDB(t *testing.T) *sql.DB {
	t.Helper()
	baseDSN := os.Getenv(testDSNEnv)
	admin, err := sql.Open("pgx", baseDSN)
	if err != nil {
		t.Fatalf("open integration admin database: %v", err)
	}
	admin.SetMaxOpenConns(1)
	admin.SetMaxIdleConns(1)
	admin.SetConnMaxLifetime(5 * time.Minute)
	if err := admin.PingContext(testContext()); err != nil {
		_ = admin.Close()
		t.Fatalf("ping integration admin database: %v", err)
	}

	schema := "access_gateway_repository_" + strings.ReplaceAll(id.New(), "-", "")
	if _, err := admin.ExecContext(testContext(), `CREATE SCHEMA `+schema); err != nil {
		_ = admin.Close()
		t.Fatalf("create integration schema: %v", err)
	}
	var database *sql.DB
	t.Cleanup(func() {
		if database != nil {
			_ = database.Close()
		}
		if _, err := admin.ExecContext(testContext(), `DROP SCHEMA IF EXISTS `+schema+` CASCADE`); err != nil {
			t.Errorf("drop integration schema: %v", err)
		}
		_ = admin.Close()
	})

	isolatedDSN, err := integrationDSNWithSearchPath(baseDSN, schema)
	if err != nil {
		t.Fatalf("build isolated integration DSN: %v", err)
	}
	database, err = sql.Open("pgx", isolatedDSN)
	if err != nil {
		t.Fatalf("open isolated integration database: %v", err)
	}
	database.SetMaxOpenConns(4)
	database.SetMaxIdleConns(4)
	database.SetConnMaxLifetime(5 * time.Minute)
	if err := database.PingContext(testContext()); err != nil {
		database.Close()
		t.Fatalf("ping database: %v", err)
	}
	applyMigration(t, database)
	return database
}

func applyMigration(t *testing.T, database *sql.DB) {
	t.Helper()
	goose.SetBaseFS(migrations.GooseFS())
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatalf("configure migration dialect: %v", err)
	}
	if err := goose.UpContext(testContext(), database, "."); err != nil {
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

func TestGatewayAuthSecretReferenceAgainstPostgres(t *testing.T) {
	database := openIntegrationDB(t)
	ctx := testContext()
	regions := NewRegionRepository()
	gateways := NewGatewayRepository()
	region, err := regions.Create(ctx, database, domain.Region{
		ID: id.New(), Code: "gateway-auth", Name: "Gateway Auth", Status: domain.ResourceStatusEnabled,
	})
	if err != nil {
		t.Fatalf("create region: %v", err)
	}
	gatewayRecord, err := gateways.Create(ctx, database, domain.Gateway{
		ID: id.New(), RegionID: region.ID, Name: "gw-auth", ManagementEndpoint: "https://manage.example",
		PublicEndpoint: "gateway.example:443", Status: domain.ResourceStatusEnabled, MaxSessions: 1,
	})
	if err != nil {
		t.Fatalf("create gateway: %v", err)
	}
	gatewayRecord, err = gateways.UpdateAuthSecretRef(ctx, database, gatewayRecord.ID, "gateway-cn-east-1")
	if err != nil || gatewayRecord.AuthSecretRef == nil || *gatewayRecord.AuthSecretRef != "gateway-cn-east-1" {
		t.Fatalf("update gateway auth secret reference: got=%+v err=%v", gatewayRecord, err)
	}
	loaded, err := gateways.GetByID(ctx, database, gatewayRecord.ID)
	if err != nil || loaded.AuthSecretRef == nil || *loaded.AuthSecretRef != "gateway-cn-east-1" {
		t.Fatalf("load gateway auth secret reference: got=%+v err=%v", loaded, err)
	}
}

func TestRepositoriesAgainstPostgres(t *testing.T) {
	database := openIntegrationDB(t)
	ctx := testContext()
	users := NewUserRepository()
	regions := NewRegionRepository()
	gateways := NewGatewayRepository()
	assets := NewAssetRepository()
	requests := NewAccessRequestRepository()
	approvals := NewApprovalRepository()
	sessions := NewSessionRepository()
	sessionEvents := NewSessionEventRepository()
	audits := NewAuditEventRepository()
	outbox := NewOutboxEventRepository()
	callbacks := NewCallbackEventRepository()
	tokenDeliveries := NewSessionTokenDeliveryRepository()
	oauthStates := NewOAuthStateRepository()

	userID := id.New()
	approverID := id.New()
	user, err := users.Create(ctx, database, domain.User{
		ID: userID, FeishuOpenID: "ou_applicant", Nickname: "Applicant", Status: domain.UserStatusActive,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	assertUser(t, user, userID, "ou_applicant", "Applicant", domain.UserStatusActive)
	approver, err := users.Create(ctx, database, domain.User{
		ID: approverID, FeishuOpenID: "ou_approver", Nickname: "Approver", Status: domain.UserStatusActive,
	})
	if err != nil {
		t.Fatalf("create approver: %v", err)
	}
	assertUser(t, approver, approverID, "ou_approver", "Approver", domain.UserStatusActive)
	if got, err := users.GetByID(ctx, database, userID); err != nil || got.FeishuOpenID != "ou_applicant" || got.Nickname != "Applicant" {
		t.Fatalf("get user: got=%+v err=%v", got, err)
	}
	if got, err := users.GetByFeishuOpenID(ctx, database, "ou_approver"); err != nil || got.ID != approverID {
		t.Fatalf("get user by open id: got=%+v err=%v", got, err)
	}
	if err := users.UpdateStatus(ctx, database, approverID, domain.UserStatusInactive); err != nil {
		t.Fatalf("update user status: %v", err)
	}
	if _, err := users.UpsertByFeishu(ctx, database, domain.User{ID: id.New(), FeishuOpenID: "ou_approver", Nickname: "Approver Updated", Status: domain.UserStatusActive}); err != nil {
		t.Fatalf("upsert user: %v", err)
	}
	approver, err = users.GetByID(ctx, database, approverID)
	if err != nil || approver.Nickname != "Approver Updated" || approver.Status != domain.UserStatusInactive {
		t.Fatalf("upsert result: got=%+v err=%v", approver, err)
	}

	region, err := regions.Create(ctx, database, domain.Region{ID: id.New(), Code: "cn-sh-prod", Name: "Shanghai Production", Status: domain.ResourceStatusEnabled})
	if err != nil {
		t.Fatalf("create region: %v", err)
	}
	if got, err := regions.GetByID(ctx, database, region.ID); err != nil || got.Code != "cn-sh-prod" || got.Name != "Shanghai Production" {
		t.Fatalf("get region: got=%+v err=%v", got, err)
	}
	if got, err := regions.GetByCode(ctx, database, region.Code); err != nil || got.ID != region.ID {
		t.Fatalf("get region by code: got=%+v err=%v", got, err)
	}
	regionsList, err := regions.ListActive(ctx, database)
	if err != nil || len(regionsList) != 1 || regionsList[0].ID != region.ID {
		t.Fatalf("list regions: got=%+v err=%v", regionsList, err)
	}

	gateway, err := gateways.Create(ctx, database, domain.Gateway{ID: id.New(), RegionID: region.ID, Name: "gw-sh-01", ManagementEndpoint: "https://manage.example", PublicEndpoint: "gw.example:443", Status: domain.ResourceStatusEnabled, MaxSessions: 2})
	if err != nil {
		t.Fatalf("create gateway: %v", err)
	}
	if got, err := gateways.GetByID(ctx, database, gateway.ID); err != nil || got.Name != "gw-sh-01" || got.RegionID != region.ID || got.ManagementEndpoint != "https://manage.example" || got.MaxSessions != 2 || got.LastHeartbeatAt != nil {
		t.Fatalf("get gateway: got=%+v err=%v", got, err)
	}
	enabled, err := gateways.ListEnabled(ctx, database)
	if err != nil || len(enabled) != 1 || enabled[0].ID != gateway.ID || enabled[0].RegionID != region.ID || enabled[0].Name != "gw-sh-01" || enabled[0].ManagementEndpoint != "https://manage.example" || enabled[0].PublicEndpoint != "gw.example:443" || enabled[0].AuthSecretRef != nil || enabled[0].Status != domain.ResourceStatusEnabled || enabled[0].MaxSessions != 2 || enabled[0].LastHeartbeatAt != nil || enabled[0].CreatedAt.IsZero() || enabled[0].UpdatedAt.IsZero() {
		t.Fatalf("list enabled gateways: got=%+v err=%v", enabled, err)
	}
	healthy, err := gateways.ListHealthyByRegion(ctx, database, region.ID, time.Now().UTC().Add(-time.Minute))
	if err != nil || len(healthy) != 0 {
		t.Fatalf("gateway without heartbeat was healthy: got=%+v err=%v", healthy, err)
	}
	heartbeatStart := time.Now().UTC().Add(-time.Second)
	gateway, err = gateways.RecordHeartbeat(ctx, database, gateway.ID)
	if err != nil || gateway.ID == "" || gateway.RegionID != region.ID || gateway.Name != "gw-sh-01" || gateway.ManagementEndpoint != "https://manage.example" || gateway.PublicEndpoint != "gw.example:443" || gateway.AuthSecretRef != nil || gateway.Status != domain.ResourceStatusEnabled || gateway.MaxSessions != 2 || gateway.LastHeartbeatAt == nil || gateway.LastHeartbeatAt.Before(heartbeatStart) || gateway.CreatedAt.IsZero() || gateway.UpdatedAt.IsZero() {
		t.Fatalf("record gateway heartbeat: got=%+v err=%v", gateway, err)
	}
	healthy, err = gateways.ListHealthyByRegion(ctx, database, region.ID, heartbeatStart)
	if err != nil || len(healthy) != 1 || healthy[0].ID != gateway.ID || healthy[0].LastHeartbeatAt == nil {
		t.Fatalf("list healthy gateways: got=%+v err=%v", healthy, err)
	}
	healthy, err = gateways.ListHealthyByRegion(ctx, database, region.ID, time.Now().UTC().Add(time.Minute))
	if err != nil || len(healthy) != 0 {
		t.Fatalf("stale gateway was healthy: got=%+v err=%v", healthy, err)
	}
	if _, err := gateways.RecordHeartbeat(ctx, database, id.New()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing gateway heartbeat error = %v", err)
	}
	gateway, err = gateways.UpdateCapacity(ctx, database, gateway.ID, 1)
	if err != nil || gateway.MaxSessions != 1 {
		t.Fatalf("update gateway capacity: got=%+v err=%v", gateway, err)
	}
	gateway, err = gateways.RecordHealth(ctx, database, gateway.ID, 1)
	if err != nil || gateway.MaxSessions != 1 || gateway.LastHeartbeatAt == nil {
		t.Fatalf("record gateway health: got=%+v err=%v", gateway, err)
	}

	asset, err := assets.Create(ctx, database, domain.Asset{ID: id.New(), RegionID: region.ID, GatewayID: gateway.ID, Name: "order-db-primary", AssetType: "mysql", TargetCiphertext: "ciphertext", RiskLevel: domain.RiskLevelSensitive, MaxTTLSeconds: 3600, Status: domain.ResourceStatusEnabled})
	if err != nil {
		t.Fatalf("create asset: %v", err)
	}
	if err := gateways.BindAsset(ctx, database, asset.ID, gateway.ID, 0); err != nil {
		t.Fatalf("bind primary asset gateway: %v", err)
	}
	backupGateway, err := gateways.Create(ctx, database, domain.Gateway{
		ID: id.New(), RegionID: region.ID, Name: "gw-sh-02", ManagementEndpoint: "https://manage-backup.example",
		PublicEndpoint: "gw-backup.example:443", Status: domain.ResourceStatusEnabled, MaxSessions: 1,
	})
	if err != nil {
		t.Fatalf("create backup gateway: %v", err)
	}
	backupGateway, err = gateways.RecordHeartbeat(ctx, database, backupGateway.ID)
	if err != nil || backupGateway.LastHeartbeatAt == nil {
		t.Fatalf("record backup heartbeat: got=%+v err=%v", backupGateway, err)
	}
	if err := gateways.BindAsset(ctx, database, asset.ID, backupGateway.ID, 10); err != nil {
		t.Fatalf("bind backup asset gateway: %v", err)
	}
	routingCutoff := time.Now().UTC().Add(-time.Minute)
	candidates, err := gateways.ListAvailableForAsset(ctx, database, asset.ID, id.New(), &routingCutoff)
	if err != nil || len(candidates) != 2 || candidates[0].ID != gateway.ID || candidates[1].ID != backupGateway.ID {
		t.Fatalf("list asset gateway candidates: got=%+v err=%v", candidates, err)
	}
	if got, err := assets.GetByID(ctx, database, asset.ID); err != nil || got.Name != "order-db-primary" || got.TargetCiphertext != "ciphertext" || got.MaxTTLSeconds != 3600 || got.ExternalSource != nil || got.ExternalID != nil || got.SyncGeneration != nil || got.LastSyncedAt != nil {
		t.Fatalf("get asset: got=%+v err=%v", got, err)
	}
	assetList, err := assets.ListActiveByRegion(ctx, database, region.ID)
	if err != nil || len(assetList) != 1 || assetList[0].ID != asset.ID {
		t.Fatalf("list assets: got=%+v err=%v", assetList, err)
	}
	lockTx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin advisory lock transaction: %v", err)
	}
	if err := sessions.LockApplicantAssetPort(ctx, lockTx, userID, asset.ID, 3306); err != nil {
		_ = lockTx.Rollback()
		t.Fatalf("lock applicant asset port: %v", err)
	}
	if err := lockTx.Rollback(); err != nil {
		t.Fatalf("rollback advisory lock transaction: %v", err)
	}
	port, err := assets.CreatePort(ctx, database, domain.AssetPort{ID: id.New(), AssetID: asset.ID, Port: 3306, Protocol: "tcp", Enabled: true})
	if err != nil {
		t.Fatalf("create port: %v", err)
	}
	if got, err := assets.GetPort(ctx, database, asset.ID, 3306, "tcp"); err != nil || got.Port != 3306 || got.Protocol != "tcp" || !got.Enabled {
		t.Fatalf("get port: got=%+v err=%v", got, err)
	}
	ports, err := assets.ListPorts(ctx, database, asset.ID)
	if err != nil || len(ports) != 1 || ports[0].ID != port.ID {
		t.Fatalf("list ports: got=%+v err=%v", ports, err)
	}
	approverRecord, err := assets.CreateApprover(ctx, database, domain.AssetApprover{ID: id.New(), AssetID: asset.ID, UserID: approverID, ApprovalLevel: 1, Role: "owner", Enabled: true})
	if err != nil {
		t.Fatalf("create approver: %v", err)
	}
	approverList, err := assets.ListApprovers(ctx, database, asset.ID)
	if err != nil || len(approverList) != 1 || approverList[0].ID != approverRecord.ID || approverList[0].Role != "owner" {
		t.Fatalf("list approvers: got=%+v err=%v", approverList, err)
	}

	request, err := requests.Create(ctx, database, domain.AccessRequest{ID: id.New(), ApplicantID: userID, AssetID: asset.ID, TargetPort: 3306, Reason: "investigate latency", TicketNo: stringPtrTest("INC-1"), Emergency: false, TTLSeconds: 3600, Status: domain.AccessRequestPendingApproval, IdempotencyKey: "idem-request-1"})
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	if request.Reason != "investigate latency" || request.TicketNo == nil || *request.TicketNo != "INC-1" || request.Status != domain.AccessRequestPendingApproval {
		t.Fatalf("request fields: %+v", request)
	}
	if got, err := requests.GetByID(ctx, database, request.ID); err != nil || got.IdempotencyKey != "idem-request-1" {
		t.Fatalf("get request: got=%+v err=%v", got, err)
	}
	if got, err := requests.GetByIdempotencyKey(ctx, database, "idem-request-1"); err != nil || got.ID != request.ID {
		t.Fatalf("get idempotent request: got=%+v err=%v", got, err)
	}
	expiredRequests, err := requests.ListApprovalExpired(ctx, database, time.Now().UTC().Add(time.Hour), 10)
	if err != nil {
		t.Fatalf("list expired approval requests: %v", err)
	}
	foundExpiredCandidate := false
	for _, candidate := range expiredRequests {
		if candidate.ID == request.ID {
			foundExpiredCandidate = true
			break
		}
	}
	if !foundExpiredCandidate {
		t.Fatalf("new pending request was not returned by approval expiry query: %+v", expiredRequests)
	}
	requestList, err := requests.ListByApplicant(ctx, database, userID, 10, 0)
	if err != nil || len(requestList) != 1 || requestList[0].ID != request.ID {
		t.Fatalf("list requests: got=%+v err=%v", requestList, err)
	}
	request, err = requests.TransitionStatus(ctx, database, request.ID, domain.AccessRequestPendingApproval, domain.AccessRequestApproved)
	if err != nil || request.Status != domain.AccessRequestApproved {
		t.Fatalf("transition request: got=%+v err=%v", request, err)
	}

	approval, err := approvals.Create(ctx, database, domain.Approval{ID: id.New(), RequestID: request.ID, ApproverID: approverID, ApprovalLevel: 1})
	if err != nil {
		t.Fatalf("create approval: %v", err)
	}
	if got, err := approvals.GetByID(ctx, database, approval.ID); err != nil || got.ApproverID != approverID || got.Decision != nil {
		t.Fatalf("get approval: got=%+v err=%v", got, err)
	}
	approvalList, err := approvals.ListByRequest(ctx, database, request.ID)
	if err != nil || len(approvalList) != 1 || approvalList[0].ID != approval.ID {
		t.Fatalf("list approvals: got=%+v err=%v", approvalList, err)
	}
	comment := "approved for incident"
	approval, err = approvals.Decide(ctx, database, approval.ID, approverID, domain.ApprovalApproved, &comment)
	if err != nil || approval.Decision == nil || *approval.Decision != domain.ApprovalApproved || approval.Comment == nil || *approval.Comment != comment || approval.DecidedAt == nil {
		t.Fatalf("decide approval: got=%+v err=%v", approval, err)
	}

	session, err := sessions.Create(ctx, database, domain.Session{ID: id.New(), RequestID: request.ID, GatewayID: gateway.ID, Status: domain.SessionProvisioning, Version: 0})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	provisioning, err := sessions.ListProvisioning(ctx, database, 10)
	if err != nil || len(provisioning) != 1 || provisioning[0].ID != session.ID {
		t.Fatalf("list provisioning sessions: got=%+v err=%v", provisioning, err)
	}
	if got, err := sessions.GetByRequestID(ctx, database, request.ID); err != nil || got.ID != session.ID || got.Status != domain.SessionProvisioning {
		t.Fatalf("get session by request: got=%+v err=%v", got, err)
	}
	session, err = sessions.ClaimProvisioning(ctx, database, session.ID, 0, time.Now().UTC().Add(-time.Minute))
	if err != nil || session.Version != 1 || session.Status != domain.SessionProvisioning {
		t.Fatalf("claim provisioning session: got=%+v err=%v", session, err)
	}
	if _, err := sessions.ClaimProvisioning(ctx, database, session.ID, 0, time.Now().UTC()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("duplicate provisioning claim error = %v", err)
	}
	started := time.Now().UTC().Add(-time.Minute)
	expires := time.Now().UTC().Add(time.Minute)
	session, err = sessions.MarkRunning(ctx, database, session.ID, session.Version, "hash-value", "proc-1", started, expires)
	if err != nil || session.Status != domain.SessionRunning || session.TokenHash == nil || *session.TokenHash != "hash-value" || session.RemoteProcessID == nil || *session.RemoteProcessID != "proc-1" || session.ExpiresAt == nil {
		t.Fatalf("mark running: got=%+v err=%v", session, err)
	}
	delivery, err := tokenDeliveries.Create(ctx, database, domain.SessionTokenDelivery{
		SessionID: session.ID, TokenCiphertext: strings.Repeat("encrypted", 8), ExpiresAt: expires,
	})
	if err != nil || delivery.SessionID != session.ID || delivery.TokenCiphertext == "" || delivery.CreatedAt.IsZero() {
		t.Fatalf("create token delivery: got=%+v err=%v", delivery, err)
	}
	if available, getErr := tokenDeliveries.GetAvailable(ctx, database, session.ID, time.Now().UTC()); getErr != nil || available.SessionID != session.ID {
		t.Fatalf("get token delivery: got=%+v err=%v", available, getErr)
	}
	consumeResults := make(chan error, 2)
	for range 2 {
		go func() {
			_, consumeErr := tokenDeliveries.Consume(ctx, database, session.ID, time.Now().UTC())
			consumeResults <- consumeErr
		}()
	}
	consumed, missing := 0, 0
	for range 2 {
		consumeErr := <-consumeResults
		switch {
		case consumeErr == nil:
			consumed++
		case errors.Is(consumeErr, ErrNotFound):
			missing++
		default:
			t.Fatalf("concurrent token consume: %v", consumeErr)
		}
	}
	if consumed != 1 || missing != 1 {
		t.Fatalf("concurrent token consume results: consumed=%d missing=%d", consumed, missing)
	}
	if _, err := tokenDeliveries.Create(ctx, database, domain.SessionTokenDelivery{
		SessionID: session.ID, TokenCiphertext: strings.Repeat("expired", 8), ExpiresAt: time.Now().UTC().Add(-time.Second),
	}); err != nil {
		t.Fatalf("create expired token delivery: %v", err)
	}
	if deleted, err := tokenDeliveries.DeleteExpired(ctx, database, time.Now().UTC(), 10); err != nil || deleted != 1 {
		t.Fatalf("delete expired token deliveries: deleted=%d err=%v", deleted, err)
	}

	oauthExpiry := time.Now().UTC().Add(time.Minute).Truncate(time.Microsecond)
	oauthState, err := oauthStates.Create(ctx, database, domain.OAuthState{
		StateHash: strings.Repeat("a", 64), ExpiresAt: oauthExpiry,
	})
	if err != nil || oauthState.StateHash != strings.Repeat("a", 64) || !oauthState.ExpiresAt.Equal(oauthExpiry) || oauthState.CreatedAt.IsZero() {
		t.Fatalf("create OAuth state: got=%+v err=%v", oauthState, err)
	}
	oauthResults := make(chan struct {
		consumed bool
		err      error
	}, 2)
	for range 2 {
		go func() {
			value, consumeErr := oauthStates.Consume(ctx, database, strings.Repeat("a", 64))
			oauthResults <- struct {
				consumed bool
				err      error
			}{value, consumeErr}
		}()
	}
	oauthConsumed := 0
	for range 2 {
		result := <-oauthResults
		if result.err != nil {
			t.Fatalf("concurrent OAuth state consume: %v", result.err)
		}
		if result.consumed {
			oauthConsumed++
		}
	}
	if oauthConsumed != 1 {
		t.Fatalf("concurrent OAuth state consume count = %d", oauthConsumed)
	}
	now := time.Now().UTC()
	for index, stateHash := range []string{strings.Repeat("b", 64), strings.Repeat("c", 64)} {
		if _, err := oauthStates.Create(ctx, database, domain.OAuthState{StateHash: stateHash, ExpiresAt: now.Add(-time.Duration(index+1) * time.Minute)}); err != nil {
			t.Fatalf("create expired OAuth state: %v", err)
		}
	}
	activeStateHash := strings.Repeat("d", 64)
	if _, err := oauthStates.Create(ctx, database, domain.OAuthState{StateHash: activeStateHash, ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatalf("create active OAuth state: %v", err)
	}
	for iteration, expected := range []int{1, 1, 0} {
		deleted, deleteErr := oauthStates.DeleteExpired(ctx, database, now, 1)
		if deleteErr != nil || deleted != expected {
			t.Fatalf("delete expired OAuth states iteration %d: deleted=%d want=%d err=%v", iteration, deleted, expected, deleteErr)
		}
	}
	if consumed, err := oauthStates.Consume(ctx, database, activeStateHash); err != nil || !consumed {
		t.Fatalf("expired-state cleanup removed active OAuth state: consumed=%v err=%v", consumed, err)
	}
	for _, invalidLimit := range []int{0, 10001} {
		if _, err := oauthStates.DeleteExpired(ctx, database, now, invalidLimit); !errors.Is(err, ErrConstraint) {
			t.Fatalf("invalid OAuth cleanup limit %d: %v", invalidLimit, err)
		}
	}
	candidates, err = gateways.ListAvailableForAsset(ctx, database, asset.ID, id.New(), &routingCutoff)
	if err != nil || len(candidates) != 1 || candidates[0].ID != backupGateway.ID {
		t.Fatalf("full gateway was not excluded: got=%+v err=%v", candidates, err)
	}
	active, err := sessions.FindActiveByApplicantAssetPort(ctx, database, userID, asset.ID, 3306)
	if err != nil || active.ID != session.ID {
		t.Fatalf("find active session: got=%+v err=%v", active, err)
	}
	// Make the running session eligible for the expiry scanner.
	if _, err := database.ExecContext(ctx, `UPDATE sessions SET expires_at = NOW() - INTERVAL '1 second' WHERE id = $1`, session.ID); err != nil {
		t.Fatalf("expire session: %v", err)
	}
	expired, err := sessions.ListExpired(ctx, database, 10)
	if err != nil || len(expired) != 1 || expired[0].ID != session.ID {
		t.Fatalf("list expired sessions: got=%+v err=%v", expired, err)
	}
	session, err = sessions.BeginRevoke(ctx, database, session.ID)
	if err != nil || session.Status != domain.SessionRevoking {
		t.Fatalf("begin revoke: got=%+v err=%v", session, err)
	}
	if err := sessions.MarkClosed(ctx, database, session.ID, domain.SessionExpired); err != nil {
		t.Fatalf("mark closed: %v", err)
	}
	routingRequest, err := requests.Create(ctx, database, domain.AccessRequest{ID: id.New(), ApplicantID: userID, AssetID: asset.ID, TargetPort: 3306, Reason: "capacity routing", TTLSeconds: 300, Status: domain.AccessRequestApproved, IdempotencyKey: "idem-routing-claim"})
	if err != nil {
		t.Fatalf("create routing request: %v", err)
	}
	routingSession, err := sessions.Create(ctx, database, domain.Session{ID: id.New(), RequestID: routingRequest.ID, GatewayID: backupGateway.ID, Status: domain.SessionProvisioning})
	if err != nil {
		t.Fatalf("create routing session: %v", err)
	}
	routingTx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin routing transaction: %v", err)
	}
	if err := gateways.LockCapacity(ctx, routingTx, gateway.ID); err != nil {
		_ = routingTx.Rollback()
		t.Fatalf("lock gateway capacity: %v", err)
	}
	routingSession, err = sessions.ClaimProvisioningOnGateway(ctx, routingTx, routingSession.ID, 0, time.Now().UTC().Add(-time.Minute), gateway.ID, asset.ID, &routingCutoff)
	if err != nil {
		_ = routingTx.Rollback()
		t.Fatalf("claim routed provisioning session: %v", err)
	}
	if err := routingTx.Commit(); err != nil {
		t.Fatalf("commit routing transaction: %v", err)
	}
	if routingSession.GatewayID != gateway.ID || routingSession.Version != 1 {
		t.Fatalf("routed provisioning session = %+v", routingSession)
	}
	if err := sessions.MarkProvisionFailed(ctx, database, routingSession.ID, routingSession.Version, "integration cleanup"); err != nil {
		t.Fatalf("release routed provisioning capacity: %v", err)
	}

	callbackID := "evt-integration-1"
	claimedCallback, err := callbacks.Claim(ctx, database, callbackID, time.Minute)
	if err != nil || !claimedCallback {
		t.Fatalf("claim callback: claimed=%v err=%v", claimedCallback, err)
	}
	claimedCallback, err = callbacks.Claim(ctx, database, callbackID, time.Minute)
	if err != nil || claimedCallback {
		t.Fatalf("duplicate callback claim: claimed=%v err=%v", claimedCallback, err)
	}
	if err := callbacks.Release(ctx, database, callbackID); err != nil {
		t.Fatalf("release callback: %v", err)
	}
	claimedCallback, err = callbacks.Claim(ctx, database, callbackID, time.Minute)
	if err != nil || !claimedCallback {
		t.Fatalf("claim released callback: claimed=%v err=%v", claimedCallback, err)
	}
	if err := callbacks.MarkProcessed(ctx, database, callbackID); err != nil {
		t.Fatalf("mark callback processed: %v", err)
	}
	claimedCallback, err = callbacks.Claim(ctx, database, callbackID, time.Nanosecond)
	if err != nil || claimedCallback {
		t.Fatalf("processed callback reclaim: claimed=%v err=%v", claimedCallback, err)
	}
	staleCallbackID := "evt-integration-stale"
	if claimed, claimErr := callbacks.Claim(ctx, database, staleCallbackID, time.Second); claimErr != nil || !claimed {
		t.Fatalf("claim stale callback fixture: claimed=%v err=%v", claimed, claimErr)
	}
	if _, err := database.ExecContext(ctx, `UPDATE callback_events SET claimed_at = NOW() - INTERVAL '2 seconds' WHERE event_id = $1`, staleCallbackID); err != nil {
		t.Fatalf("age callback claim: %v", err)
	}
	if claimed, claimErr := callbacks.Claim(ctx, database, staleCallbackID, time.Second); claimErr != nil || !claimed {
		t.Fatalf("reclaim stale callback: claimed=%v err=%v", claimed, claimErr)
	}

	eventMetadata := map[string]any{"source": "integration", "count": float64(1)}
	if err := sessionEvents.Append(ctx, database, domain.SessionEvent{ID: id.New(), SessionID: session.ID, EventType: "session.connected", ActorType: "gateway", ActorID: stringPtrTest(userID), Metadata: eventMetadata}); err != nil {
		t.Fatalf("append session event: %v", err)
	}
	events, err := sessionEvents.ListBySession(ctx, database, session.ID, 10, 0)
	if err != nil || len(events) != 1 || events[0].EventType != "session.connected" || events[0].Metadata["source"] != "integration" {
		t.Fatalf("list session events: got=%+v err=%v", events, err)
	}
	if err := audits.Append(ctx, database, domain.AuditEvent{ID: id.New(), EventType: "session.connected", ActorType: "gateway", SubjectUserID: stringPtrTest(userID), RequestID: stringPtrTest(request.ID), SessionID: stringPtrTest(session.ID), RegionID: stringPtrTest(region.ID), AssetID: stringPtrTest(asset.ID), TargetPort: intPtrTest(3306), SourceIP: stringPtrTest("10.0.0.1"), ClientVersion: stringPtrTest("1.0.0"), Result: stringPtrTest("success"), Metadata: map[string]any{"ok": true}}); err != nil {
		t.Fatalf("append audit event: %v", err)
	}
	auditEvents, err := audits.List(ctx, database, domain.AuditFilter{SessionID: session.ID, Limit: 10})
	if err != nil || len(auditEvents) != 1 || auditEvents[0].EventType != "session.connected" || auditEvents[0].SourceIP == nil || *auditEvents[0].SourceIP != "10.0.0.1" || auditEvents[0].TargetPort == nil || *auditEvents[0].TargetPort != 3306 || auditEvents[0].Metadata["ok"] != true {
		t.Fatalf("list audit events: got=%+v err=%v", auditEvents, err)
	}
	if _, err := database.ExecContext(ctx, `UPDATE audit_events SET reason = 'tampered' WHERE id = $1`, auditEvents[0].ID); err == nil {
		t.Fatal("audit update unexpectedly succeeded")
	}
	if _, err := database.ExecContext(ctx, `DELETE FROM audit_events WHERE id = $1`, auditEvents[0].ID); err == nil {
		t.Fatal("audit delete unexpectedly succeeded")
	}
	payload := map[string]any{"request_id": request.ID}
	outboxID := id.New()
	if err := outbox.Create(ctx, database, domain.OutboxEvent{ID: outboxID, AggregateType: "access_request", AggregateID: request.ID, EventType: "notify", Payload: payload, Status: "pending", RetryCount: 0}); err != nil {
		t.Fatalf("create outbox event: %v", err)
	}
	outboxValue, err := outbox.GetByID(ctx, database, outboxID)
	if err != nil || outboxValue.ID != outboxID || outboxValue.AggregateType != "access_request" || outboxValue.AggregateID != request.ID || outboxValue.Payload["request_id"] != request.ID || outboxValue.EventType != "notify" || outboxValue.Status != "pending" || outboxValue.RetryCount != 0 || outboxValue.NextRetryAt != nil || outboxValue.CreatedAt.IsZero() || outboxValue.ProcessedAt != nil {
		t.Fatalf("get outbox event: got=%+v err=%v", outboxValue, err)
	}
	claimed, err := outbox.ClaimPending(ctx, database, 10, time.Minute)
	if err != nil || len(claimed) != 1 || claimed[0].ID != outboxID || claimed[0].Status != "processing" || claimed[0].NextRetryAt == nil {
		t.Fatalf("claim outbox event: got=%+v err=%v", claimed, err)
	}
	if err := outbox.MarkProcessed(ctx, database, outboxID); err != nil {
		t.Fatalf("mark outbox processed: %v", err)
	}
	outboxValue, err = outbox.GetByID(ctx, database, outboxID)
	if err != nil || outboxValue.Status != "processed" || outboxValue.NextRetryAt != nil || outboxValue.ProcessedAt == nil {
		t.Fatalf("processed outbox event: got=%+v err=%v", outboxValue, err)
	}

	retryOutboxID := id.New()
	if err := outbox.Create(ctx, database, domain.OutboxEvent{ID: retryOutboxID, AggregateType: "session", AggregateID: session.ID, EventType: "revoke", Payload: map[string]any{"session_id": session.ID}, Status: "pending"}); err != nil {
		t.Fatalf("create retry outbox event: %v", err)
	}
	claimed, err = outbox.ClaimPending(ctx, database, 10, 30*time.Second)
	if err != nil || len(claimed) != 1 || claimed[0].ID != retryOutboxID {
		t.Fatalf("claim retry outbox event: got=%+v err=%v", claimed, err)
	}
	retryAt := time.Now().UTC().Add(time.Minute)
	if err := outbox.Reschedule(ctx, database, retryOutboxID, retryAt, false); err != nil {
		t.Fatalf("reschedule outbox event: %v", err)
	}
	outboxValue, err = outbox.GetByID(ctx, database, retryOutboxID)
	if err != nil || outboxValue.Status != "pending" || outboxValue.RetryCount != 1 || outboxValue.NextRetryAt == nil || outboxValue.ProcessedAt != nil {
		t.Fatalf("rescheduled outbox event: got=%+v err=%v", outboxValue, err)
	}
	queueStats, err := outbox.QueueStats(ctx, database)
	if err != nil || queueStats.PendingCount != 1 || queueStats.OldestAgeSeconds < 0 {
		t.Fatalf("outbox queue stats: got=%+v err=%v", queueStats, err)
	}

	secondRequest, err := requests.Create(ctx, database, domain.AccessRequest{ID: id.New(), ApplicantID: userID, AssetID: asset.ID, TargetPort: 3306, Reason: "second request", TTLSeconds: 300, Status: domain.AccessRequestPendingApproval, IdempotencyKey: "idem-request-2"})
	if err != nil {
		t.Fatalf("create second request: %v", err)
	}
	secondApproval, err := approvals.Create(ctx, database, domain.Approval{ID: id.New(), RequestID: secondRequest.ID, ApproverID: approverID, ApprovalLevel: 1})
	if err != nil {
		t.Fatalf("create second approval: %v", err)
	}
	pendingApprovals, err := approvals.ListPendingByApprover(ctx, database, approverID, 10, 0)
	if err != nil || len(pendingApprovals) != 1 || pendingApprovals[0].ID != secondApproval.ID {
		t.Fatalf("list pending approvals: got=%+v err=%v", pendingApprovals, err)
	}
	if _, err := requests.Cancel(ctx, database, secondRequest.ID); err != nil {
		t.Fatalf("cancel request: %v", err)
	}
	if got, err := requests.GetByID(ctx, database, secondRequest.ID); err != nil || got.Status != domain.AccessRequestCancelled {
		t.Fatalf("cancelled request: got=%+v err=%v", got, err)
	}

	failedSession, err := sessions.Create(ctx, database, domain.Session{ID: id.New(), RequestID: secondRequest.ID, GatewayID: gateway.ID, Status: domain.SessionProvisioning, Version: 0})
	if err != nil {
		t.Fatalf("create failed session: %v", err)
	}
	if err := sessions.MarkProvisionFailed(ctx, database, failedSession.ID, 0, "gateway unavailable"); err != nil {
		t.Fatalf("mark provision failed: %v", err)
	}
	if got, err := sessions.GetByID(ctx, database, failedSession.ID); err != nil || got.Status != domain.SessionFailed || got.FailureReason == nil || *got.FailureReason != "gateway unavailable" {
		t.Fatalf("failed session: got=%+v err=%v", got, err)
	}

	revokeRequest, err := requests.Create(ctx, database, domain.AccessRequest{ID: id.New(), ApplicantID: userID, AssetID: asset.ID, TargetPort: 3306, Reason: "revoke failure", TTLSeconds: 300, Status: domain.AccessRequestApproved, IdempotencyKey: "idem-request-3"})
	if err != nil {
		t.Fatalf("create revoke request: %v", err)
	}
	revokeSession, err := sessions.Create(ctx, database, domain.Session{ID: id.New(), RequestID: revokeRequest.ID, GatewayID: gateway.ID, Status: domain.SessionProvisioning})
	if err != nil {
		t.Fatalf("create revoke session: %v", err)
	}
	revokeSession, err = sessions.MarkRunning(ctx, database, revokeSession.ID, 0, "revoke-hash", "revoke-proc", time.Now().UTC(), time.Now().UTC().Add(time.Minute))
	if err != nil {
		t.Fatalf("mark revoke session running: %v", err)
	}
	runtimeFailureReason := "gateway_process_exited"
	runtimeFailed, err := sessions.MarkRuntimeTerminated(ctx, database, revokeSession.ID, domain.SessionFailed, &runtimeFailureReason)
	if err != nil || runtimeFailed.Status != domain.SessionFailed || runtimeFailed.ClosedAt == nil || runtimeFailed.FailureReason == nil || *runtimeFailed.FailureReason != runtimeFailureReason {
		t.Fatalf("mark runtime terminated: got=%+v err=%v", runtimeFailed, err)
	}

	runtimeRequest, err := requests.Create(ctx, database, domain.AccessRequest{ID: id.New(), ApplicantID: userID, AssetID: asset.ID, TargetPort: 3306, Reason: "revoke failure", TTLSeconds: 300, Status: domain.AccessRequestApproved, IdempotencyKey: "idem-request-4"})
	if err != nil {
		t.Fatalf("create runtime revoke request: %v", err)
	}
	revokeSession, err = sessions.Create(ctx, database, domain.Session{ID: id.New(), RequestID: runtimeRequest.ID, GatewayID: gateway.ID, Status: domain.SessionProvisioning})
	if err != nil {
		t.Fatalf("create runtime revoke session: %v", err)
	}
	revokeSession, err = sessions.MarkRunning(ctx, database, revokeSession.ID, 0, "revoke-hash", "revoke-proc", time.Now().UTC(), time.Now().UTC().Add(time.Minute))
	if err != nil {
		t.Fatalf("mark runtime revoke session running: %v", err)
	}
	revocable, err := sessions.ListRevocationsToQueueByApplicant(ctx, database, userID, 10)
	if err != nil || len(revocable) != 1 || revocable[0].ID != revokeSession.ID {
		t.Fatalf("list revocable applicant sessions: got=%+v err=%v", revocable, err)
	}
	if _, err := sessions.BeginRevoke(ctx, database, revokeSession.ID); err != nil {
		t.Fatalf("begin failed revoke: %v", err)
	}
	if err := sessions.MarkRevokeFailed(ctx, database, revokeSession.ID, "gateway timeout"); err != nil {
		t.Fatalf("mark revoke failed: %v", err)
	}
	if err := sessions.MarkManualIntervention(ctx, database, revokeSession.ID, "automatic retries exhausted"); err != nil {
		t.Fatalf("mark manual intervention: %v", err)
	}
	manual, err := sessions.GetByID(ctx, database, revokeSession.ID)
	if err != nil || manual.Status != domain.SessionManualIntervention || manual.FailureReason == nil || *manual.FailureReason != "automatic retries exhausted" {
		t.Fatalf("manual intervention session: got=%+v err=%v", manual, err)
	}
	queued, err := outbox.CreateIfNoActive(ctx, database, domain.OutboxEvent{
		ID: id.New(), AggregateType: "session", AggregateID: revokeSession.ID,
		EventType: "session.revoke", Payload: map[string]any{"session_id": revokeSession.ID}, Status: "pending",
	})
	if err != nil || !queued {
		t.Fatalf("queue active session revocation: queued=%v err=%v", queued, err)
	}
	revocable, err = sessions.ListRevocationsToQueueByApplicant(ctx, database, userID, 10)
	if err != nil || len(revocable) != 0 {
		t.Fatalf("already queued revocation was returned: got=%+v err=%v", revocable, err)
	}

	bindings, err := gateways.ListAssetBindings(ctx, database, asset.ID)
	if err != nil || len(bindings) != 2 || bindings[0].AssetID != asset.ID || bindings[0].GatewayID != gateway.ID || !bindings[0].Enabled {
		t.Fatalf("list asset bindings: got=%+v err=%v", bindings, err)
	}
	updatedBinding, err := gateways.UpdateAssetBinding(ctx, database, asset.ID, backupGateway.ID, false, 20)
	if err != nil || updatedBinding.Enabled || updatedBinding.Priority != 20 {
		t.Fatalf("update asset binding: got=%+v err=%v", updatedBinding, err)
	}
	updatedBinding, err = gateways.UpdateAssetBinding(ctx, database, asset.ID, backupGateway.ID, true, 10)
	if err != nil || !updatedBinding.Enabled || updatedBinding.Priority != 10 {
		t.Fatalf("re-enable asset binding: got=%+v err=%v", updatedBinding, err)
	}
	if _, err := gateways.DisableAssetBindingsExcept(ctx, database, asset.ID, []string{gateway.ID}); err != nil {
		t.Fatalf("disable stale bindings: %v", err)
	}
	if err := gateways.BindAsset(ctx, database, asset.ID, backupGateway.ID, 10); err != nil {
		t.Fatalf("restore backup binding: %v", err)
	}

	stalePort, err := assets.CreatePort(ctx, database, domain.AssetPort{ID: id.New(), AssetID: asset.ID, Port: 5432, Protocol: "tcp", Enabled: true})
	if err != nil {
		t.Fatalf("create stale port: %v", err)
	}
	if count, err := assets.DisablePortsExcept(ctx, database, asset.ID, []int{3306}); err != nil || count != 1 {
		t.Fatalf("disable stale port: count=%d err=%v", count, err)
	}
	if _, err := assets.GetPort(ctx, database, asset.ID, stalePort.Port, stalePort.Protocol); !errors.Is(err, ErrNotFound) {
		t.Fatalf("disabled stale port lookup error=%v", err)
	}
	upsertGeneration := id.New()
	externalSource, externalID := "test-cmdb", "cmdb-asset-1"
	external, err := assets.UpsertExternal(ctx, database, domain.Asset{
		ID: id.New(), RegionID: region.ID, GatewayID: gateway.ID, Name: "external-db", AssetType: "postgres",
		TargetCiphertext: "agk1.test", RiskLevel: domain.RiskLevelNormal, MaxTTLSeconds: 600, Status: domain.ResourceStatusEnabled,
		ExternalSource: &externalSource, ExternalID: &externalID, SyncGeneration: &upsertGeneration,
	})
	if err != nil || external.ExternalSource == nil || *external.ExternalSource != externalSource || external.ExternalID == nil || *external.ExternalID != externalID || external.SyncGeneration == nil || *external.SyncGeneration != upsertGeneration || external.LastSyncedAt == nil {
		t.Fatalf("upsert external asset: got=%+v err=%v", external, err)
	}
	if got, err := assets.GetByExternalIdentity(ctx, database, externalSource, externalID); err != nil || got.ID != external.ID {
		t.Fatalf("get external asset: got=%+v err=%v", got, err)
	}
	if _, err := assets.DisableExternalMissing(ctx, database, externalSource, id.New()); err != nil {
		t.Fatalf("disable missing external assets: %v", err)
	}
	if got, err := assets.GetByID(ctx, database, external.ID); err != nil || got.Status != domain.ResourceStatusDisabled {
		t.Fatalf("missing external asset status: got=%+v err=%v", got, err)
	}
	lockTx, err = database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin CMDB lock transaction: %v", err)
	}
	locked, err := assets.TryExternalSyncLock(ctx, lockTx, "lock-test")
	if err != nil || !locked {
		_ = lockTx.Rollback()
		t.Fatalf("acquire CMDB lock: locked=%v err=%v", locked, err)
	}
	secondLockTx, err := database.BeginTx(ctx, nil)
	if err != nil {
		_ = lockTx.Rollback()
		t.Fatalf("begin second CMDB lock transaction: %v", err)
	}
	locked, err = assets.TryExternalSyncLock(ctx, secondLockTx, "lock-test")
	if err != nil || locked {
		_ = secondLockTx.Rollback()
		_ = lockTx.Rollback()
		t.Fatalf("duplicate CMDB lock: locked=%v err=%v", locked, err)
	}
	if err := secondLockTx.Rollback(); err != nil {
		t.Fatalf("rollback second CMDB lock transaction: %v", err)
	}
	if err := lockTx.Commit(); err != nil {
		t.Fatalf("commit CMDB lock transaction: %v", err)
	}

	roleRepo := NewRoleRepository()
	assignment, err := roleRepo.Create(ctx, database, domain.RoleAssignment{ID: id.New(), UserID: userID, Role: "auditor", GrantedBy: approverID})
	if err != nil || assignment.UserID != userID || assignment.Role != "auditor" || assignment.RevokedAt != nil || assignment.CreatedAt.IsZero() {
		t.Fatalf("create role assignment: got=%+v err=%v", assignment, err)
	}
	roleList, err := roleRepo.ListActiveByUser(ctx, database, userID)
	if err != nil || len(roleList) != 1 || roleList[0].ID != assignment.ID {
		t.Fatalf("list role assignments: got=%+v err=%v", roleList, err)
	}
	assignment, err = roleRepo.Revoke(ctx, database, assignment.ID)
	if err != nil || assignment.RevokedAt == nil {
		t.Fatalf("revoke role assignment: got=%+v err=%v", assignment, err)
	}
	if roleList, err = roleRepo.ListActiveByUser(ctx, database, userID); err != nil || len(roleList) != 0 {
		t.Fatalf("revoked role assignment still active: got=%+v err=%v", roleList, err)
	}

}

func TestGatewayCatalogEntriesAgainstPostgres(t *testing.T) {
	database := openIntegrationDB(t)
	ctx := testContext()
	regions := NewRegionRepository()
	gateways := NewGatewayRepository()
	assets := NewAssetRepository()

	region, err := regions.Create(ctx, database, domain.Region{
		ID: id.New(), Code: "catalog-region", Name: "Catalog Region", Status: domain.ResourceStatusEnabled,
	})
	if err != nil {
		t.Fatalf("create catalog region: %v", err)
	}
	gatewayRecord, err := gateways.Create(ctx, database, domain.Gateway{
		ID: id.New(), RegionID: region.ID, Name: "catalog-gateway",
		ManagementEndpoint: "https://catalog-gateway.example", PublicEndpoint: "catalog-gateway.example:443",
		Status: domain.ResourceStatusEnabled, MaxSessions: 10,
	})
	if err != nil {
		t.Fatalf("create catalog gateway: %v", err)
	}
	disabledGateway, err := gateways.Create(ctx, database, domain.Gateway{
		ID: id.New(), RegionID: region.ID, Name: "disabled-catalog-gateway",
		ManagementEndpoint: "https://disabled-catalog-gateway.example", PublicEndpoint: "disabled-catalog-gateway.example:443",
		Status: domain.ResourceStatusDisabled, MaxSessions: 10,
	})
	if err != nil {
		t.Fatalf("create disabled catalog gateway: %v", err)
	}

	createAsset := func(name string, status domain.ResourceStatus, externalSource, externalID *string) domain.Asset {
		t.Helper()
		value := domain.Asset{
			ID: id.New(), RegionID: region.ID, GatewayID: gatewayRecord.ID, Name: name,
			AssetType: "postgres", TargetCiphertext: "encrypted-target", RiskLevel: domain.RiskLevelNormal,
			MaxTTLSeconds: 600, Status: status,
		}
		var created domain.Asset
		var createErr error
		if externalSource == nil {
			created, createErr = assets.Create(ctx, database, value)
		} else {
			generation := id.New()
			value.ExternalSource = externalSource
			value.ExternalID = externalID
			value.SyncGeneration = &generation
			created, createErr = assets.UpsertExternal(ctx, database, value)
		}
		if createErr != nil {
			t.Fatalf("create catalog asset %s: %v", name, createErr)
		}
		return created
	}
	createPort := func(assetID string, port int, enabled bool) {
		t.Helper()
		if _, createErr := assets.CreatePort(ctx, database, domain.AssetPort{
			ID: id.New(), AssetID: assetID, Port: port, Protocol: "tcp", Enabled: enabled,
		}); createErr != nil {
			t.Fatalf("create catalog port %d: %v", port, createErr)
		}
	}
	bind := func(assetID, gatewayID string) {
		t.Helper()
		if bindErr := gateways.BindAsset(ctx, database, assetID, gatewayID, 0); bindErr != nil {
			t.Fatalf("bind catalog asset %s: %v", assetID, bindErr)
		}
	}

	source, externalID := "primary-cmdb", "cmdb-db-001"
	external := createAsset("external", domain.ResourceStatusEnabled, &source, &externalID)
	bind(external.ID, gatewayRecord.ID)
	createPort(external.ID, 6432, true)
	createPort(external.ID, 5432, true)
	createPort(external.ID, 15432, false)

	manual := createAsset("manual", domain.ResourceStatusEnabled, nil, nil)
	bind(manual.ID, gatewayRecord.ID)
	createPort(manual.ID, 3306, true)

	disabledAsset := createAsset("disabled-asset", domain.ResourceStatusDisabled, nil, nil)
	bind(disabledAsset.ID, gatewayRecord.ID)
	createPort(disabledAsset.ID, 7001, true)

	disabledBinding := createAsset("disabled-binding", domain.ResourceStatusEnabled, nil, nil)
	bind(disabledBinding.ID, gatewayRecord.ID)
	createPort(disabledBinding.ID, 7002, true)
	if _, err := gateways.UpdateAssetBinding(ctx, database, disabledBinding.ID, gatewayRecord.ID, false, 0); err != nil {
		t.Fatalf("disable catalog binding: %v", err)
	}

	disabledPort := createAsset("disabled-port", domain.ResourceStatusEnabled, nil, nil)
	bind(disabledPort.ID, gatewayRecord.ID)
	createPort(disabledPort.ID, 7003, false)

	bind(external.ID, disabledGateway.ID)
	entries, err := gateways.ListCatalogEntries(ctx, database, gatewayRecord.ID)
	if err != nil {
		t.Fatalf("list gateway catalog entries: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("catalog entry count=%d entries=%+v", len(entries), entries)
	}
	byTarget := make(map[string]domain.GatewayCatalogEntry, len(entries))
	for _, entry := range entries {
		byTarget[entry.TargetID] = entry
	}
	externalEntry, ok := byTarget[external.ID]
	if !ok || externalEntry.TargetID != external.ID || externalEntry.ExternalSource == nil || *externalEntry.ExternalSource != source || externalEntry.ExternalID == nil || *externalEntry.ExternalID != externalID || len(externalEntry.Ports) != 2 || externalEntry.Ports[0] != 5432 || externalEntry.Ports[1] != 6432 {
		t.Fatalf("external catalog fields: %+v", externalEntry)
	}
	manualEntry, ok := byTarget[manual.ID]
	if !ok || manualEntry.TargetID != manual.ID || manualEntry.ExternalSource != nil || manualEntry.ExternalID != nil || len(manualEntry.Ports) != 1 || manualEntry.Ports[0] != 3306 {
		t.Fatalf("manual catalog fields: %+v", manualEntry)
	}

	disabledEntries, err := gateways.ListCatalogEntries(ctx, database, disabledGateway.ID)
	if err != nil || len(disabledEntries) != 0 {
		t.Fatalf("disabled gateway catalog: entries=%+v err=%v", disabledEntries, err)
	}
	if _, err := gateways.UpdateStatus(ctx, database, gatewayRecord.ID, domain.ResourceStatusMaint); err != nil {
		t.Fatalf("put catalog gateway in maintenance: %v", err)
	}
	entries, err = gateways.ListCatalogEntries(ctx, database, gatewayRecord.ID)
	if err != nil || len(entries) != 0 {
		t.Fatalf("maintenance gateway catalog: entries=%+v err=%v", entries, err)
	}
}

func TestDirectAccessEvidenceAgainstPostgres(t *testing.T) {
	database := openIntegrationDB(t)
	ctx := testContext()
	users := NewUserRepository()
	regions := NewRegionRepository()
	gateways := NewGatewayRepository()
	assets := NewAssetRepository()
	requests := NewAccessRequestRepository()
	sessions := NewSessionRepository()
	evidence := NewAccessEvidenceRepository()

	user, err := users.Create(ctx, database, domain.User{
		ID: id.New(), FeishuOpenID: "ou_evidence_user", Nickname: "Evidence User", Status: domain.UserStatusActive,
	})
	if err != nil {
		t.Fatalf("create evidence user: %v", err)
	}
	region, err := regions.Create(ctx, database, domain.Region{
		ID: id.New(), Code: "evidence-region", Name: "Evidence Region", Status: domain.ResourceStatusEnabled,
	})
	if err != nil {
		t.Fatalf("create evidence region: %v", err)
	}
	gatewayRecord, err := gateways.Create(ctx, database, domain.Gateway{
		ID: id.New(), RegionID: region.ID, Name: "evidence-gateway",
		ManagementEndpoint: "https://evidence-gateway.example", PublicEndpoint: "evidence-gateway.example",
		Status: domain.ResourceStatusEnabled, MaxSessions: 10,
	})
	if err != nil {
		t.Fatalf("create evidence gateway: %v", err)
	}
	asset, err := assets.Create(ctx, database, domain.Asset{
		ID: id.New(), RegionID: region.ID, GatewayID: gatewayRecord.ID, Name: "evidence-postgres",
		AssetType: "postgres", TargetCiphertext: "encrypted-target", RiskLevel: domain.RiskLevelSensitive,
		MaxTTLSeconds: 600, Status: domain.ResourceStatusEnabled,
	})
	if err != nil {
		t.Fatalf("create evidence asset: %v", err)
	}
	sourceIP, targetAccount := "203.0.113.25", "readonly"
	request, err := requests.Create(ctx, database, domain.AccessRequest{
		ID: id.New(), ApplicantID: user.ID, AssetID: asset.ID, TargetPort: 5432,
		SourceIP: &sourceIP, TargetAccount: &targetAccount, Reason: "audit evidence",
		TTLSeconds: 300, Status: domain.AccessRequestApproved, IdempotencyKey: "evidence-request",
	})
	if err != nil {
		t.Fatalf("create evidence request: %v", err)
	}
	if request.SourceIP == nil || *request.SourceIP != sourceIP || request.TargetAccount == nil || *request.TargetAccount != targetAccount {
		t.Fatalf("direct request fields: %+v", request)
	}
	session, err := sessions.Create(ctx, database, domain.Session{
		ID: id.New(), RequestID: request.ID, GatewayID: gatewayRecord.ID, Status: domain.SessionProvisioning,
		ConnectionMode: "native",
	})
	if err != nil {
		t.Fatalf("create evidence session: %v", err)
	}
	startedAt := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	expiresAt := startedAt.Add(5 * time.Minute)
	session, err = sessions.MarkDirectRunning(
		ctx, database, session.ID, 0, "tcp-20000", 20000, 32001,
		"kubernetes_nodeport", "kubernetes/service/access-gateway/ag-evidence", startedAt, expiresAt,
		"", "",
	)
	if err != nil {
		t.Fatalf("mark direct session running: %v", err)
	}
	if session.Status != domain.SessionRunning || session.ConnectionMode != "native" || session.TunnelClientPublicKey != "" || session.TunnelServerCertificate != "" || session.TokenHash != nil || session.RemoteProcessID == nil || *session.RemoteProcessID != "tcp-20000" ||
		session.ListenerPort == nil || *session.ListenerPort != 20000 || session.ExternalPort == nil || *session.ExternalPort != 32001 ||
		session.ExposureMode == nil || *session.ExposureMode != "kubernetes_nodeport" || session.ExposureRef == nil ||
		*session.ExposureRef != "kubernetes/service/access-gateway/ag-evidence" || session.StartedAt == nil || session.ExpiresAt == nil {
		t.Fatalf("direct session fields: %+v", session)
	}

	connectionEventID := id.New()
	connectionID := id.New()
	backendIP := "10.20.0.15"
	backendPort := 45678
	result := "success"
	connectedAt := startedAt.Add(time.Second)
	connection := domain.GatewayConnectionEvent{
		EventID: connectionEventID, ConnectionID: connectionID, SessionID: session.ID,
		EventType: "backend_connected", SourceIP: &sourceIP, BackendSourceIP: &backendIP,
		BackendSourcePort: &backendPort, Result: &result, OccurredAt: connectedAt,
	}
	inserted, err := evidence.AppendConnectionEvent(ctx, database, connection)
	if err != nil || !inserted {
		t.Fatalf("append connection event: inserted=%v err=%v", inserted, err)
	}
	inserted, err = evidence.AppendConnectionEvent(ctx, database, connection)
	if err != nil || inserted {
		t.Fatalf("replay connection event: inserted=%v err=%v", inserted, err)
	}
	storedConnection, err := evidence.GetConnectionEvent(ctx, database, connectionEventID)
	if err != nil || storedConnection.EventID != connectionEventID || storedConnection.ConnectionID != connectionID || storedConnection.SessionID != session.ID ||
		storedConnection.EventType != "backend_connected" || storedConnection.SourceIP == nil || *storedConnection.SourceIP != sourceIP ||
		storedConnection.BackendSourceIP == nil || *storedConnection.BackendSourceIP != backendIP || storedConnection.BackendSourcePort == nil ||
		*storedConnection.BackendSourcePort != backendPort || storedConnection.BytesUp != nil || storedConnection.BytesDown != nil ||
		storedConnection.DurationMS != nil || storedConnection.Result == nil || *storedConnection.Result != result || storedConnection.Reason != nil ||
		!storedConnection.OccurredAt.Equal(connectedAt) || storedConnection.CreatedAt.IsZero() {
		t.Fatalf("connection event fields: value=%+v err=%v", storedConnection, err)
	}
	correlatedConnectionID, correlatedSessionID, correlatedAccount, err := evidence.CorrelateOperation(
		ctx, database, asset.ID, 5432, backendIP, backendPort, connectedAt.Add(time.Millisecond),
	)
	if err != nil || correlatedConnectionID != connectionID || correlatedSessionID != session.ID || correlatedAccount != targetAccount {
		t.Fatalf("correlate operation: connection=%s session=%s account=%s err=%v", correlatedConnectionID, correlatedSessionID, correlatedAccount, err)
	}
	if _, _, _, err := evidence.CorrelateOperation(ctx, database, asset.ID, 5432, backendIP, backendPort+1, connectedAt); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing correlation error = %v", err)
	}

	operationEventID := id.New()
	fingerprint := "sha256:catalog-read"
	normalized := "SELECT FROM pg_catalog.pg_tables"
	objectName := "pg_catalog.pg_tables"
	durationMS := int64(12)
	operationAt := connectedAt.Add(time.Millisecond)
	operation := domain.OperationAuditEvent{
		EventID: operationEventID, ConnectionID: &connectionID, SessionID: &session.ID,
		Protocol: "postgresql", AssetID: asset.ID, TargetPort: 5432, ActualAccount: targetAccount,
		OperationType: "select", StatementFingerprint: &fingerprint, NormalizedOperation: &normalized,
		ObjectName: &objectName, Result: result, DurationMS: &durationMS, BackendSourceIP: backendIP,
		BackendSourcePort: backendPort, SourceRecordID: "pgaudit:evidence:1", CorrelationStatus: "matched",
		OccurredAt: operationAt, Metadata: map[string]any{"collector": "pgaudit", "sequence": float64(1)},
	}
	inserted, err = evidence.AppendOperationEvent(ctx, database, operation)
	if err != nil || !inserted {
		t.Fatalf("append operation event: inserted=%v err=%v", inserted, err)
	}
	inserted, err = evidence.AppendOperationEvent(ctx, database, operation)
	if err != nil || inserted {
		t.Fatalf("replay operation event: inserted=%v err=%v", inserted, err)
	}
	storedOperation, err := evidence.GetOperationEvent(ctx, database, operationEventID)
	if err != nil || storedOperation.EventID != operationEventID || storedOperation.ConnectionID == nil || *storedOperation.ConnectionID != connectionID ||
		storedOperation.SessionID == nil || *storedOperation.SessionID != session.ID || storedOperation.Protocol != "postgresql" ||
		storedOperation.AssetID != asset.ID || storedOperation.TargetPort != 5432 || storedOperation.ActualAccount != targetAccount ||
		storedOperation.OperationType != "select" || storedOperation.StatementFingerprint == nil || *storedOperation.StatementFingerprint != fingerprint ||
		storedOperation.NormalizedOperation == nil || *storedOperation.NormalizedOperation != normalized || storedOperation.ObjectName == nil ||
		*storedOperation.ObjectName != objectName || storedOperation.Result != result || storedOperation.DurationMS == nil ||
		*storedOperation.DurationMS != durationMS || storedOperation.BackendSourceIP != backendIP || storedOperation.BackendSourcePort != backendPort ||
		storedOperation.SourceRecordID != "pgaudit:evidence:1" || storedOperation.CorrelationStatus != "matched" ||
		!storedOperation.OccurredAt.Equal(operationAt) || storedOperation.Metadata["collector"] != "pgaudit" || storedOperation.CreatedAt.IsZero() {
		t.Fatalf("operation event fields: value=%+v err=%v", storedOperation, err)
	}
	from, to := connectedAt, operationAt.Add(time.Second)
	operations, err := evidence.ListOperationEvents(ctx, database, domain.OperationAuditFilter{
		SubjectUserID: user.ID, ActualAccount: targetAccount, AssetID: asset.ID, SessionID: session.ID,
		Protocol: "postgresql", Result: result, CorrelationStatus: "matched", From: &from, To: &to, Limit: 10,
	})
	if err != nil || len(operations) != 1 || operations[0].EventID != operationEventID {
		t.Fatalf("filtered operation events: values=%+v err=%v", operations, err)
	}
	if values, listErr := evidence.ListOperationEvents(ctx, database, domain.OperationAuditFilter{ActualAccount: "other", Limit: 10}); listErr != nil || len(values) != 0 {
		t.Fatalf("empty operation filter: values=%+v err=%v", values, listErr)
	}
	if _, err := evidence.GetConnectionEvent(ctx, database, id.New()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing connection event error = %v", err)
	}
	if _, err := evidence.GetOperationEvent(ctx, database, id.New()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing operation event error = %v", err)
	}
	foreignConnection := connection
	foreignConnection.EventID = id.New()
	foreignConnection.SessionID = id.New()
	if _, err := evidence.AppendConnectionEvent(ctx, database, foreignConnection); !errors.Is(err, ErrConstraint) {
		t.Fatalf("connection foreign-key error = %v", err)
	}
	invalidOperation := operation
	invalidOperation.EventID = id.New()
	invalidOperation.Protocol = "http"
	if _, err := evidence.AppendOperationEvent(ctx, database, invalidOperation); !errors.Is(err, ErrConstraint) {
		t.Fatalf("operation check-constraint error = %v", err)
	}
	if _, err := database.ExecContext(ctx, `UPDATE gateway_connection_events SET result = 'tampered' WHERE event_id = $1`, connectionEventID); err == nil {
		t.Fatal("connection evidence update unexpectedly succeeded")
	}
	if _, err := database.ExecContext(ctx, `DELETE FROM gateway_connection_events WHERE event_id = $1`, connectionEventID); err == nil {
		t.Fatal("connection evidence delete unexpectedly succeeded")
	}
	if _, err := database.ExecContext(ctx, `UPDATE operation_audit_events SET result = 'tampered' WHERE event_id = $1`, operationEventID); err == nil {
		t.Fatal("operation evidence update unexpectedly succeeded")
	}
	if _, err := database.ExecContext(ctx, `DELETE FROM operation_audit_events WHERE event_id = $1`, operationEventID); err == nil {
		t.Fatal("operation evidence delete unexpectedly succeeded")
	}
}

func assertUser(t *testing.T, value domain.User, idValue, openID, name string, status domain.UserStatus) {
	t.Helper()
	if value.ID != idValue || value.FeishuOpenID != openID || value.Nickname != name || value.Status != status || value.CreatedAt.IsZero() || value.UpdatedAt.IsZero() {
		t.Fatalf("user fields: %+v", value)
	}
}

func stringPtrTest(value string) *string { return &value }
func intPtrTest(value int) *int          { return &value }
