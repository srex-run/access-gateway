//go:build integration

package integration_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/srex-run/access-gateway/internal/cloudassets"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/gateway"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/secretstore"
	"github.com/srex-run/access-gateway/internal/service"
)

type cloudDiscoveryFunc func(context.Context, string, cloudassets.Credentials, string, []string) ([]cloudassets.Instance, error)

func (f cloudDiscoveryFunc) Discover(ctx context.Context, provider string, credentials cloudassets.Credentials, region string, ids []string) ([]cloudassets.Instance, error) {
	return f(ctx, provider, credentials, region, ids)
}

type cloudFixture struct {
	db      *sql.DB
	svc     *service.AccessService
	repos   repositories
	cloud   *repository.CloudRepository
	actor   domain.User
	account domain.CloudAccount
	input   domain.CloudSyncInput
}

func newCloudFixture(t *testing.T, discover cloudDiscoveryFunc) cloudFixture {
	t.Helper()
	database := openDatabase(t)
	repos := newRepositories()
	ctx := context.Background()
	actor, err := repos.users.Create(ctx, database, domain.User{ID: id.New(), Nickname: "Cloud Admin", Status: domain.UserStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	region, err := repos.regions.Create(ctx, database, domain.Region{ID: id.New(), Name: "Production", Code: "cloud-test", Status: domain.ResourceStatusEnabled})
	if err != nil {
		t.Fatal(err)
	}
	gatewayRecord, err := repos.gateways.Create(ctx, database, domain.Gateway{ID: id.New(), RegionID: region.ID, Name: "Private gateway", ManagementEndpoint: "https://gateway.test", PublicEndpoint: "gateway.test", Status: domain.ResourceStatusEnabled, MaxSessions: 100})
	if err != nil {
		t.Fatal(err)
	}
	cipher, _ := secretstore.NewAESGCM("test-cloud", make([]byte, 32))
	svc, err := service.NewAccessService(service.ServiceOptions{DB: database, Users: repos.users, Regions: repos.regions, Gateways: repos.gateways,
		PublicURL: "https://access-gateway.srex.run", GatewayBaseURL: "https://gateway.test",
		Assets: repos.assets, Requests: repos.requests, Approvals: repos.approvals, Sessions: repos.sessions, SessionEvents: repos.sessionEvents,
		Audits: repos.audits, Outbox: repos.outbox, Gateway: gateway.UnavailableClient{}, Logger: zerolog.Nop(),
		AdminUserIDs: map[string]struct{}{actor.ID: {}}, CloudCipher: cipher, CloudDiscoverer: discover})
	if err != nil {
		t.Fatal(err)
	}
	account, err := svc.SaveCloudAccount(ctx, actor.ID, "", service.CloudAccountInput{Name: "Cloud production", Provider: "aliyun", Enabled: true, AccessKey: "test-ak", SecretKey: "test-sk"})
	if err != nil {
		t.Fatal(err)
	}
	return cloudFixture{db: database, svc: svc, repos: repos, cloud: &repository.CloudRepository{}, actor: actor, account: account,
		input: domain.CloudSyncInput{RegionID: region.ID, GatewayID: gatewayRecord.ID, CloudRegion: "cn-hangzhou", Ports: []int{22, 3306}, ApproverID: actor.ID, RiskLevel: domain.RiskLevelSensitive, MaxTTLSeconds: 3600}}
}

func TestCloudSyncAutomaticallyBindsDefaultGateway(t *testing.T) {
	f := newCloudFixture(t, func(context.Context, string, cloudassets.Credentials, string, []string) ([]cloudassets.Instance, error) {
		return []cloudassets.Instance{{ID: "i-default", Name: "Default route", Host: "10.0.0.20"}}, nil
	})
	ctx := context.Background()
	input := f.input
	input.GatewayID, input.RegionID = "", ""
	job := f.sync(t, input)
	if job.Status != "success" || job.Input.GatewayID == "" || job.Input.RegionID == "" {
		t.Fatalf("sync without manual gateway failed: %s", job.Status)
	}
	route, err := f.repos.gateways.GetByID(ctx, f.db, job.Input.GatewayID)
	if err != nil || route.PublicEndpoint != "access-gateway.srex.run" || route.RegionID != job.Input.RegionID {
		t.Fatal("cloud sync did not use configured default gateway")
	}
	repeated := f.sync(t, input)
	if repeated.Status != "success" || repeated.Input.GatewayID != job.Input.GatewayID {
		t.Fatal("repeated cloud sync created a different default gateway")
	}
}

func (f cloudFixture) sync(t *testing.T, input domain.CloudSyncInput) domain.CloudSyncJob {
	t.Helper()
	ctx := context.Background()
	queued, err := f.svc.QueueCloudSync(ctx, f.actor.ID, f.account.ID, input)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.ProcessCloudSync(ctx); err != nil {
		t.Fatal(err)
	}
	jobs, err := f.svc.ListCloudSyncJobs(ctx, f.actor.ID, input.RegionID)
	if err != nil {
		t.Fatal(err)
	}
	for _, job := range jobs {
		if job.ID == queued.ID {
			return job
		}
	}
	t.Fatal("queued job disappeared")
	return domain.CloudSyncJob{}
}

func TestCloudSyncPersistenceScopeAndPolicies(t *testing.T) {
	ctx := context.Background()
	values := []cloudassets.Instance{{ID: "i-1", Name: "database one", Host: "10.0.0.1"}, {ID: "i-2", Name: "database two", Host: "10.0.0.2"}}
	var providerError error
	f := newCloudFixture(t, func(_ context.Context, provider string, credentials cloudassets.Credentials, region string, _ []string) ([]cloudassets.Instance, error) {
		if provider != "aliyun" || credentials.AccessKey != "test-ak" || credentials.SecretKey != "test-sk" || region != "cn-hangzhou" {
			t.Fatal("incorrect cloud configuration")
		}
		return values, providerError
	})
	accountJSON, _ := json.Marshal(f.account)
	stored, err := f.cloud.GetAccount(ctx, f.db, f.account.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(accountJSON), "ciphertext") || strings.Contains(stored.CredentialsCiphertext, "test-sk") {
		t.Fatal("credentials exposed in account or storage")
	}
	saved, err := f.svc.SaveCloudAccount(ctx, f.actor.ID, f.account.ID, service.CloudAccountInput{Name: f.account.Name, Provider: "aliyun", Enabled: true, Revision: f.account.Revision})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.SaveCloudAccount(ctx, f.actor.ID, f.account.ID, service.CloudAccountInput{Name: "stale", Provider: "aliyun", Enabled: true, Revision: f.account.Revision}); !errors.Is(err, repository.ErrConflict) {
		t.Fatal("stale cloud account edit accepted")
	}
	f.account = saved
	gateways, err := f.svc.ListCloudSyncGateways(ctx, f.actor.ID, f.input.RegionID)
	if err != nil || len(gateways) != 1 || gateways[0].ID != f.input.GatewayID {
		t.Fatal("region gateway choices are incomplete")
	}
	job := f.sync(t, f.input)
	if job.Status != "success" || job.Result.Created != 2 {
		t.Fatalf("initial sync: %+v", job)
	}
	assets, err := f.repos.assets.ListActiveByRegion(ctx, f.db, f.input.RegionID)
	if err != nil || len(assets) != 2 {
		t.Fatalf("imported assets: %d, %v", len(assets), err)
	}
	for _, asset := range assets {
		ports, err := f.repos.assets.ListPorts(ctx, f.db, asset.ID)
		if err != nil || len(ports) != 2 {
			t.Fatal("bulk ports missing")
		}
		approvers, err := f.repos.assets.ListApprovers(ctx, f.db, asset.ID)
		if err != nil || len(approvers) != 1 || approvers[0].UserID != f.actor.ID {
			t.Fatal("bulk approval missing")
		}
		bindings, err := f.repos.gateways.ListAssetBindings(ctx, f.db, asset.ID)
		if err != nil || len(bindings) != 1 || bindings[0].GatewayID != f.input.GatewayID {
			t.Fatal("bulk gateway binding missing")
		}
	}
	bundle, err := f.svc.ExportGatewayRelease(ctx, f.actor.ID, f.input.GatewayID)
	if err != nil || !strings.Contains(string(bundle.Targets), "10.0.0.1") || !strings.Contains(string(bundle.Targets), "10.0.0.2") {
		t.Fatalf("gateway export failed: %v", err)
	}
	first, err := f.repos.assets.GetByExternalIdentity(ctx, f.db, "cloud."+f.account.ID, "cn-hangzhou.i-1")
	if err != nil {
		t.Fatal(err)
	}
	first.Status, first.RiskLevel, first.MaxTTLSeconds = domain.ResourceStatusDisabled, domain.RiskLevelCritical, 120
	first, err = f.repos.assets.UpsertExternal(ctx, f.db, first)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.repos.assets.DisablePortsExcept(ctx, f.db, first.ID, []int{3306}); err != nil {
		t.Fatal(err)
	}
	input := f.input
	input.InstanceIDs, input.Ports, input.RiskLevel = []string{"i-1", "i-missing"}, []int{80}, domain.RiskLevelNormal
	values[0].Host, values[0].Name = "10.0.0.10", "renamed"
	job = f.sync(t, input)
	if job.Status != "success" || job.Result.Updated != 1 || len(job.Result.MissingIDs) != 1 {
		t.Fatalf("targeted sync: %+v", job)
	}
	updated, err := f.repos.assets.GetByID(ctx, f.db, first.ID)
	if err != nil || updated.Status != domain.ResourceStatusDisabled || updated.RiskLevel != domain.RiskLevelCritical || updated.MaxTTLSeconds != 120 || updated.Name != "renamed" {
		t.Fatal("sync replaced local policy")
	}
	ports, _ := f.repos.assets.ListPorts(ctx, f.db, first.ID)
	if len(ports) != 1 || ports[0].Port != 3306 {
		t.Fatal("sync replaced manual port configuration")
	}
	other, _ := f.repos.assets.GetByExternalIdentity(ctx, f.db, "cloud."+f.account.ID, "cn-hangzhou.i-2")
	if other.Status != domain.ResourceStatusEnabled || *other.SyncGeneration == job.ID {
		t.Fatal("targeted sync changed an unrelated instance")
	}
	values = nil
	job = f.sync(t, f.input)
	if job.Status != "success" || job.Result.Created != 0 {
		t.Fatal("empty region sync failed")
	}
	other, _ = f.repos.assets.GetByID(ctx, f.db, other.ID)
	if other.Status != domain.ResourceStatusEnabled {
		t.Fatal("empty cloud response disabled existing assets")
	}
	values = []cloudassets.Instance{{ID: "i-new", Host: "10.0.0.99"}}
	providerError = errors.New("request contains test-sk")
	job = f.sync(t, f.input)
	if job.Status != "failed" || strings.Contains(job.Error, "test-sk") {
		t.Fatal("provider failure was not safely recorded")
	}
	if _, err := f.repos.assets.GetByExternalIdentity(ctx, f.db, "cloud."+f.account.ID, "cn-hangzhou.i-new"); !errors.Is(err, repository.ErrNotFound) {
		t.Fatal("partial response was applied")
	}
	audits, err := f.repos.audits.List(ctx, f.db, domain.AuditFilter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(audits)
	if strings.Contains(string(encoded), "test-sk") || strings.Contains(string(encoded), "10.0.0.1") {
		t.Fatal("audit exposed secret material")
	}
}

func TestCloudSyncLeaseAndChangedAccount(t *testing.T) {
	ctx := context.Background()
	calls := 0
	f := newCloudFixture(t, func(context.Context, string, cloudassets.Credentials, string, []string) ([]cloudassets.Instance, error) {
		calls++
		return nil, nil
	})
	if _, err := f.svc.QueueCloudSync(ctx, f.actor.ID, f.account.ID, f.input); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.QueueCloudSync(ctx, f.actor.ID, f.account.ID, f.input); !errors.Is(err, repository.ErrConflict) {
		t.Fatal("concurrent sync for one account was accepted")
	}
	job, err := f.cloud.ClaimJob(ctx, f.db, id.New())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.cloud.ClaimJob(ctx, f.db, id.New()); !errors.Is(err, repository.ErrNotFound) {
		t.Fatal("live lease was claimed twice")
	}
	if err := f.cloud.LockJob(ctx, f.db, job.ID, id.New()); !errors.Is(err, repository.ErrNotFound) {
		t.Fatal("incorrect worker token was accepted")
	}
	// Simulate a process dying after claiming a durable job.
	if _, err := f.db.ExecContext(ctx, `UPDATE cloud_sync_jobs SET lease_until = NOW() - INTERVAL '1 second' WHERE id = $1`, job.ID); err != nil {
		t.Fatal(err)
	}
	recovered, err := f.cloud.ClaimJob(ctx, f.db, id.New())
	if err != nil || recovered.ID != job.ID || *recovered.LeaseToken == *job.LeaseToken {
		t.Fatal("expired cloud job was not recovered")
	}
	job.Status = "success"
	if err := f.cloud.FinishJob(ctx, f.db, job); !errors.Is(err, repository.ErrNotFound) {
		t.Fatal("expired worker replaced recovered job")
	}
	recovered.Status = "success"
	if err := f.cloud.FinishJob(ctx, f.db, recovered); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.QueueCloudSync(ctx, f.actor.ID, f.account.ID, f.input); err != nil {
		t.Fatal(err)
	}
	_, err = f.svc.SaveCloudAccount(ctx, f.actor.ID, f.account.ID, service.CloudAccountInput{Name: f.account.Name, Provider: "aliyun", Enabled: false, Revision: f.account.Revision})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.ProcessCloudSync(ctx); err != nil {
		t.Fatal(err)
	}
	jobs, _ := f.svc.ListCloudSyncJobs(ctx, f.actor.ID, f.input.RegionID)
	if jobs[0].Status != "failed" || calls != 0 {
		t.Fatal("queued task used credentials after account was disabled")
	}
}
