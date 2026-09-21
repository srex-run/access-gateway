//go:build integration

package integration_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/gateway"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/secretstore"
	"github.com/srex-run/access-gateway/internal/service"
)

type sessionRuntimeStub struct {
	gateway.UnavailableClient
	target  string
	creates int
	closes  int
}

func (r *sessionRuntimeStub) PublicHost() string  { return "sessions.example.com" }
func (r *sessionRuntimeStub) RuntimeMode() string { return "kubernetes" }
func (r *sessionRuntimeStub) CreateApprovedSession(_ context.Context, _ string, request gateway.CreateSessionRequest, target string) (gateway.CreateSessionResponse, error) {
	r.target, r.creates = target, r.creates+1
	started := time.Now().UTC().Truncate(time.Second)
	expires := started.Add(time.Duration(request.TTLSeconds) * time.Second)
	if request.ExpiresAt != nil {
		expires = *request.ExpiresAt
	}
	return gateway.CreateSessionResponse{SessionID: request.SessionID, ConnectionMode: "native", Status: "running", ProcessID: "pod:access-gateway:session-" + request.SessionID,
		ListenerPort: 20000, ExternalPort: 31001, ExposureMode: "kubernetes_nodeport", ExposureRef: "kubernetes/service/access-gateway/session-" + request.SessionID,
		StartedAt: started, ExpiresAt: expires}, nil
}
func (r *sessionRuntimeStub) CloseSession(_ context.Context, _ string, sessionID, _ string) (gateway.CloseSessionResponse, error) {
	r.closes++
	return gateway.CloseSessionResponse{SessionID: sessionID, Status: "closed", ClosedAt: time.Now()}, nil
}

func TestApprovedSessionRuntimeDatabaseLifecycle(t *testing.T) {
	database := openDatabase(t)
	ctx := context.Background()
	repos := newRepositories()
	admin, err := repos.users.Create(ctx, database, domain.User{ID: id.New(), Nickname: "Admin", Status: domain.UserStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := secretstore.NewAESGCM("test", []byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	runtime := &sessionRuntimeStub{}
	svc, err := service.NewAccessService(service.ServiceOptions{
		SystemSettings: clientAccessFixture(t, database, admin.ID, nil, "sessions.example.com"),
		DB:             database, Users: repos.users, Regions: repos.regions, Gateways: repos.gateways, Assets: repos.assets,
		Requests: repos.requests, Approvals: repos.approvals, Sessions: repos.sessions, SessionEvents: repos.sessionEvents,
		Audits: repos.audits, Outbox: repos.outbox, Gateway: runtime, AssetEncryptor: cipher, Logger: zerolog.Nop(),
		DefaultTTL: time.Hour, MaxTTL: time.Hour, AdminUserIDs: map[string]struct{}{admin.ID: {}},
	})
	if err != nil {
		t.Fatal(err)
	}
	route, err := svc.CreateGateway(ctx, admin.ID, service.CreateGatewayInput{Name: "Session runtime"})
	if err != nil {
		t.Fatal(err)
	}
	if route.PublicEndpoint != runtime.PublicHost() || route.ManagementEndpoint != "https://kubernetes.default.svc" || route.AuthSecretRef != nil {
		t.Fatalf("managed route requires manual agent configuration: %+v", route)
	}
	asset, err := svc.CreateAsset(ctx, admin.ID, service.CreateAssetInput{RegionID: route.RegionID, GatewayID: route.ID, Name: "db", AssetType: "mysql", Target: "db.internal", RiskLevel: domain.RiskLevelNormal, MaxTTLSeconds: 600})
	if err != nil {
		t.Fatal(err)
	}
	_, err = repos.assets.CreatePort(ctx, database, domain.AssetPort{ID: id.New(), AssetID: asset.ID, Port: 3306, Protocol: "tcp", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	request, err := svc.CreateTestAccessRequest(ctx, service.CreateRequestInput{ApplicantID: admin.ID, RegionID: route.RegionID, AssetID: asset.ID, TargetPort: 3306,
		SourceIP: "192.0.2.1", TargetAccount: "readonly", Reason: "session runtime test", TTLSeconds: 600, IdempotencyKey: "session-runtime-test"})
	if err != nil {
		t.Fatal(err)
	}
	session, err := repos.sessions.GetByRequestID(ctx, database, request.ID)
	if err != nil {
		t.Fatal(err)
	}
	running, err := svc.ProvisionSession(ctx, session.ID)
	if err != nil || running.Status != domain.SessionRunning || runtime.target != "db.internal" || runtime.creates != 1 {
		t.Fatalf("provisioned session: %+v target=%s err=%v", running, runtime.target, err)
	}
	view, err := svc.GetSession(ctx, admin.ID, session.ID)
	if err != nil || view.GatewayEndpoint != "sessions.example.com:31001" || !view.CanConnect {
		t.Fatalf("connection view: %+v %v", view, err)
	}
	if _, err := svc.ProvisionSession(ctx, session.ID); err != nil || runtime.creates != 1 {
		t.Fatal("running session was provisioned twice")
	}
	if _, err := svc.CloseSession(ctx, admin.ID, session.ID); err != nil {
		t.Fatal(err)
	}
	closed, err := svc.RevokeSession(ctx, session.ID, "requested")
	if err != nil || closed.Status != domain.SessionClosed || runtime.closes != 1 {
		t.Fatalf("revocation: %+v %v calls=%d", closed, err, runtime.closes)
	}
	view, err = svc.GetSession(ctx, admin.ID, session.ID)
	if err != nil || view.CanConnect {
		t.Fatal("closed session is still connectable")
	}
}
