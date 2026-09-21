package service

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/gateway"
	"github.com/srex-run/access-gateway/internal/secretstore"
)

type approvedRuntimeStub struct {
	gateway.UnavailableClient
	called    bool
	target    string
	gatewayID string
}

func TestNewNativeSessionNeedsNoTargetAuthentication(t *testing.T) {
	approvedAt := time.Date(2026, 9, 15, 9, 0, 0, 0, time.UTC)
	svc := &AccessService{gateway: &approvedRuntimeStub{}, clock: func() time.Time { return approvedAt }}
	// No database, settings cipher or audit registry is needed to approve a
	// native session. TargetAccount is deliberately absent.
	request := domain.AccessRequest{ID: "request", TTLSeconds: 1800}
	for _, protocol := range []string{"mysql", "postgresql", "redis", "mongodb", "http", "https", "ssh", "sshd"} {
		t.Run(protocol, func(t *testing.T) {
			asset := domain.Asset{ID: "asset", GatewayID: "gateway", AssetType: protocol}
			session, err := svc.newNativeSession(asset, request)
			if err != nil {
				t.Fatal(err)
			}
			if session.ID == "" || session.RequestID != request.ID || session.GatewayID != asset.GatewayID || session.Status != domain.SessionProvisioning ||
				session.ConnectionMode != gateway.ConnectionModeNative || session.AuditPolicy.Profile != "" || session.TunnelClientPublicKey != "" || session.TunnelServerCertificate != "" ||
				session.ExpiresAt == nil || !session.ExpiresAt.Equal(approvedAt.Add(30*time.Minute)) {
				t.Fatalf("invalid native session: %+v", session)
			}
		})
	}
}

func TestApprovedSessionExpiryDoesNotRestartTheClock(t *testing.T) {
	approved := time.Date(2026, 9, 14, 9, 0, 0, 0, time.UTC)
	expires := approved.Add(30 * time.Minute)
	request := domain.AccessRequest{TTLSeconds: 1800, UpdatedAt: approved.Add(5 * time.Minute)}
	session := domain.Session{CreatedAt: approved, UpdatedAt: approved.Add(10 * time.Minute), ExpiresAt: &expires}
	if got := approvedSessionExpiry(session, request); !got.Equal(expires) {
		t.Fatalf("provisioning retry moved expiry: %s", got)
	}
	session.ExpiresAt = nil
	if got := approvedSessionExpiry(session, request); !got.Equal(expires) {
		t.Fatalf("legacy session deadline moved after a retry: %s", got)
	}
}

func (r *approvedRuntimeStub) PublicHost() string  { return "sessions.example.com" }
func (r *approvedRuntimeStub) RuntimeMode() string { return "kubernetes" }
func (r *approvedRuntimeStub) CreateApprovedSession(_ context.Context, gatewayID string, _ gateway.CreateSessionRequest, target string) (gateway.CreateSessionResponse, error) {
	r.called, r.target, r.gatewayID = true, target, gatewayID
	return gateway.CreateSessionResponse{}, nil
}

func TestPublicURLOverridesLegacyRuntimeHost(t *testing.T) {
	svc := &AccessService{gateway: &approvedRuntimeStub{}, publicURL: "https://access.example.test:8443"}
	if svc.publicHost() != "access.example.test" {
		t.Fatal("legacy runtime host overrode the configured service hostname")
	}
}

func TestSessionRuntimeDecryptsOnlyTheApprovedAsset(t *testing.T) {
	ctx := context.Background()
	cipher, _ := secretstore.NewAESGCM("test", []byte(strings.Repeat("k", 32)))
	asset := domain.Asset{ID: "approved-asset"}
	asset.TargetCiphertext, _ = cipher.Encrypt(ctx, []byte("db.internal"), []byte(asset.ID))
	runtime := &approvedRuntimeStub{}
	svc := &AccessService{gateway: runtime, assetEncryptor: cipher, cloudCipher: cipher}
	if _, err := svc.createGatewaySession(ctx, domain.Gateway{ID: "route"}, asset, gateway.CreateSessionRequest{}); err != nil || !runtime.called || runtime.target != "db.internal" || runtime.gatewayID != "route" {
		t.Fatalf("resolved grant: %+v %v", runtime, err)
	}
	runtime.called = false
	asset.ID = "other-asset"
	if _, err := svc.createGatewaySession(ctx, domain.Gateway{}, asset, gateway.CreateSessionRequest{}); err == nil || runtime.called {
		t.Fatal("asset identity substitution accepted")
	}
	source := "cloud.aws"
	asset.ExternalSource = &source
	asset.TargetCiphertext, _ = cipher.Encrypt(ctx, []byte("cloud-db.internal"), cloudTargetAAD(asset.ID))
	if _, err := svc.createGatewaySession(ctx, domain.Gateway{}, asset, gateway.CreateSessionRequest{}); err != nil || runtime.target != "cloud-db.internal" {
		t.Fatalf("cloud grant: %v", err)
	}
}
