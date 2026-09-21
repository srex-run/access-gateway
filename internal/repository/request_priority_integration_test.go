//go:build integration

package repository

import (
	"testing"
	"time"

	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/id"
)

func TestEmergencyApprovalsPaginateFirstAndSessionDeadlinePersists(t *testing.T) {
	db := openIntegrationDB(t)
	ctx := testContext()
	region, err := NewRegionRepository().EnsureDefault(ctx, db, id.New())
	if err != nil {
		t.Fatal(err)
	}
	gw, err := NewGatewayRepository().Create(ctx, db, domain.Gateway{ID: id.New(), RegionID: region.ID, Name: "priority-test", ManagementEndpoint: "https://gateway.test", PublicEndpoint: "gateway.test:8443", Status: domain.ResourceStatusEnabled, MaxSessions: 100})
	if err != nil {
		t.Fatal(err)
	}
	asset, err := NewAssetRepository().Create(ctx, db, domain.Asset{ID: id.New(), RegionID: region.ID, GatewayID: gw.ID, Name: "db", AssetType: "mysql", TargetCiphertext: "fixture", RiskLevel: domain.RiskLevelNormal, MaxTTLSeconds: 18000, Status: domain.ResourceStatusEnabled})
	if err != nil {
		t.Fatal(err)
	}
	users := NewUserRepository()
	applicant, err := users.Create(ctx, db, domain.User{ID: id.New(), Nickname: "Applicant", Status: domain.UserStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	approver, err := users.Create(ctx, db, domain.User{ID: id.New(), Nickname: "Approver", Status: domain.UserStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	requests, approvals := NewAccessRequestRepository(), NewApprovalRepository()
	var expected []string
	var urgentRequest domain.AccessRequest
	for _, urgent := range []bool{false, true} {
		request, err := requests.Create(ctx, db, domain.AccessRequest{ID: id.New(), ApplicantID: applicant.ID, AssetID: asset.ID, TargetPort: 3306, Reason: "priority", Emergency: urgent, TTLSeconds: 1800, Status: domain.AccessRequestPendingApproval, IdempotencyKey: id.New()})
		if err != nil {
			t.Fatal(err)
		}
		approval, err := approvals.Create(ctx, db, domain.Approval{ID: id.New(), RequestID: request.ID, ApproverID: approver.ID, ApprovalLevel: 1})
		if err != nil {
			t.Fatal(err)
		}
		expected = append(expected, approval.ID)
		if urgent {
			urgentRequest = request
		}
	}
	for offset, urgent := range []bool{true, false} {
		page, err := approvals.ListPendingByApprover(ctx, db, approver.ID, 1, offset)
		if err != nil || len(page) != 1 || page[0].ID != expected[1-offset] || page[0].Emergency != urgent {
			t.Fatalf("priority pagination page %d: %+v %v", offset, page, err)
		}
	}
	deadline := time.Now().UTC().Add(30 * time.Minute).Truncate(time.Microsecond)
	sessions := NewSessionRepository()
	created, err := sessions.Create(ctx, db, domain.Session{ID: id.New(), RequestID: urgentRequest.ID, GatewayID: gw.ID, Status: domain.SessionProvisioning, ConnectionMode: "native", ExpiresAt: &deadline})
	if err != nil {
		t.Fatal(err)
	}
	stored, err := sessions.GetByID(ctx, db, created.ID)
	if err != nil || stored.ExpiresAt == nil || !stored.ExpiresAt.Equal(deadline) {
		t.Fatalf("approval deadline was not persisted: %+v %v", stored, err)
	}
}
