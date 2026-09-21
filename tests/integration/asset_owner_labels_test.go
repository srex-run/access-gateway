//go:build integration

package integration_test

import (
	"context"
	"errors"
	"testing"

	"github.com/srex-run/access-gateway/internal/approvalflow"
	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/iam"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/service"
)

func TestAssetOwnerLabelRoutesOnlyToAuthorizedNonApplicant(t *testing.T) {
	database, svc, admin := builtinRoleService(t)
	ctx := context.Background()
	repos := newRepositories()
	createUser := func(name string, status domain.UserStatus) domain.User {
		t.Helper()
		user, err := repos.users.Create(ctx, database, domain.User{ID: id.New(), Nickname: name, Status: status})
		if err != nil {
			t.Fatal(err)
		}
		return user
	}
	owner := createUser("Owner", domain.UserStatusActive)
	applicant := createUser("Applicant", domain.UserStatusActive)
	inactive := createUser("Inactive owner", domain.UserStatusInactive)
	flow, err := svc.SaveWorkflow(ctx, admin.ID, approvalflow.Definition{Name: "Direct owner", Enabled: true, TimeoutSeconds: 600, Steps: []approvalflow.Step{{Name: "Resource owner", Kind: "owners", Mode: "all"}}})
	if err != nil {
		t.Fatal(err)
	}
	region, err := repos.regions.EnsureDefault(ctx, database, id.New())
	if err != nil {
		t.Fatal(err)
	}
	gw, err := repos.gateways.Create(ctx, database, domain.Gateway{ID: id.New(), RegionID: region.ID, Name: "Owner labels", ManagementEndpoint: "https://gateway.test", PublicEndpoint: "gateway.test:20000", MaxSessions: 10, Status: domain.ResourceStatusEnabled})
	if err != nil {
		t.Fatal(err)
	}
	asset, err := svc.CreateAsset(ctx, admin.ID, service.CreateAssetInput{RegionID: region.ID, GatewayID: gw.ID, Name: "Owned database", AssetType: "mysql", TargetCiphertext: "unused", MaxTTLSeconds: 600, ApprovalWorkflowID: &flow.ID})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := svc.GetAssetPolicy(ctx, admin.ID, asset.ID)
	if err != nil {
		t.Fatal(err)
	}
	policy.Labels["env"], policy.Labels["owner"] = "prod", owner.ID
	if _, err := svc.SaveAssetPolicy(ctx, applicant.ID, asset.ID, policy); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("ordinary applicant changed the owner: %v", err)
	}
	if _, err := svc.SaveAssetPolicy(ctx, admin.ID, asset.ID, policy); !errors.Is(err, service.ErrValidation) {
		t.Fatalf("owner label granted approval permission: %v", err)
	}
	role, err := svc.SaveIAMRole(ctx, admin.ID, iam.Role{Name: "asset-owner-approver", Enabled: true, Permissions: []authz.Permission{authz.PermissionApprovalManage}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.GrantRole(ctx, admin.ID, service.GrantRoleInput{UserID: owner.ID, Role: role.Name}); err != nil {
		t.Fatal(err)
	}
	policy, err = svc.SaveAssetPolicy(ctx, admin.ID, asset.ID, policy)
	if err != nil {
		t.Fatal(err)
	}
	view, err := svc.PreviewAssetWorkflow(ctx, applicant.ID, asset.ID)
	if err != nil || view.Snapshot == nil || len(view.Snapshot.Steps) != 1 || len(view.Snapshot.Steps[0].Candidates) != 1 || view.Snapshot.Steps[0].Candidates[0].UserID != owner.ID || view.Snapshot.Steps[0].Required != 1 {
		t.Fatalf("owner label did not directly resolve the owner: %+v %v", view, err)
	}
	if _, err := svc.PreviewAssetWorkflow(ctx, owner.ID, asset.ID); !errors.Is(err, service.ErrValidation) {
		t.Fatalf("owner was allowed to approve their own request: %v", err)
	}
	for _, ownerID := range []string{"not-a-user", id.New(), inactive.ID, applicant.ID} {
		invalid := policy
		invalid.Labels = policy.Labels.Copy()
		invalid.Labels["owner"] = ownerID
		if _, err := svc.SaveAssetPolicy(ctx, admin.ID, asset.ID, invalid); !errors.Is(err, service.ErrValidation) {
			t.Fatalf("invalid or unauthorized owner %q accepted: %v", ownerID, err)
		}
	}
	persisted, err := svc.GetAssetPolicy(ctx, admin.ID, asset.ID)
	if err != nil || persisted.Revision != policy.Revision || persisted.Labels["owner"] != owner.ID || persisted.Labels["env"] != "prod" {
		t.Fatalf("failed owner update changed labels: %+v %v", persisted, err)
	}
	role.Enabled = false
	if _, err := svc.SaveIAMRole(ctx, admin.ID, role); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.PreviewAssetWorkflow(ctx, applicant.ID, asset.ID); !errors.Is(err, service.ErrValidation) {
		t.Fatalf("owner label bypassed revoked approval permission: %v", err)
	}
}
