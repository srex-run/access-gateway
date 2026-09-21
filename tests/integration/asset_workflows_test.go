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

func TestAssetWorkflowAssignmentPersistsAndControlsApproval(t *testing.T) {
	database, svc, admin := builtinRoleService(t)
	ctx := context.Background()
	repos := newRepositories()
	applicant, err := repos.users.Create(ctx, database, domain.User{ID: id.New(), Nickname: "Applicant", Status: domain.UserStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	flow, err := svc.SaveWorkflow(ctx, admin.ID, approvalflow.Definition{Name: "Explicit database approval", Enabled: true, TimeoutSeconds: 600,
		Steps: []approvalflow.Step{{Name: "Platform review", Kind: "role_selector", Mode: "any", Selector: "access-gateway.io/role=admin"}}})
	if err != nil {
		t.Fatal(err)
	}
	region, err := repos.regions.Create(ctx, database, domain.Region{ID: id.New(), Code: "workflow-link", Name: "Workflow", Status: domain.ResourceStatusEnabled})
	if err != nil {
		t.Fatal(err)
	}
	gw, err := repos.gateways.Create(ctx, database, domain.Gateway{ID: id.New(), RegionID: region.ID, Name: "Gateway", ManagementEndpoint: "https://gateway.test", PublicEndpoint: "gateway.test:20000", MaxSessions: 10, Status: domain.ResourceStatusEnabled})
	if err != nil {
		t.Fatal(err)
	}
	input := service.CreateAssetInput{RegionID: region.ID, GatewayID: gw.ID, Name: "Linked database", AssetType: "mysql", TargetCiphertext: "unused", MaxTTLSeconds: 600, ApprovalWorkflowID: &flow.ID}
	asset, err := svc.CreateAsset(ctx, admin.ID, input)
	if err != nil || asset.ApprovalWorkflowID == nil || *asset.ApprovalWorkflowID != flow.ID {
		t.Fatalf("create linked asset: %+v %v", asset, err)
	}
	createdEvents, err := repos.audits.List(ctx, database, domain.AuditFilter{AssetID: asset.ID, EventType: "asset.created", Limit: 10})
	if err != nil || len(createdEvents) != 1 || createdEvents[0].Metadata["approval_workflow_id"] != flow.ID {
		t.Fatalf("creation audit lost the assigned workflow: %v", err)
	}
	if _, err := svc.CreateAssetPort(ctx, admin.ID, asset.ID, domain.AssetPort{Port: 3306, Protocol: "tcp"}); err != nil {
		t.Fatal(err)
	}
	view, err := svc.PreviewAssetWorkflow(ctx, applicant.ID, asset.ID)
	if err != nil || view.Snapshot == nil || view.Snapshot.WorkflowID != flow.ID || len(view.Snapshot.Steps) != 1 || view.Snapshot.Steps[0].Candidates[0].UserID != admin.ID {
		t.Fatalf("asset assignment did not drive approval materialization: %+v %v", view, err)
	}
	name := "Renamed database"
	updated, err := svc.UpdateAsset(ctx, admin.ID, asset.ID, service.UpdateAssetInput{Name: &name})
	if err != nil || updated.ApprovalWorkflowID == nil || *updated.ApprovalWorkflowID != flow.ID {
		t.Fatalf("metadata update lost assignment: %+v %v", updated, err)
	}
	missing := id.New()
	if _, err := svc.UpdateAsset(ctx, admin.ID, asset.ID, service.UpdateAssetInput{Name: stringPointer("must rollback"), ApprovalWorkflowID: &missing}); !errors.Is(err, service.ErrValidation) {
		t.Fatalf("nonexistent workflow accepted: %v", err)
	}
	stored, err := repos.assets.GetByID(ctx, database, asset.ID)
	if err != nil || stored.Name != name || stored.ApprovalWorkflowID == nil || *stored.ApprovalWorkflowID != flow.ID {
		t.Fatalf("failed assignment partially updated asset: %+v %v", stored, err)
	}
	flow.Enabled = false
	flow, err = svc.SaveWorkflow(ctx, admin.ID, flow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.PreviewAssetWorkflow(ctx, applicant.ID, asset.ID); !errors.Is(err, service.ErrValidation) {
		t.Fatalf("disabled flow silently fell back: %v", err)
	}
	input.Name = "Must not be created"
	if _, err := svc.CreateAsset(ctx, admin.ID, input); !errors.Is(err, service.ErrValidation) {
		t.Fatalf("disabled workflow assigned to new asset: %v", err)
	}
	var count int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM assets WHERE name=$1`, input.Name).Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed create persisted asset: %d %v", count, err)
	}
	updated, err = svc.UpdateAsset(ctx, admin.ID, asset.ID, service.UpdateAssetInput{ApprovalWorkflowID: stringPointer("")})
	if err != nil || updated.ApprovalWorkflowID != nil {
		t.Fatalf("could not clear the assigned workflow: %+v %v", updated, err)
	}
	updatedEvents, err := repos.audits.List(ctx, database, domain.AuditFilter{AssetID: asset.ID, EventType: "asset.updated", Limit: 10})
	if err != nil || len(updatedEvents) != 2 {
		t.Fatalf("asset updates did not produce operation logs: %v", err)
	}
	workflowIDs := map[any]int{}
	for _, event := range updatedEvents {
		workflowID, ok := event.Metadata["approval_workflow_id"]
		if !ok {
			t.Fatal("update audit omitted the workflow assignment")
		}
		workflowIDs[workflowID]++
	}
	if workflowIDs[flow.ID] != 1 || workflowIDs[nil] != 1 {
		t.Fatal("update audit did not preserve the assigned and cleared workflows")
	}
	if _, err := svc.CreateAssetApprover(ctx, admin.ID, asset.ID, domain.AssetApprover{UserID: admin.ID, ApprovalLevel: 1, Role: "owner"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.PreviewAssetWorkflow(ctx, applicant.ID, asset.ID); !errors.Is(err, service.ErrValidation) {
		t.Fatalf("unassigned asset fell back to legacy approvers: %v", err)
	}
}

func TestCatalogManagerCanChooseButCannotEditWorkflowDefinitions(t *testing.T) {
	database, svc, admin := builtinRoleService(t)
	ctx := context.Background()
	operator, err := newRepositories().users.Create(ctx, database, domain.User{ID: id.New(), Nickname: "Catalog manager", Status: domain.UserStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	role, err := svc.SaveIAMRole(ctx, admin.ID, iam.Role{Name: "asset-editor", Enabled: true, Permissions: []authz.Permission{authz.PermissionCatalogManage}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.GrantRole(ctx, admin.ID, service.GrantRoleInput{UserID: operator.ID, Role: role.Name}); err != nil {
		t.Fatal(err)
	}
	flows, err := svc.ListAssetWorkflows(ctx, operator.ID)
	if err != nil || len(flows) == 0 {
		t.Fatalf("catalog manager cannot load choices: %+v %v", flows, err)
	}
	if _, err := svc.ListWorkflows(ctx, operator.ID); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("catalog permission gained workflow management: %v", err)
	}
	flow := flows[0]
	flow.ID, flow.BuiltIn, flow.Revision = "", false, 0
	if _, err := svc.SaveWorkflow(ctx, operator.ID, flow); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("catalog manager edited workflow: %v", err)
	}
}
