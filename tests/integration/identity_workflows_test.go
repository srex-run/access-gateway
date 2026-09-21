//go:build integration

package integration_test

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/srex-run/access-gateway/internal/approvalflow"
	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/gateway"
	"github.com/srex-run/access-gateway/internal/iam"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/label"
	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/service"
	"github.com/srex-run/access-gateway/internal/sessionproxy"
)

// Uses real migrations, SQL scans and local accounts; no external identity provider.
func TestLabelIAMAndLocalApprovalWorkflow(t *testing.T) {
	db := openDatabase(t)
	seedLegacyRoles(t, db)
	ctx := context.Background()
	repos := newRepositories()
	admin, err := repos.users.Create(ctx, db, domain.User{ID: id.New(), Nickname: "IAM admin", Status: domain.UserStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Now().UTC().Truncate(time.Microsecond)
	svc, err := service.NewAccessService(service.ServiceOptions{SystemSettings: clientAccessFixture(t, db, admin.ID, nil, "sessions.example.com"), DB: db, Users: repos.users, Regions: repos.regions, Gateways: repos.gateways, Assets: repos.assets, Requests: repos.requests, Approvals: repos.approvals, Sessions: repos.sessions, SessionEvents: repos.sessionEvents, Audits: repos.audits, Outbox: repos.outbox, Gateway: &sessionRuntimeStub{}, Logger: zerolog.Nop(), AdminUserIDs: map[string]struct{}{admin.ID: {}}, Clock: func() time.Time { return clock }})
	if err != nil {
		t.Fatal(err)
	}
	makeUser := func(name string, labels label.Labels) service.UserDetail {
		t.Helper()
		created, err := svc.CreateLocalUser(ctx, admin.ID, service.CreateLocalUserInput{Nickname: name, Username: name, Password: "initial-password-12345"})
		if err != nil {
			t.Fatal(err)
		}
		profile, err := svc.GetManagedUser(ctx, admin.ID, created.ID)
		if err != nil {
			t.Fatal(err)
		}
		profile, err = svc.UpdateManagedUser(ctx, admin.ID, created.ID, service.UpdateUserInput{Nickname: name, Email: name + "@example.test", Department: "Operations", Status: domain.UserStatusActive, Labels: labels, Revision: profile.Revision})
		if err != nil {
			t.Fatal(err)
		}
		if profile.Nickname != name || profile.Email != name+"@example.test" || profile.Department != "Operations" || profile.Revision != 2 || profile.Status != "active" || !reflect.DeepEqual(profile.Labels, labels) || profile.CreatedAt.IsZero() || profile.FeishuBound || profile.Username != name {
			t.Fatalf("profile scan mismatch: %+v", profile)
		}
		if _, err := svc.AuthenticateLocal(ctx, name, "initial-password-12345"); err != nil {
			t.Fatal(err)
		}
		return profile
	}
	applicant := makeUser("workflow-applicant", label.Labels{"team": "web"})
	owner := makeUser("workflow-owner", label.Labels{"team": "db", "duty": "owner"})
	owner2 := makeUser("workflow-owner2", label.Labels{"team": "db", "duty": "owner"})
	approverRole, err := svc.SaveIAMRole(ctx, admin.ID, iam.Role{Name: "workflow-approver", Enabled: true, Permissions: []authz.Permission{authz.PermissionApprovalManage}})
	if err != nil {
		t.Fatal(err)
	}
	for _, ownerID := range []string{owner.ID, owner2.ID} {
		if _, err := svc.GrantRole(ctx, admin.ID, service.GrantRoleInput{UserID: ownerID, Role: approverRole.Name}); err != nil {
			t.Fatal(err)
		}
	}
	sre := makeUser("workflow-sre", label.Labels{"team": "operations"})
	if err := svc.Authorize(ctx, sre.ID, authz.PermissionWorkflowManage); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("label alone granted permission: %v", err)
	}
	role, err := svc.SaveIAMRole(ctx, admin.ID, iam.Role{Name: "workflow-reader", Description: "Read operation audit", Enabled: true, Labels: label.Labels{"duty": "reader"}, Permissions: []authz.Permission{authz.PermissionAuditRead}})
	if err != nil {
		t.Fatal(err)
	}
	if role.Name != "workflow-reader" || role.Description != "Read operation audit" || role.Revision != 1 || role.BuiltIn || !role.Enabled || role.CreatedAt.IsZero() || role.UpdatedAt.IsZero() || !reflect.DeepEqual(role.Labels, label.Labels{"duty": "reader"}) || !reflect.DeepEqual(role.Permissions, []authz.Permission{authz.PermissionAuditRead}) {
		t.Fatalf("role scan: %+v", role)
	}
	binding, err := svc.SaveIAMBinding(ctx, admin.ID, iam.Binding{Name: "Operations SREs", UserSelector: "team=operations", RoleSelector: "access-gateway.io/role=sre", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if binding.ID == "" || binding.Name != "Operations SREs" || binding.UserSelector != "team=operations" || binding.RoleSelector != "access-gateway.io/role=sre" || binding.Revision != 1 || !binding.Enabled || binding.CreatedAt.IsZero() || binding.UpdatedAt.IsZero() {
		t.Fatalf("binding scan: %+v", binding)
	}
	if err := svc.Authorize(ctx, sre.ID, authz.PermissionWorkflowManage); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SaveIAMBinding(ctx, sre.ID, iam.Binding{Name: "escalate", UserSelector: "team=operations", RoleSelector: "access-gateway.io/role=admin", Enabled: true}); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("SRE escalated role: %v", err)
	}
	ownership, err := svc.SaveOwnership(ctx, sre.ID, approvalflow.Ownership{Name: "DB owners", AssetSelector: "team=db", UserSelector: "team=db,duty=owner", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if ownership.ID == "" || ownership.Name != "DB owners" || ownership.AssetSelector != "team=db" || ownership.UserSelector != "team=db,duty=owner" || !ownership.Enabled || ownership.Revision != 1 || ownership.CreatedAt.IsZero() || ownership.UpdatedAt.IsZero() {
		t.Fatalf("ownership scan: %+v", ownership)
	}
	flow, err := svc.SaveWorkflow(ctx, sre.ID, approvalflow.Definition{Name: "DB change", Description: "all owners then ops", Labels: label.Labels{"team": "db"}, AssetSelector: "approval=db-test", TimeoutSeconds: 600, Enabled: true, Steps: []approvalflow.Step{{Name: "Owners", Kind: "owners", Mode: "all"}, {Name: "SRE", Kind: "role_selector", Mode: "any", Selector: "access-gateway.io/role=sre"}}})
	if err != nil {
		t.Fatal(err)
	}
	if flow.ID == "" || flow.Name != "DB change" || flow.Description != "all owners then ops" || flow.AssetSelector != "approval=db-test" || flow.TimeoutSeconds != 600 || !flow.Enabled || flow.BuiltIn || flow.Revision != 1 || flow.CreatedAt.IsZero() || flow.UpdatedAt.IsZero() || !reflect.DeepEqual(flow.Labels, label.Labels{"team": "db"}) || len(flow.Steps) != 2 || flow.Steps[0].Mode != "all" {
		t.Fatalf("workflow scan: %+v", flow)
	}
	region, err := repos.regions.Create(ctx, db, domain.Region{ID: id.New(), Code: "iam-workflow", Name: "Workflow", Status: domain.ResourceStatusEnabled})
	if err != nil {
		t.Fatal(err)
	}
	gw, err := repos.gateways.Create(ctx, db, domain.Gateway{ID: id.New(), RegionID: region.ID, Name: "Local", ManagementEndpoint: "https://gateway.test", PublicEndpoint: "127.0.0.1:20000", MaxSessions: 10, Status: domain.ResourceStatusEnabled})
	if err != nil {
		t.Fatal(err)
	}
	asset, err := repos.assets.Create(ctx, db, domain.Asset{ID: id.New(), RegionID: region.ID, GatewayID: gw.ID, Name: "ssh-server", AssetType: "ssh", TargetCiphertext: "test-ciphertext", RiskLevel: domain.RiskLevelNormal, MaxTTLSeconds: 600, Status: domain.ResourceStatusEnabled, ApprovalWorkflowID: &flow.ID})
	if err != nil {
		t.Fatal(err)
	}
	_, err = repos.assets.CreatePort(ctx, db, domain.AssetPort{ID: id.New(), AssetID: asset.ID, Port: 22, Protocol: "tcp", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := svc.SaveAssetPolicy(ctx, sre.ID, asset.ID, approvalflow.AssetPolicy{Labels: label.Labels{"team": "db", "approval": "db-test"}})
	if err != nil {
		t.Fatal(err)
	}
	// asset_labels_default_audit_profile always re-injects the automatic audit
	// profile, so an explicit policy carries it alongside the saved labels.
	expected := label.Labels{"team": "db", "approval": "db-test", sessionproxy.ProfileLabel: sessionproxy.AutoProfile}
	if policy.AssetID != asset.ID || policy.Revision != 1 || policy.DefaultsOnly || policy.UpdatedAt.IsZero() || !reflect.DeepEqual(policy.Labels, expected) {
		t.Fatalf("asset policy scan: %+v", policy)
	}
	if _, err := svc.SaveAssetPolicy(ctx, sre.ID, asset.ID, approvalflow.AssetPolicy{Labels: label.Labels{"team": "db"}, Revision: 99}); !errors.Is(err, service.ErrStateConflict) {
		t.Fatalf("stale revision accepted: %v", err)
	}
	input := service.CreateRequestInput{ApplicantID: applicant.ID, RegionID: region.ID, AssetID: asset.ID, TargetPort: 22, TargetAccount: "root", SourceIP: "127.0.0.1", Reason: "verify local approval", TTLSeconds: 600, IdempotencyKey: "label-workflow"}
	req, err := svc.CreateAccessRequest(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if req.WorkflowSnapshot == nil || req.WorkflowSnapshot.WorkflowID != flow.ID || req.WorkflowSnapshot.Revision != 1 || req.WorkflowSnapshot.AssetPolicyRevision != 1 || !reflect.DeepEqual(req.WorkflowSnapshot.AssetLabels, policy.Labels) || req.ApprovalExpiresAt == nil || req.ApprovalExpiresAt.Sub(clock) != 600*time.Second {
		t.Fatalf("request snapshot: %+v", req)
	}
	if repeat, err := svc.CreateAccessRequest(ctx, input); err != nil || repeat.ID != req.ID {
		t.Fatalf("request idempotency: %v", err)
	}
	view, err := svc.GetRequestWorkflow(ctx, applicant.ID, req.ID)
	if err != nil {
		t.Fatal(err)
	}
	if view.CurrentLevel != 1 || len(view.Approvals) != 3 {
		t.Fatalf("workflow view: %+v", view)
	}
	byUser := map[string]service.WorkflowApproval{}
	for _, a := range view.Approvals {
		byUser[a.UserID] = a
	}
	if byUser[owner.ID].Required != 2 || byUser[owner.ID].Name != owner.Nickname || byUser[owner.ID].StepName != "Owners" || byUser[owner.ID].Decision != nil || byUser[owner.ID].Comment != nil || byUser[owner.ID].DecidedAt != nil {
		t.Fatalf("approval fields: %+v", byUser[owner.ID])
	}
	if _, err := svc.DecideApproval(ctx, sre.ID, byUser[sre.ID].ID, domain.ApprovalApproved, nil); !errors.Is(err, service.ErrStateConflict) {
		t.Fatalf("later node bypass: %v", err)
	}
	if _, err := svc.DecideApproval(ctx, applicant.ID, byUser[owner.ID].ID, domain.ApprovalApproved, nil); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("self/foreign approval: %v", err)
	}
	if _, err := svc.DecideApproval(ctx, owner.ID, byUser[owner.ID].ID, domain.ApprovalApproved, nil); err != nil {
		t.Fatal(err)
	}
	pending, err := svc.ListPendingApprovals(ctx, owner2.ID, 10, 0)
	if err != nil || len(pending) != 1 {
		t.Fatalf("all-node pending query: %+v %v", pending, err)
	}
	if pending, err := svc.ListPendingApprovals(ctx, sre.ID, 10, 0); err != nil || len(pending) != 0 {
		t.Fatalf("future node in inbox: %v %v", pending, err)
	}
	// Updating a template must not rewrite this request's frozen all threshold.
	flow.Steps[0].Mode = "any"
	flow, err = svc.SaveWorkflow(ctx, sre.ID, flow)
	if err != nil || flow.Revision != 2 {
		t.Fatalf("edit flow: %v", err)
	}
	if _, err := svc.DecideApproval(ctx, owner2.ID, byUser[owner2.ID].ID, domain.ApprovalApproved, nil); err != nil {
		t.Fatal(err)
	}
	// Revocation is immediate even though the candidate remains in the snapshot.
	binding.Enabled = false
	binding, err = svc.SaveIAMBinding(ctx, admin.ID, binding)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.DecideApproval(ctx, sre.ID, byUser[sre.ID].ID, domain.ApprovalApproved, nil); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("revoked SRE approved: %v", err)
	}
	binding.Enabled = true
	_, err = svc.SaveIAMBinding(ctx, admin.ID, binding)
	if err != nil {
		t.Fatal(err)
	}
	// Concurrent final decisions create precisely one provisioning session.
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		wg.Go(func() {
			_, e := svc.DecideApproval(ctx, sre.ID, byUser[sre.ID].ID, domain.ApprovalApproved, nil)
			errs <- e
		})
	}
	wg.Wait()
	close(errs)
	success := 0
	for e := range errs {
		if e == nil {
			success++
		} else if !errors.Is(e, service.ErrStateConflict) {
			t.Fatal(e)
		}
	}
	if success != 1 {
		t.Fatalf("concurrent final approvals: %d", success)
	}
	session, err := repos.sessions.GetByRequestID(ctx, db, req.ID)
	if err != nil || session.Status != domain.SessionProvisioning {
		t.Fatalf("session not queued: %v", err)
	}
	if session.ExpiresAt == nil || !session.ExpiresAt.Equal(clock.Add(time.Duration(req.TTLSeconds)*time.Second)) {
		t.Fatalf("final approval did not fix session expiry: %+v", session.ExpiresAt)
	}
	// Asset-side command evidence must retain the session/identity correlation.
	backendIP, backendPort := "10.10.0.8", 42000
	connectionID := id.New()
	evidence := repository.NewAccessEvidenceRepository()
	if _, err := evidence.AppendConnectionEvent(ctx, db, domain.GatewayConnectionEvent{EventID: id.New(), ConnectionID: connectionID, SessionID: session.ID, EventType: "backend_connected", BackendSourceIP: &backendIP, BackendSourcePort: &backendPort, OccurredAt: clock.Add(-time.Second)}); err != nil {
		t.Fatal(err)
	}
	command := "id"
	operation := service.OperationAuditInput{EventID: id.New(), Protocol: "ssh", AssetID: asset.ID, TargetPort: 22, ActualAccount: "root", OperationType: "exec", NormalizedOperation: &command, Result: "success", BackendSourceIP: backendIP, BackendSourcePort: backendPort, SourceRecordID: "host-audit:command-1", OccurredAt: clock, Metadata: map[string]any{"source": "test-fixture"}}
	if n, err := svc.RecordOperationAuditBatch(ctx, []service.OperationAuditInput{operation}); err != nil || n != 1 {
		t.Fatalf("command evidence: %d %v", n, err)
	}
	if n, err := svc.RecordOperationAuditBatch(ctx, []service.OperationAuditInput{operation}); err != nil || n != 0 {
		t.Fatalf("command replay: %d %v", n, err)
	}
	operations, err := svc.ListOperationAuditEvents(ctx, sre.ID, domain.OperationAuditFilter{SessionID: session.ID, Limit: 10})
	if err != nil || len(operations) != 1 || operations[0].NormalizedOperation == nil || *operations[0].NormalizedOperation != "id" || operations[0].CorrelationStatus != "matched" || operations[0].ActualAccount != "root" || operations[0].SessionID == nil || *operations[0].SessionID != session.ID {
		t.Fatalf("command attribution: %+v %v", operations, err)
	}
	if own, err := svc.ListOperationAuditEvents(ctx, applicant.ID, domain.OperationAuditFilter{Limit: 10}); err != nil || len(own) != 1 || own[0].EventID != operation.EventID {
		t.Fatalf("ordinary user cannot read own command audit: %+v %v", own, err)
	}
	if other, err := svc.ListOperationAuditEvents(ctx, owner.ID, domain.OperationAuditFilter{SessionID: session.ID, Limit: 10}); err != nil || len(other) != 0 {
		t.Fatalf("ordinary user read another user's command audit: %+v %v", other, err)
	}
	input.IdempotencyKey = "expired-label-workflow"
	input.ApplicantID = owner.ID
	expired, err := svc.CreateAccessRequest(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	expiredApprovals, err := repos.approvals.ListByRequest(ctx, db, expired.ID)
	if err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(601 * time.Second)
	if _, err := svc.DecideApproval(ctx, expiredApprovals[0].ApproverID, expiredApprovals[0].ID, domain.ApprovalApproved, nil); !errors.Is(err, service.ErrStateConflict) {
		t.Fatalf("late approval accepted: %v", err)
	}
	// A matching selector on another workflow cannot replace the explicit binding.
	duplicate := flow
	duplicate.ID = ""
	duplicate.Revision = 0
	duplicate.Name = "same selector"
	if _, err := svc.SaveWorkflow(ctx, sre.ID, duplicate); err != nil {
		t.Fatal(err)
	}
	input.IdempotencyKey = "explicit-label-workflow"
	if explicit, err := svc.CreateAccessRequest(ctx, input); err != nil || explicit.WorkflowSnapshot == nil || explicit.WorkflowSnapshot.WorkflowID != flow.ID {
		t.Fatalf("duplicate selector changed the assigned workflow: %+v %v", explicit, err)
	}
	// A disabled assignment must fail without falling back to the matching flow.
	flow.Enabled = false
	if _, err := svc.SaveWorkflow(ctx, sre.ID, flow); err != nil {
		t.Fatal(err)
	}
	input.IdempotencyKey = "disabled-label-workflow"
	if _, err := svc.CreateAccessRequest(ctx, input); !errors.Is(err, service.ErrValidation) {
		t.Fatalf("disabled workflow accepted: %v", err)
	}
	if _, err := repos.requests.GetByIdempotencyKey(ctx, db, input.IdempotencyKey); !errors.Is(err, repository.ErrNotFound) {
		t.Fatal("failed request was persisted")
	}
	// Profile status invalidates auth_version and preserves labels at every scan.
	before, err := repos.users.GetByID(ctx, db, owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.UpdateManagedUser(ctx, admin.ID, owner.ID, service.UpdateUserInput{Nickname: owner.Nickname, Status: domain.UserStatusInactive, Labels: owner.Labels, Revision: owner.Revision})
	if err != nil {
		t.Fatal(err)
	}
	after, err := repos.users.GetByID(ctx, db, owner.ID)
	if err != nil || after.AuthVersion != before.AuthVersion+1 || after.Status != domain.UserStatusInactive || after.Revision != 3 {
		t.Fatalf("user deactivation: %+v %v", after, err)
	}
}

func TestIdentityRepositoryConstraints(t *testing.T) {
	db := openDatabase(t)
	ctx := context.Background()
	repos := newRepositories()
	ir := repository.IAMRepository{}
	wr := repository.WorkflowRepository{}
	roles, err := ir.ListRoles(ctx, db)
	if err != nil || len(roles) != 3 {
		t.Fatalf("built-in migration: %d %v", len(roles), err)
	}
	for index, name := range []string{"admin", "auditor", "user"} {
		if roles[index].Name != name || !roles[index].BuiltIn || !roles[index].Enabled {
			t.Fatalf("built-in role %q: %+v", name, roles[index])
		}
	}
	if _, err := wr.AssetPolicy(ctx, db, id.New()); err != nil {
		t.Fatalf("absent labels must use legacy default: %v", err)
	}
	if _, err := repos.users.DirectoryByID(ctx, db, id.New()); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("missing user: %v", err)
	}
	v := iam.Role{Name: "constraint-reader", Permissions: []authz.Permission{authz.PermissionAuditRead}, Labels: label.Labels{}, Enabled: true}
	created, err := ir.SaveRole(ctx, db, v)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ir.SaveRole(ctx, db, v); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("duplicate create overwrote role: %v", err)
	}
	created.Description = "updated"
	created.Enabled = false
	updated, err := ir.SaveRole(ctx, db, created)
	if err != nil || updated.Revision != 2 || updated.Enabled || updated.Description != "updated" {
		t.Fatalf("role update: %+v %v", updated, err)
	}
	if _, err := ir.SaveRole(ctx, db, created); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("stale role updated: %v", err)
	}
	if _, err := wr.SaveAssetPolicy(ctx, db, approvalflow.AssetPolicy{AssetID: id.New(), Labels: label.Labels{"team": "db"}}); !errors.Is(err, repository.ErrConstraint) {
		t.Fatalf("asset label FK: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE iam_roles SET enabled=false WHERE name='admin'`); err == nil {
		t.Fatal("disabled built-in administrator")
	}
	rollbackID := id.New()
	rollback := errors.New("rollback-test")
	err = service.InTx(ctx, db, func(q repository.DBTX) error {
		_, err := wr.SaveOwnership(ctx, q, approvalflow.Ownership{ID: rollbackID, Name: "rollback", AssetSelector: "team=db", UserSelector: "team=db", Enabled: true})
		if err != nil {
			return err
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatal(err)
	}
	owners, err := wr.ListOwnerships(ctx, db)
	if err != nil || len(owners) != 0 {
		t.Fatalf("ownership rollback: %+v %v", owners, err)
	}
	// Concurrent cross-revocation cannot remove every explicit administrator.
	first, err := repos.users.Create(ctx, db, domain.User{ID: id.New(), Nickname: "Admin one", Status: domain.UserStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	second, err := repos.users.Create(ctx, db, domain.User{ID: id.New(), Nickname: "Admin two", Status: domain.UserStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	a, err := repository.NewRoleRepository().Create(ctx, db, domain.RoleAssignment{ID: id.New(), UserID: first.ID, Role: "admin", GrantedBy: first.ID})
	if err != nil {
		t.Fatal(err)
	}
	b, err := repository.NewRoleRepository().Create(ctx, db, domain.RoleAssignment{ID: id.New(), UserID: second.ID, Role: "admin", GrantedBy: first.ID})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := service.NewAccessService(service.ServiceOptions{DB: db, Users: repos.users, Regions: repos.regions, Gateways: repos.gateways, Assets: repos.assets, Requests: repos.requests, Approvals: repos.approvals, Sessions: repos.sessions, SessionEvents: repos.sessionEvents, Audits: repos.audits, Outbox: repos.outbox, Gateway: gateway.UnavailableClient{}, Logger: zerolog.Nop()})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	wg.Go(func() { _, err := svc.RevokeRole(ctx, first.ID, b.ID); results <- err })
	wg.Go(func() { _, err := svc.RevokeRole(ctx, second.ID, a.ID); results <- err })
	wg.Wait()
	close(results)
	ok := 0
	for err := range results {
		if err == nil {
			ok++
		} else if !errors.Is(err, service.ErrForbidden) && !errors.Is(err, service.ErrValidation) {
			t.Fatal(err)
		}
	}
	if ok != 1 {
		t.Fatalf("concurrent cross revocation successes: %d", ok)
	}
	assignments, err := ir.ListAssignments(ctx, db)
	if err != nil || len(assignments) != 1 {
		t.Fatalf("lost final administrator: %+v %v", assignments, err)
	}
}
