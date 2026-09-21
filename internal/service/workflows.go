package service

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/srex-run/access-gateway/internal/approvalflow"
	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/iam"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/label"
	"github.com/srex-run/access-gateway/internal/repository"
)

func (s *AccessService) ListWorkflows(ctx context.Context, actor string) ([]approvalflow.Definition, error) {
	if err := s.Authorize(ctx, actor, authz.PermissionWorkflowManage); err != nil {
		return nil, err
	}
	values, err := (repository.WorkflowRepository{}).List(ctx, s.db)
	if err != nil {
		return nil, err
	}
	if len(values) > 1000 {
		return nil, ErrStateConflict
	}
	return values, nil
}

func (s *AccessService) SaveWorkflow(ctx context.Context, actor string, v approvalflow.Definition) (approvalflow.Definition, error) {
	v.AssetSelector = strings.TrimSpace(v.AssetSelector)
	if err := v.Validate(); err != nil {
		return v, requestValidation(err.Error())
	}
	if err := prepareRevisionID(&v.ID, v.Revision); err != nil {
		return v, err
	}
	if v.Labels == nil {
		v.Labels = label.Labels{}
	}
	var result approvalflow.Definition
	err := s.mutateIAM(ctx, actor, authz.PermissionWorkflowManage, func(q repository.DBTX) error {
		repo := repository.WorkflowRepository{}
		values, err := repo.List(ctx, q)
		if err != nil {
			return err
		}
		if len(values) >= 1000 && v.Revision == 0 {
			return ErrValidation
		}
		result, err = repo.Save(ctx, q, v)
		if err != nil {
			return revisionError(err)
		}
		return s.iamAudit(ctx, q, actor, "workflow.saved", map[string]any{"workflow_id": result.ID, "revision": result.Revision, "asset_selector": result.AssetSelector, "enabled": result.Enabled})
	})
	return result, err
}

func (s *AccessService) ListOwnerships(ctx context.Context, actor string) ([]approvalflow.Ownership, error) {
	if err := s.Authorize(ctx, actor, authz.PermissionWorkflowManage); err != nil {
		return nil, err
	}
	values, err := (repository.WorkflowRepository{}).ListOwnerships(ctx, s.db)
	if err != nil {
		return nil, err
	}
	if len(values) > 1000 {
		return nil, ErrStateConflict
	}
	return values, nil
}

func (s *AccessService) SaveOwnership(ctx context.Context, actor string, v approvalflow.Ownership) (approvalflow.Ownership, error) {
	if err := v.Validate(); err != nil {
		return v, requestValidation(err.Error())
	}
	if err := prepareRevisionID(&v.ID, v.Revision); err != nil {
		return v, err
	}
	var result approvalflow.Ownership
	err := s.mutateIAM(ctx, actor, authz.PermissionWorkflowManage, func(q repository.DBTX) error {
		repo := repository.WorkflowRepository{}
		values, err := repo.ListOwnerships(ctx, q)
		if err != nil {
			return err
		}
		if len(values) >= 1000 && v.Revision == 0 {
			return ErrValidation
		}
		result, err = repo.SaveOwnership(ctx, q, v)
		if err != nil {
			return revisionError(err)
		}
		return s.iamAudit(ctx, q, actor, "workflow.ownership_saved", map[string]any{"ownership_id": result.ID, "revision": result.Revision, "asset_selector": result.AssetSelector, "user_selector": result.UserSelector, "enabled": result.Enabled})
	})
	return result, err
}

func (s *AccessService) GetAssetPolicy(ctx context.Context, actor, assetID string) (approvalflow.AssetPolicy, error) {
	if err := s.Authorize(ctx, actor, authz.PermissionDirectoryRead); err != nil {
		return approvalflow.AssetPolicy{}, err
	}
	if err := validateUUID(assetID, "asset ID"); err != nil {
		return approvalflow.AssetPolicy{}, err
	}
	if _, err := s.assets.GetByID(ctx, s.db, assetID); err != nil {
		return approvalflow.AssetPolicy{}, err
	}
	return (repository.WorkflowRepository{}).AssetPolicy(ctx, s.db, assetID)
}

func (s *AccessService) SaveAssetPolicy(ctx context.Context, actor, assetID string, v approvalflow.AssetPolicy) (approvalflow.AssetPolicy, error) {
	if err := validateUUID(assetID, "asset ID"); err != nil {
		return v, err
	}
	if v.Revision < 0 {
		return v, ErrValidation
	}
	if err := label.ValidateEditable(v.Labels); err != nil {
		return v, requestValidation(err.Error())
	}
	if v.Labels == nil {
		v.Labels = label.Labels{}
	}
	v.AssetID = assetID
	var result approvalflow.AssetPolicy
	err := s.mutateIAM(ctx, actor, authz.PermissionWorkflowManage, func(q repository.DBTX) error {
		if _, err := s.assets.GetByID(ctx, q, assetID); err != nil {
			return err
		}
		if err := s.validateAssetOwner(ctx, q, v.Labels); err != nil {
			return err
		}
		var err error
		result, err = (repository.WorkflowRepository{}).SaveAssetPolicy(ctx, q, v)
		if err != nil {
			return revisionError(err)
		}
		metadata, err := plainMetadata(map[string]any{"revision": result.Revision, "labels": result.Labels})
		if err != nil {
			return err
		}
		return s.appendAudit(ctx, q, domain.AuditEvent{EventType: "workflow.asset_labels_saved", ActorType: "admin", ActorID: stringPtr(actor), AssetID: stringPtr(assetID), Result: stringPtr("success"), Metadata: metadata})
	})
	return result, err
}

type workflowDirectory struct {
	users       []domain.User
	roles       []iam.Role
	bindings    []iam.Binding
	assignments map[string][]string
	resolver    *iam.Resolver
}

func (s *AccessService) workflowDirectory(ctx context.Context, q repository.DBTX) (workflowDirectory, error) {
	r := repository.IAMRepository{}
	var d workflowDirectory
	var err error
	d.users, err = r.ListSubjects(ctx, q)
	if err != nil {
		return d, err
	}
	d.roles, err = r.ListRoles(ctx, q)
	if err != nil {
		return d, err
	}
	d.bindings, err = r.ListBindings(ctx, q)
	if err != nil {
		return d, err
	}
	assignments, err := r.ListAssignments(ctx, q)
	if err != nil {
		return d, err
	}
	if len(d.users) > 10000 || len(d.roles) > 1000 || len(d.bindings) > 1000 || len(assignments) > 100000 {
		return d, fmt.Errorf("审批目录超过安全匹配上限: %w", ErrStateConflict)
	}
	d.assignments = map[string][]string{}
	for _, a := range assignments {
		d.assignments[a.UserID] = append(d.assignments[a.UserID], a.Role)
	}
	for _, u := range d.users {
		if s.configuredAdmin(u) {
			d.assignments[u.ID] = append(d.assignments[u.ID], "admin")
		}
	}
	d.resolver = iam.NewResolver(d.roles, d.bindings)
	return d, nil
}

// materializeApproval is called under the configuration lock and inside the
// request transaction. Every configured node must retain a non-self approver.
func (s *AccessService) materializeApproval(ctx context.Context, q repository.DBTX, request *domain.AccessRequest) ([]domain.Approval, error) {
	repo := repository.WorkflowRepository{}
	policy, err := repo.AssetPolicy(ctx, q, request.AssetID)
	if err != nil {
		return nil, err
	}
	flows, err := repo.List(ctx, q)
	if err != nil {
		return nil, err
	}
	if len(flows) > 1000 {
		return nil, ErrStateConflict
	}
	asset, err := s.assets.GetByID(ctx, q, request.AssetID)
	if err != nil {
		return nil, err
	}
	selected, err := selectApprovalWorkflow(flows, asset.ApprovalWorkflowID)
	if err != nil {
		return nil, err
	}
	deadline := s.clock().Add(time.Duration(selected.TimeoutSeconds) * time.Second)
	request.ApprovalExpiresAt = &deadline
	owners, err := repo.ListOwnerships(ctx, q)
	if err != nil {
		return nil, err
	}
	if len(owners) > 1000 {
		return nil, ErrStateConflict
	}
	directory, err := s.workflowDirectory(ctx, q)
	if err != nil {
		return nil, err
	}
	snapshot := &approvalflow.Snapshot{WorkflowID: selected.ID, Name: selected.Name, Revision: selected.Revision, AssetPolicyRevision: policy.Revision, AssetLabels: policy.Labels.Copy(), Steps: []approvalflow.ResolvedStep{}}
	approvals := []domain.Approval{}
	eligibleRoles := map[string][]iam.Role{}
	for _, user := range directory.users {
		if user.ID == request.ApplicantID {
			continue
		}
		roles := directory.resolver.Resolve(user.Labels, directory.assignments[user.ID])
		if s.allowedRoles(roles, authz.PermissionApprovalManage) {
			eligibleRoles[user.ID] = roles
		}
	}
	ownerSelectors := []label.Selector{}
	for _, owner := range owners {
		if owner.Enabled && label.MatchesBinding(owner.AssetSelector, policy.Labels) {
			selector, err := label.BindingSelector(owner.UserSelector)
			if err != nil {
				return nil, ErrStateConflict
			}
			ownerSelectors = append(ownerSelectors, selector)
		}
	}
	for index, step := range selected.Steps {
		resolved := approvalflow.ResolvedStep{Step: step, Level: index + 1, Candidates: []approvalflow.Candidate{}}
		selector := label.Nothing()
		if step.Kind != "owners" {
			selector, err = label.BindingSelector(step.Selector)
			if err != nil {
				return nil, ErrStateConflict
			}
		}
		for _, user := range directory.users {
			roles, ok := eligibleRoles[user.ID]
			if !ok {
				continue
			}
			matched := false
			switch step.Kind {
			case "owners":
				matched = matchesAssetOwner(policy.Labels, user, ownerSelectors)
			case "user_selector":
				matched = selector.Matches(user.Labels)
			case "role_selector":
				matched = slices.ContainsFunc(roles, func(role iam.Role) bool { return selector.Matches(role.Labels) })
			}
			if matched {
				resolved.Candidates = append(resolved.Candidates, approvalflow.Candidate{UserID: user.ID, Name: user.Nickname})
			}
		}
		if len(resolved.Candidates) == 0 {
			return nil, requestValidation(fmt.Sprintf("审批节点“%s”没有可用审批人；请检查标签、角色和负责人规则，申请人不能自批", step.Name))
		}
		if len(resolved.Candidates) > 100 {
			return nil, requestValidation("单个审批节点最多匹配 100 人，请缩小匹配范围")
		}
		resolved.Required = 1
		if step.Mode == "all" {
			resolved.Required = len(resolved.Candidates)
		}
		for _, candidate := range resolved.Candidates {
			approvals = append(approvals, domain.Approval{ID: id.New(), ApproverID: candidate.UserID, ApprovalLevel: resolved.Level, RequiredApprovals: resolved.Required, StepName: step.Name})
		}
		snapshot.Steps = append(snapshot.Steps, resolved)
	}
	request.WorkflowSnapshot = snapshot
	return approvals, nil
}

type WorkflowView struct {
	Snapshot       *approvalflow.Snapshot     `json:"snapshot"`
	Approvals      []WorkflowApproval         `json:"approvals"`
	CurrentLevel   int                        `json:"current_level"`
	ExpiresAt      *time.Time                 `json:"expires_at"`
	Status         domain.AccessRequestStatus `json:"status"`
	Stages         []WorkflowStage            `json:"stages"`
	CanDecide      bool                       `json:"can_decide"`
	ApprovalID     string                     `json:"approval_id,omitempty"`
	DecisionReason string                     `json:"decision_reason,omitempty"`
}

type WorkflowApproval struct {
	ID        string                   `json:"id"`
	UserID    string                   `json:"user_id"`
	Name      string                   `json:"name"`
	Level     int                      `json:"level"`
	Required  int                      `json:"required"`
	StepName  string                   `json:"step_name"`
	Decision  *domain.ApprovalDecision `json:"decision"`
	Comment   *string                  `json:"comment"`
	DecidedAt *time.Time               `json:"decided_at"`
}

func (s *AccessService) GetRequestWorkflow(ctx context.Context, actor, requestID string) (WorkflowView, error) {
	if err := validateUUID(requestID, "request ID"); err != nil {
		return WorkflowView{}, err
	}
	var view WorkflowView
	err := s.readIAM(ctx, func(q repository.DBTX) error {
		if err := s.authorizeIn(ctx, q, actor, authz.PermissionRequestManage); err != nil {
			return err
		}
		request, err := s.requests.GetByIDForUpdate(ctx, q, requestID)
		if err != nil {
			return err
		}
		approvals, err := s.approvals.ListByRequest(ctx, q, requestID)
		if err != nil {
			return err
		}
		if request.ApplicantID != actor && !slices.ContainsFunc(approvals, func(a domain.Approval) bool { return a.ApproverID == actor }) {
			user, err := s.users.GetByID(ctx, q, actor)
			if err != nil {
				return err
			}
			roles, err := s.resolvedRoles(ctx, q, user)
			if err != nil {
				return err
			}
			if !slices.ContainsFunc(roles, func(role iam.Role) bool { return role.Name == "admin" }) {
				return ErrForbidden
			}
		}
		view, err = s.workflowView(ctx, q, request, approvals)
		if err != nil {
			return err
		}
		return s.workflowDecision(ctx, q, actor, request, approvals, &view)
	})
	return view, err
}

func (s *AccessService) PreviewAssetWorkflow(ctx context.Context, actor, assetID string) (WorkflowView, error) {
	if _, err := s.ListAssetPorts(ctx, actor, assetID); err != nil {
		return WorkflowView{}, err
	}
	request := domain.AccessRequest{AssetID: assetID, ApplicantID: actor, Status: domain.AccessRequestPendingApproval}
	var view WorkflowView
	err := s.readIAM(ctx, func(q repository.DBTX) error {
		if err := s.authorizeIn(ctx, q, actor, authz.PermissionDirectoryRead); err != nil {
			return err
		}
		approvals, err := s.materializeApproval(ctx, q, &request)
		if err != nil {
			return err
		}
		view, err = s.workflowView(ctx, q, request, approvals)
		return err
	})
	if err != nil {
		return WorkflowView{}, err
	}
	return view, nil
}

func (s *AccessService) workflowView(ctx context.Context, q repository.DBTX, request domain.AccessRequest, approvals []domain.Approval) (WorkflowView, error) {
	level, _ := nextApprovalLevel(approvals)
	view := WorkflowView{Snapshot: request.WorkflowSnapshot, CurrentLevel: level, ExpiresAt: request.ApprovalExpiresAt, Status: request.Status, Approvals: []WorkflowApproval{}}
	if view.ExpiresAt == nil && !request.CreatedAt.IsZero() {
		deadline := request.CreatedAt.Add(s.approvalTimeout)
		view.ExpiresAt = &deadline
	}
	if view.Status == domain.AccessRequestPendingApproval && view.ExpiresAt != nil && !s.clock().Before(*view.ExpiresAt) {
		view.Status = domain.AccessRequestApprovalExpired
	}
	view.Stages = workflowStages(approvals, view.Status, level)
	if view.Status != domain.AccessRequestPendingApproval {
		view.CurrentLevel = 0
	}
	for _, a := range approvals {
		name := ""
		if request.WorkflowSnapshot != nil {
			for _, step := range request.WorkflowSnapshot.Steps {
				if step.Level != a.ApprovalLevel {
					continue
				}
				for _, c := range step.Candidates {
					if c.UserID == a.ApproverID {
						name = c.Name
					}
				}
			}
		}
		if name == "" {
			user, err := s.users.GetByID(ctx, q, a.ApproverID)
			if err != nil {
				return view, err
			}
			name = user.Nickname
		}
		view.Approvals = append(view.Approvals, WorkflowApproval{ID: a.ID, UserID: a.ApproverID, Name: name, Level: a.ApprovalLevel, Required: a.RequiredApprovals, StepName: a.StepName, Decision: a.Decision, Comment: a.Comment, DecidedAt: a.DecidedAt})
	}
	return view, nil
}

// Snapshot membership is immutable, but revoked live role/label eligibility
// cannot be used to approve an outstanding request. No new candidate is added.
func (s *AccessService) validateWorkflowVoter(ctx context.Context, q repository.DBTX, request domain.AccessRequest, approval domain.Approval) error {
	deadline := request.CreatedAt.Add(s.approvalTimeout)
	if request.ApprovalExpiresAt != nil {
		deadline = *request.ApprovalExpiresAt
	}
	if !s.clock().Before(deadline) {
		return fmt.Errorf("审批已过期: %w", ErrStateConflict)
	}
	if err := s.authorizeIn(ctx, q, approval.ApproverID, authz.PermissionApprovalManage); err != nil {
		return err
	}
	if request.WorkflowSnapshot == nil {
		return nil
	}
	stepIndex := slices.IndexFunc(request.WorkflowSnapshot.Steps, func(step approvalflow.ResolvedStep) bool { return step.Level == approval.ApprovalLevel })
	if stepIndex < 0 {
		return ErrStateConflict
	}
	step := request.WorkflowSnapshot.Steps[stepIndex]
	if !slices.ContainsFunc(step.Candidates, func(c approvalflow.Candidate) bool { return c.UserID == approval.ApproverID }) {
		return ErrForbidden
	}
	user, err := s.users.GetByID(ctx, q, approval.ApproverID)
	if err != nil {
		return err
	}
	matched := false
	switch step.Kind {
	case "user_selector":
		matched = label.MatchesBinding(step.Selector, user.Labels)
	case "role_selector":
		roles, err := s.resolvedRoles(ctx, q, user)
		if err != nil {
			return err
		}
		matched = iam.MatchesRole(step.Selector, roles)
	case "owners":
		if request.WorkflowSnapshot.AssetLabels[assetOwnerLabel] != "" {
			matched = matchesAssetOwner(request.WorkflowSnapshot.AssetLabels, user, nil)
			break
		}
		owners, err := (repository.WorkflowRepository{}).ListOwnerships(ctx, q)
		if err != nil {
			return err
		}
		for _, owner := range owners {
			if owner.Enabled && label.MatchesBinding(owner.AssetSelector, request.WorkflowSnapshot.AssetLabels) && label.MatchesBinding(owner.UserSelector, user.Labels) {
				matched = true
			}
		}
	}
	if !matched {
		return fmt.Errorf("审批人的标签或角色授权已变更: %w", ErrForbidden)
	}
	return nil
}
