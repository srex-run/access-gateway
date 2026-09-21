package service

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/gateway"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/secretstore"
)

type CreateRegionInput struct {
	Code   string
	Name   string
	Status domain.ResourceStatus
}

type CreateGatewayInput struct {
	RegionID           string
	Name               string
	ManagementEndpoint string
	PublicEndpoint     string
	AuthSecretRef      *string
	Status             domain.ResourceStatus
	MaxSessions        int
}

type CreateAssetInput struct {
	RegionID           string
	GatewayID          string
	Name               string
	AssetType          string
	Target             string
	TargetCiphertext   string
	RiskLevel          domain.RiskLevel
	MaxTTLSeconds      int
	Status             domain.ResourceStatus
	Audit              *AssetAuditUpdate
	ApprovalWorkflowID *string
}

type UpdateAssetInput struct {
	Name               *string           `json:"name,omitempty"`
	AssetType          *string           `json:"asset_type,omitempty"`
	Target             *string           `json:"target,omitempty"`
	RiskLevel          *domain.RiskLevel `json:"risk_level,omitempty"`
	MaxTTLSeconds      *int              `json:"max_ttl_seconds,omitempty"`
	Audit              *AssetAuditUpdate `json:"audit,omitempty"`
	ApprovalWorkflowID *string           `json:"approval_workflow_id,omitempty"`
}

type UpdateAssetGatewayBindingInput struct {
	Enabled  bool
	Priority int
}

const (
	maxGatewayAssetTTLSeconds = 5 * 60 * 60
	defaultGatewayMaxSessions = 100
	maximumGatewayMaxSessions = 100000
)

func (s *AccessService) CreateRegion(ctx context.Context, actorID string, input CreateRegionInput) (domain.Region, error) {
	if err := s.requireAdmin(ctx, actorID); err != nil {
		return domain.Region{}, err
	}
	input.Code = strings.TrimSpace(input.Code)
	input.Name = strings.TrimSpace(input.Name)
	if err := validateAdminText(input.Code, "region code", 64, true); err != nil {
		return domain.Region{}, err
	}
	if err := validateAdminText(input.Name, "region name", 128, true); err != nil {
		return domain.Region{}, err
	}
	if input.Status == "" {
		input.Status = domain.ResourceStatusEnabled
	}
	if !validResourceStatus(input.Status) {
		return domain.Region{}, fmt.Errorf("invalid region status: %w", ErrValidation)
	}
	value := domain.Region{ID: id.New(), Code: input.Code, Name: input.Name, Status: input.Status}
	err := InTx(ctx, s.db, func(q repository.DBTX) error {
		var createErr error
		value, createErr = s.regions.Create(ctx, q, value)
		if createErr != nil {
			return createErr
		}
		return s.appendAudit(ctx, q, domain.AuditEvent{EventType: "region.created", ActorType: "admin", ActorID: stringPtr(actorID), RegionID: stringPtr(value.ID), Result: stringPtr("success")})
	})
	if err != nil {
		return domain.Region{}, fmt.Errorf("create region: %w", err)
	}
	return value, nil
}

func (s *AccessService) UpdateRegionStatus(ctx context.Context, actorID, regionID string, status domain.ResourceStatus) (domain.Region, error) {
	if err := s.requireAdmin(ctx, actorID); err != nil {
		return domain.Region{}, err
	}
	if err := validateUUID(regionID, "region ID"); err != nil {
		return domain.Region{}, err
	}
	if !validResourceStatus(status) {
		return domain.Region{}, fmt.Errorf("invalid region status: %w", ErrValidation)
	}
	var value domain.Region
	err := InTx(ctx, s.db, func(q repository.DBTX) error {
		var updateErr error
		value, updateErr = s.regions.UpdateStatus(ctx, q, regionID, status)
		if updateErr != nil {
			return updateErr
		}
		return s.appendAudit(ctx, q, domain.AuditEvent{
			EventType: "region.status_updated", ActorType: "admin", ActorID: stringPtr(actorID),
			RegionID: stringPtr(value.ID), Result: stringPtr(string(value.Status)),
		})
	})
	if err != nil {
		return domain.Region{}, fmt.Errorf("update region status: %w", err)
	}
	if status != domain.ResourceStatusEnabled {
		if err := s.enqueueRegionRevocations(ctx, value.ID, "region_"+string(status)); err != nil {
			return value, fmt.Errorf("revoke sessions for region status change: %w", err)
		}
	}
	return value, nil
}

func (s *AccessService) CreateGateway(ctx context.Context, actorID string, input CreateGatewayInput) (domain.Gateway, error) {
	if err := s.requireAdmin(ctx, actorID); err != nil {
		return domain.Gateway{}, err
	}
	input.RegionID = strings.TrimSpace(input.RegionID)
	input.Name = strings.TrimSpace(input.Name)
	input.ManagementEndpoint = strings.TrimSpace(input.ManagementEndpoint)
	input.PublicEndpoint = strings.TrimSpace(input.PublicEndpoint)
	_, managedRuntime := s.gateway.(gateway.ApprovedSessionClient)
	if runtime, ok := s.gateway.(gateway.ApprovedSessionClient); ok {
		input.ManagementEndpoint = "https://session-runtime.invalid/" + runtime.RuntimeMode()
		if runtime.RuntimeMode() == "kubernetes" {
			input.ManagementEndpoint = "https://kubernetes.default.svc"
		}
		input.PublicEndpoint = s.publicHost()
		input.AuthSecretRef = nil
	}
	if input.ManagementEndpoint == "" || input.PublicEndpoint == "" {
		return domain.Gateway{}, fmt.Errorf("gateway fields are required: %w", ErrValidation)
	}
	if err := validateAdminText(input.Name, "gateway name", 128, true); err != nil {
		return domain.Gateway{}, err
	}
	if err := validateAdminText(input.ManagementEndpoint, "management endpoint", 512, true); err != nil {
		return domain.Gateway{}, err
	}
	if err := validateAdminText(input.PublicEndpoint, "public endpoint", 512, true); err != nil {
		return domain.Gateway{}, err
	}
	if input.RegionID != "" && validateUUID(input.RegionID, "region ID") != nil {
		return domain.Gateway{}, ErrValidation
	}
	if input.Status == "" {
		input.Status = domain.ResourceStatusEnabled
	}
	if input.MaxSessions == 0 {
		input.MaxSessions = defaultGatewayMaxSessions
	}
	if !validResourceStatus(input.Status) {
		return domain.Gateway{}, fmt.Errorf("invalid gateway status: %w", ErrValidation)
	}
	if input.MaxSessions < 1 || input.MaxSessions > maximumGatewayMaxSessions {
		return domain.Gateway{}, fmt.Errorf("gateway capacity is invalid: %w", ErrValidation)
	}
	if err := validateManagementEndpoint(input.ManagementEndpoint); err != nil {
		return domain.Gateway{}, err
	}
	if !managedRuntime {
		if err := validatePublicEndpoint(input.PublicEndpoint); err != nil {
			return domain.Gateway{}, err
		}
	}
	if input.AuthSecretRef != nil {
		trimmed, err := normalizeGatewayCredentialReference(*input.AuthSecretRef, false)
		if err != nil {
			return domain.Gateway{}, err
		}
		if trimmed == "" {
			input.AuthSecretRef = nil
		} else {
			if err := s.validateGatewayCredentialReference(ctx, trimmed); err != nil {
				return domain.Gateway{}, err
			}
			input.AuthSecretRef = &trimmed
		}
	}
	value := domain.Gateway{ID: id.New(), RegionID: input.RegionID, Name: strings.TrimSpace(input.Name), ManagementEndpoint: strings.TrimSpace(input.ManagementEndpoint), PublicEndpoint: strings.TrimSpace(input.PublicEndpoint), AuthSecretRef: input.AuthSecretRef, Status: input.Status, MaxSessions: input.MaxSessions}
	err := InTx(ctx, s.db, func(q repository.DBTX) error {
		if value.RegionID == "" {
			region, err := s.regions.EnsureDefault(ctx, q, id.New())
			if err != nil {
				return err
			}
			if region.Status != domain.ResourceStatusEnabled {
				return fmt.Errorf("default region is not enabled: %w", ErrValidation)
			}
			value.RegionID = region.ID
		} else if _, err := s.regions.GetByID(ctx, q, value.RegionID); err != nil {
			return fmt.Errorf("validate gateway region: %w", err)
		}
		var createErr error
		value, createErr = s.gateways.Create(ctx, q, value)
		if createErr != nil {
			return createErr
		}
		return s.appendAudit(ctx, q, domain.AuditEvent{EventType: "gateway.created", ActorType: "admin", ActorID: stringPtr(actorID), RegionID: stringPtr(value.RegionID), Metadata: map[string]any{"gateway_id": value.ID}, Result: stringPtr("success")})
	})
	if err != nil {
		return domain.Gateway{}, fmt.Errorf("create gateway: %w", err)
	}
	return value, nil
}

func normalizeGatewayCredentialReference(reference string, required bool) (string, error) {
	reference = strings.TrimSpace(reference)
	if reference == "" && !required {
		return "", nil
	}
	if err := secretstore.ValidateCredentialReference(reference); err != nil {
		return "", fmt.Errorf("gateway secret reference is invalid: %w", ErrValidation)
	}
	return reference, nil
}

func (s *AccessService) validateGatewayCredentialReference(ctx context.Context, reference string) error {
	if s.gatewayCredentials == nil {
		return nil
	}
	credentials, err := s.gatewayCredentials.Resolve(ctx, reference)
	defer func() {
		for _, credential := range credentials {
			clear(credential)
		}
	}()
	if err != nil {
		// Resolver errors may contain the reference or its backing path, and this
		// service error is logged for 5xx responses.
		return fmt.Errorf("gateway credential reference is unavailable: %w", ErrNotConfigured)
	}
	if len(credentials) == 0 {
		return fmt.Errorf("gateway credential reference contains no credentials: %w", ErrNotConfigured)
	}
	for _, credential := range credentials {
		if err := secretstore.ValidateCredential(credential); err != nil {
			return fmt.Errorf("gateway credential reference is invalid (%v): %w", err, ErrNotConfigured)
		}
	}
	return nil
}

func (s *AccessService) UpdateGatewayStatus(ctx context.Context, actorID, gatewayID string, status domain.ResourceStatus) (domain.Gateway, error) {
	if err := s.requireAdmin(ctx, actorID); err != nil {
		return domain.Gateway{}, err
	}
	if err := validateUUID(gatewayID, "gateway ID"); err != nil {
		return domain.Gateway{}, err
	}
	if !validResourceStatus(status) {
		return domain.Gateway{}, fmt.Errorf("invalid gateway status: %w", ErrValidation)
	}
	existing, err := s.gateways.GetByID(ctx, s.db, gatewayID)
	if err != nil {
		return domain.Gateway{}, fmt.Errorf("load gateway: %w", err)
	}
	if status == domain.ResourceStatusEnabled {
		region, regionErr := s.regions.GetByID(ctx, s.db, existing.RegionID)
		if regionErr != nil {
			return domain.Gateway{}, fmt.Errorf("load gateway region: %w", regionErr)
		}
		if region.Status != domain.ResourceStatusEnabled {
			return domain.Gateway{}, fmt.Errorf("cannot enable a gateway in a non-enabled region: %w", ErrValidation)
		}
	}
	var value domain.Gateway
	err = InTx(ctx, s.db, func(q repository.DBTX) error {
		var updateErr error
		value, updateErr = s.gateways.UpdateStatus(ctx, q, gatewayID, status)
		if updateErr != nil {
			return updateErr
		}
		return s.appendAudit(ctx, q, domain.AuditEvent{
			EventType: "gateway.status_updated", ActorType: "admin", ActorID: stringPtr(actorID),
			RegionID: stringPtr(value.RegionID), Result: stringPtr(string(value.Status)),
			Metadata: map[string]any{"gateway_id": value.ID},
		})
	})
	if err != nil {
		return domain.Gateway{}, fmt.Errorf("update gateway status: %w", err)
	}
	if status != domain.ResourceStatusEnabled {
		if err := s.enqueueGatewayRevocations(ctx, value.ID, "gateway_"+string(status)); err != nil {
			return value, fmt.Errorf("revoke sessions for gateway status change: %w", err)
		}
	}
	return value, nil
}

func (s *AccessService) ListManagedAssets(ctx context.Context, actorID string) ([]domain.Asset, error) {
	if err := s.requireAdmin(ctx, actorID); err != nil {
		return nil, err
	}
	return s.assets.ListManaged(ctx, s.db)
}

func (s *AccessService) CreateAsset(ctx context.Context, actorID string, input CreateAssetInput) (domain.Asset, error) {
	if err := s.requireAdmin(ctx, actorID); err != nil {
		return domain.Asset{}, err
	}
	input.RegionID = strings.TrimSpace(input.RegionID)
	input.GatewayID = strings.TrimSpace(input.GatewayID)
	input.Name = strings.TrimSpace(input.Name)
	input.AssetType = strings.TrimSpace(input.AssetType)
	input.Target = strings.TrimSpace(input.Target)
	input.TargetCiphertext = strings.TrimSpace(input.TargetCiphertext)
	if input.Name == "" || input.AssetType == "" {
		return domain.Asset{}, fmt.Errorf("asset fields are required: %w", ErrValidation)
	}
	if err := validateAdminText(input.Name, "asset name", 128, true); err != nil {
		return domain.Asset{}, err
	}
	if err := validateAdminText(input.AssetType, "asset type", 64, true); err != nil {
		return domain.Asset{}, err
	}
	if input.RegionID != "" && validateUUID(input.RegionID, "region ID") != nil {
		return domain.Asset{}, ErrValidation
	}
	if input.GatewayID != "" && validateUUID(input.GatewayID, "gateway ID") != nil {
		return domain.Asset{}, ErrValidation
	}
	if input.RiskLevel == "" {
		input.RiskLevel = domain.RiskLevelNormal
	}
	if input.Status == "" {
		input.Status = domain.ResourceStatusEnabled
	}
	if !validRiskLevel(input.RiskLevel) || !validResourceStatus(input.Status) || input.MaxTTLSeconds <= 0 || input.MaxTTLSeconds > maxGatewayAssetTTLSeconds {
		return domain.Asset{}, fmt.Errorf("asset policy fields are invalid: %w", ErrValidation)
	}
	assetID := id.New()
	targetCiphertext, err := s.protectAssetTarget(ctx, assetID, input.Target, input.TargetCiphertext)
	if err != nil {
		return domain.Asset{}, err
	}
	value := domain.Asset{ID: assetID, RegionID: input.RegionID, GatewayID: input.GatewayID, Name: input.Name, AssetType: input.AssetType, TargetCiphertext: targetCiphertext, RiskLevel: input.RiskLevel, MaxTTLSeconds: input.MaxTTLSeconds, Status: input.Status}
	var auditRow repository.AssetAudit
	if input.Audit != nil {
		if input.Audit.Revision != 0 {
			return domain.Asset{}, requestValidation("新资源的审计版本必须为 0")
		}
		auditRow, err = s.prepareAssetAudit(ctx, actorID, value, *input.Audit, storedAssetAudit{})
		if err != nil {
			return domain.Asset{}, err
		}
	}
	err = InTx(ctx, s.db, func(q repository.DBTX) error {
		if input.ApprovalWorkflowID != nil {
			if err := (repository.IAMRepository{}).Lock(ctx, q, true); err != nil {
				return err
			}
			workflowID, err := validateAssetWorkflow(ctx, q, *input.ApprovalWorkflowID)
			if err != nil {
				return err
			}
			value.ApprovalWorkflowID = workflowID
		}
		route, err := s.resolveAssetGateway(ctx, q, input.RegionID, input.GatewayID)
		if err != nil {
			return err
		}
		value.RegionID, value.GatewayID = route.RegionID, route.ID
		var createErr error
		value, createErr = s.assets.Create(ctx, q, value)
		if createErr != nil {
			return createErr
		}
		if bindErr := s.gateways.BindAsset(ctx, q, value.ID, value.GatewayID, 0); bindErr != nil {
			return bindErr
		}
		if input.Audit != nil {
			if err := s.saveAssetAudit(ctx, q, auditRow, *input.Audit, nil); err != nil {
				return err
			}
		}
		metadata := map[string]any{"approval_workflow_id": nil}
		if value.ApprovalWorkflowID != nil {
			metadata["approval_workflow_id"] = *value.ApprovalWorkflowID
		}
		return s.appendAudit(ctx, q, domain.AuditEvent{EventType: "asset.created", ActorType: "admin", ActorID: stringPtr(actorID), RegionID: stringPtr(value.RegionID), AssetID: stringPtr(value.ID), Result: stringPtr("success"), Metadata: metadata})
	})
	if err != nil {
		return domain.Asset{}, fmt.Errorf("create asset: %w", err)
	}
	return value, nil
}

func (s *AccessService) UpdateAsset(ctx context.Context, actorID, assetID string, input UpdateAssetInput) (domain.Asset, error) {
	if err := s.requireAdmin(ctx, actorID); err != nil {
		return domain.Asset{}, err
	}
	if err := validateUUID(assetID, "asset ID"); err != nil {
		return domain.Asset{}, requestValidation("资产标识无效，请刷新页面后重试")
	}
	if input.Name == nil && input.AssetType == nil && input.Target == nil && input.RiskLevel == nil && input.MaxTTLSeconds == nil && input.Audit == nil && input.ApprovalWorkflowID == nil {
		return domain.Asset{}, requestValidation("请至少修改一项资产配置")
	}
	for _, field := range []struct {
		value **string
		name  string
		limit int
	}{{&input.Name, "资产名称", 128}, {&input.AssetType, "资产类型", 64}, {&input.Target, "目标地址", 4096}} {
		if *field.value != nil {
			value := strings.TrimSpace(**field.value)
			if value == "" {
				return domain.Asset{}, requestValidation(field.name + "不能为空")
			}
			if err := validateAdminText(value, field.name, field.limit, true); err != nil {
				return domain.Asset{}, requestValidation(fmt.Sprintf("%s不能包含控制字符，且不能超过 %d 个字符", field.name, field.limit))
			}
			*field.value = &value
		}
	}
	if input.RiskLevel != nil && !validRiskLevel(*input.RiskLevel) {
		return domain.Asset{}, requestValidation("请选择有效的风险级别")
	}
	if input.MaxTTLSeconds != nil && (*input.MaxTTLSeconds < 1 || *input.MaxTTLSeconds > maxGatewayAssetTTLSeconds) {
		return domain.Asset{}, requestValidation(fmt.Sprintf("最长访问时限必须在 1-%d 秒之间", maxGatewayAssetTTLSeconds))
	}
	var ciphertext string
	if input.Target != nil {
		if len(*input.Target) > 4096 {
			return domain.Asset{}, requestValidation("目标地址不能超过 4096 字节")
		}
		if s.assetEncryptor == nil {
			return domain.Asset{}, requestValidation("服务尚未配置资产加密，无法更新目标地址，请联系管理员")
		}
		var err error
		ciphertext, err = s.protectAssetTarget(ctx, assetID, *input.Target, "")
		if err != nil {
			return domain.Asset{}, err
		}
	}
	var auditRow repository.AssetAudit
	var auditAssetType string
	var previousAudit storedAssetAudit
	if input.Audit != nil || input.AssetType != nil {
		original, err := s.assets.GetByID(ctx, s.db, assetID)
		if err != nil {
			return domain.Asset{}, err
		}
		previous, revision, err := s.loadAssetAudit(ctx, s.db, original)
		if err != nil {
			return domain.Asset{}, err
		}
		previousAudit = previous
		auditAssetType = original.AssetType
		if input.AssetType != nil {
			original.AssetType = *input.AssetType
		}
		if input.Audit != nil {
			if input.Audit.Revision != revision {
				return domain.Asset{}, ErrStateConflict
			}
			auditRow, err = s.prepareAssetAudit(ctx, actorID, original, *input.Audit, previous)
			if err != nil {
				return domain.Asset{}, err
			}
		} else if revision > 0 && original.AssetType != auditAssetType {
			// A protocol change must explicitly replace the old certificate configuration.
			return domain.Asset{}, requestValidation("修改资源类型时，请同时提交对应协议的审计配置")
		}
	}
	var value domain.Asset
	err := InTx(ctx, s.db, func(q repository.DBTX) error {
		if input.ApprovalWorkflowID != nil {
			if err := (repository.IAMRepository{}).Lock(ctx, q, true); err != nil {
				return err
			}
		}
		var err error
		value, err = s.assets.GetByIDForUpdate(ctx, q, assetID)
		if err != nil {
			return err
		}
		// External targets belong to their sync source and may use a different
		// encryption key and associated data (for example cloud assets).
		if input.Target != nil && value.ExternalSource != nil {
			return requestValidation("该资产由外部来源同步，请在来源系统修改目标地址")
		}
		if auditAssetType != "" && value.AssetType != auditAssetType {
			return ErrStateConflict
		}
		fields := make([]any, 0, 5)
		if input.ApprovalWorkflowID != nil {
			previous := ""
			if value.ApprovalWorkflowID != nil {
				previous = *value.ApprovalWorkflowID
			}
			if previous != strings.TrimSpace(*input.ApprovalWorkflowID) {
				workflowID, err := validateAssetWorkflow(ctx, q, *input.ApprovalWorkflowID)
				if err != nil {
					return err
				}
				value.ApprovalWorkflowID = workflowID
				fields = append(fields, "approval_workflow_id")
			}
		}
		if input.Name != nil && value.Name != *input.Name {
			value.Name = *input.Name
			fields = append(fields, "name")
		}
		if input.AssetType != nil && value.AssetType != *input.AssetType {
			value.AssetType = *input.AssetType
			fields = append(fields, "asset_type")
		}
		if input.Target != nil {
			value.TargetCiphertext = ciphertext
			fields = append(fields, "target")
		}
		if input.RiskLevel != nil && value.RiskLevel != *input.RiskLevel {
			value.RiskLevel = *input.RiskLevel
			fields = append(fields, "risk_level")
		}
		if input.MaxTTLSeconds != nil && value.MaxTTLSeconds != *input.MaxTTLSeconds {
			value.MaxTTLSeconds = *input.MaxTTLSeconds
			fields = append(fields, "max_ttl_seconds")
		}
		if input.Audit != nil {
			if err := s.saveAssetAudit(ctx, q, auditRow, *input.Audit, previousAudit.Profiles); err != nil {
				return err
			}
			fields = append(fields, "audit")
		}
		if len(fields) == 0 {
			return nil
		}
		value, err = s.assets.UpdateConfiguration(ctx, q, value)
		if err != nil {
			return err
		}
		metadata := map[string]any{"changed_fields": fields, "approval_workflow_id": nil}
		if value.ApprovalWorkflowID != nil {
			metadata["approval_workflow_id"] = *value.ApprovalWorkflowID
		}
		return s.appendAudit(ctx, q, domain.AuditEvent{EventType: "asset.updated", ActorType: "admin", ActorID: stringPtr(actorID),
			RegionID: stringPtr(value.RegionID), AssetID: stringPtr(assetID), Result: stringPtr("success"), Metadata: metadata})
	})
	if err != nil {
		return domain.Asset{}, fmt.Errorf("update asset configuration: %w", err)
	}
	return value, nil
}

func (s *AccessService) UpdateAssetStatus(ctx context.Context, actorID, assetID string, status domain.ResourceStatus) (domain.Asset, error) {
	if err := s.requireAdmin(ctx, actorID); err != nil {
		return domain.Asset{}, err
	}
	if err := validateUUID(assetID, "asset ID"); err != nil {
		return domain.Asset{}, err
	}
	if !validResourceStatus(status) {
		return domain.Asset{}, fmt.Errorf("invalid asset status: %w", ErrValidation)
	}
	existing, err := s.assets.GetByID(ctx, s.db, assetID)
	if err != nil {
		return domain.Asset{}, fmt.Errorf("load asset: %w", err)
	}
	if status == domain.ResourceStatusEnabled {
		region, regionErr := s.regions.GetByID(ctx, s.db, existing.RegionID)
		if regionErr != nil {
			return domain.Asset{}, fmt.Errorf("load asset region: %w", regionErr)
		}
		bindings, bindingErr := s.gateways.ListAssetBindings(ctx, s.db, assetID)
		if bindingErr != nil {
			return domain.Asset{}, fmt.Errorf("list asset bindings: %w", bindingErr)
		}
		ports, portErr := s.assets.ListPorts(ctx, s.db, assetID)
		if portErr != nil {
			return domain.Asset{}, fmt.Errorf("list asset ports: %w", portErr)
		}
		hasEnabledBinding := false
		for _, binding := range bindings {
			if binding.Enabled {
				hasEnabledBinding = true
				break
			}
		}
		if region.Status != domain.ResourceStatusEnabled || !hasEnabledBinding || len(ports) == 0 {
			return domain.Asset{}, fmt.Errorf("asset requires an enabled region, gateway binding, and port: %w", ErrValidation)
		}
	}
	var value domain.Asset
	err = InTx(ctx, s.db, func(q repository.DBTX) error {
		var updateErr error
		value, updateErr = s.assets.UpdateStatus(ctx, q, assetID, status)
		if updateErr != nil {
			return updateErr
		}
		return s.appendAudit(ctx, q, domain.AuditEvent{
			EventType: "asset.status_updated", ActorType: "admin", ActorID: stringPtr(actorID),
			RegionID: stringPtr(value.RegionID), AssetID: stringPtr(value.ID), Result: stringPtr(string(value.Status)),
		})
	})
	if err != nil {
		return domain.Asset{}, fmt.Errorf("update asset status: %w", err)
	}
	if status != domain.ResourceStatusEnabled {
		if err := s.enqueueAssetRevocations(ctx, value.ID, "asset_"+string(status)); err != nil {
			return value, fmt.Errorf("revoke sessions for asset status change: %w", err)
		}
	}
	return value, nil
}

func (s *AccessService) protectAssetTarget(ctx context.Context, assetID, target, targetCiphertext string) (string, error) {
	if s.assetEncryptor != nil {
		if target == "" || targetCiphertext != "" {
			return "", fmt.Errorf("asset target must be supplied as plaintext exactly once when encryption is configured: %w", ErrValidation)
		}
		if !utf8.ValidString(target) || strings.IndexFunc(target, unicode.IsControl) >= 0 || len([]byte(target)) > 4096 {
			return "", fmt.Errorf("asset target is invalid: %w", ErrValidation)
		}
		plaintext := []byte(target)
		defer clear(plaintext)
		ciphertext, err := s.assetEncryptor.Encrypt(ctx, plaintext, []byte(assetID))
		if err != nil {
			return "", fmt.Errorf("encrypt asset target: %w", err)
		}
		return ciphertext, nil
	}
	if target != "" || targetCiphertext == "" {
		return "", fmt.Errorf("asset target_ciphertext is required when encryption is not configured: %w", ErrValidation)
	}
	if !utf8.ValidString(targetCiphertext) || strings.IndexFunc(targetCiphertext, unicode.IsControl) >= 0 || len([]byte(targetCiphertext)) > 1<<20 {
		return "", fmt.Errorf("asset target ciphertext is invalid: %w", ErrValidation)
	}
	return targetCiphertext, nil
}

func (s *AccessService) UpdateGatewayCapacity(ctx context.Context, actorID, gatewayID string, maxSessions int) (domain.Gateway, error) {
	if err := s.requireAdmin(ctx, actorID); err != nil {
		return domain.Gateway{}, err
	}
	if err := validateUUID(gatewayID, "gateway ID"); err != nil {
		return domain.Gateway{}, err
	}
	if maxSessions < 1 || maxSessions > maximumGatewayMaxSessions {
		return domain.Gateway{}, fmt.Errorf("gateway capacity is invalid: %w", ErrValidation)
	}
	var value domain.Gateway
	err := InTx(ctx, s.db, func(q repository.DBTX) error {
		var updateErr error
		value, updateErr = s.gateways.UpdateCapacity(ctx, q, gatewayID, maxSessions)
		if updateErr != nil {
			return updateErr
		}
		return s.appendAudit(ctx, q, domain.AuditEvent{
			EventType: "gateway.capacity_updated", ActorType: "admin", ActorID: stringPtr(actorID),
			RegionID: stringPtr(value.RegionID), Metadata: map[string]any{"gateway_id": value.ID, "max_sessions": value.MaxSessions}, Result: stringPtr("success"),
		})
	})
	if err != nil {
		return domain.Gateway{}, fmt.Errorf("update gateway capacity: %w", err)
	}
	return value, nil
}

func (s *AccessService) UpdateGatewayAuthSecretRef(ctx context.Context, actorID, gatewayID, authSecretRef string) (domain.Gateway, error) {
	if err := s.requireAdmin(ctx, actorID); err != nil {
		return domain.Gateway{}, err
	}
	if err := validateUUID(gatewayID, "gateway ID"); err != nil {
		return domain.Gateway{}, err
	}
	authSecretRef, err := normalizeGatewayCredentialReference(authSecretRef, true)
	if err != nil {
		return domain.Gateway{}, err
	}
	if err := s.validateGatewayCredentialReference(ctx, authSecretRef); err != nil {
		return domain.Gateway{}, err
	}
	var value domain.Gateway
	err = InTx(ctx, s.db, func(q repository.DBTX) error {
		var updateErr error
		value, updateErr = s.gateways.UpdateAuthSecretRef(ctx, q, gatewayID, authSecretRef)
		if updateErr != nil {
			return updateErr
		}
		return s.appendAudit(ctx, q, domain.AuditEvent{
			EventType: "gateway.credential_reference_updated", ActorType: "admin", ActorID: stringPtr(actorID),
			RegionID: stringPtr(value.RegionID), Metadata: map[string]any{"gateway_id": value.ID}, Result: stringPtr("success"),
		})
	})
	if err != nil {
		return domain.Gateway{}, fmt.Errorf("update gateway credential reference: %w", err)
	}
	return value, nil
}

func (s *AccessService) ListGatewayCatalog(ctx context.Context, actorID, gatewayID string) ([]domain.GatewayCatalogEntry, error) {
	if err := s.Authorize(ctx, actorID, authz.PermissionCatalogManage); err != nil {
		return nil, err
	}
	gatewayID = strings.TrimSpace(gatewayID)
	if err := validateUUID(gatewayID, "gateway ID"); err != nil {
		return nil, err
	}
	gatewayRecord, err := s.gateways.GetByID(ctx, s.db, gatewayID)
	if err != nil {
		return nil, fmt.Errorf("load gateway catalog gateway: %w", err)
	}
	if gatewayRecord.Status != domain.ResourceStatusEnabled {
		return nil, fmt.Errorf("gateway catalog is unavailable while gateway is %s: %w", gatewayRecord.Status, ErrValidation)
	}
	values, err := s.gateways.ListCatalogEntries(ctx, s.db, gatewayID)
	if err != nil {
		return nil, fmt.Errorf("list gateway catalog: %w", err)
	}
	return values, nil
}

func (s *AccessService) BindAssetGateway(ctx context.Context, actorID, assetID, gatewayID string, priority int) error {
	if err := s.requireAdmin(ctx, actorID); err != nil {
		return err
	}
	if err := validateUUID(assetID, "asset ID"); err != nil {
		return err
	}
	if err := validateUUID(gatewayID, "gateway ID"); err != nil {
		return err
	}
	if priority < 0 || priority > 100000 {
		return fmt.Errorf("gateway binding priority is invalid: %w", ErrValidation)
	}
	asset, err := s.assets.GetByID(ctx, s.db, assetID)
	if err != nil {
		return fmt.Errorf("validate gateway binding asset: %w", err)
	}
	gatewayRecord, err := s.gateways.GetByID(ctx, s.db, gatewayID)
	if err != nil {
		return fmt.Errorf("validate gateway binding gateway: %w", err)
	}
	if gatewayRecord.RegionID != asset.RegionID {
		return fmt.Errorf("gateway and asset regions differ: %w", ErrValidation)
	}
	err = InTx(ctx, s.db, func(q repository.DBTX) error {
		if bindErr := s.gateways.BindAsset(ctx, q, asset.ID, gatewayRecord.ID, priority); bindErr != nil {
			return bindErr
		}
		return s.appendAudit(ctx, q, domain.AuditEvent{
			EventType: "asset.gateway_bound", ActorType: "admin", ActorID: stringPtr(actorID),
			RegionID: stringPtr(asset.RegionID), AssetID: stringPtr(asset.ID),
			Metadata: map[string]any{"gateway_id": gatewayRecord.ID, "priority": priority}, Result: stringPtr("success"),
		})
	})
	if err != nil {
		return fmt.Errorf("bind asset gateway: %w", err)
	}
	return nil
}

func (s *AccessService) ListAssetGatewayBindings(ctx context.Context, actorID, assetID string) ([]domain.AssetGatewayBinding, error) {
	if err := s.requireAdmin(ctx, actorID); err != nil {
		return nil, err
	}
	if err := validateUUID(assetID, "asset ID"); err != nil {
		return nil, err
	}
	if _, err := s.assets.GetByID(ctx, s.db, assetID); err != nil {
		return nil, fmt.Errorf("validate binding asset: %w", err)
	}
	values, err := s.gateways.ListAssetBindings(ctx, s.db, assetID)
	if err != nil {
		return nil, fmt.Errorf("list asset gateway bindings: %w", err)
	}
	return values, nil
}

func (s *AccessService) UpdateAssetGatewayBinding(ctx context.Context, actorID, assetID, gatewayID string, input UpdateAssetGatewayBindingInput) (domain.AssetGatewayBinding, error) {
	if err := s.requireAdmin(ctx, actorID); err != nil {
		return domain.AssetGatewayBinding{}, err
	}
	if err := validateUUID(assetID, "asset ID"); err != nil {
		return domain.AssetGatewayBinding{}, err
	}
	if err := validateUUID(gatewayID, "gateway ID"); err != nil {
		return domain.AssetGatewayBinding{}, err
	}
	if input.Priority < 0 || input.Priority > 100000 {
		return domain.AssetGatewayBinding{}, fmt.Errorf("gateway binding priority is invalid: %w", ErrValidation)
	}
	asset, err := s.assets.GetByID(ctx, s.db, assetID)
	if err != nil {
		return domain.AssetGatewayBinding{}, fmt.Errorf("load binding asset: %w", err)
	}
	bindings, err := s.gateways.ListAssetBindings(ctx, s.db, assetID)
	if err != nil {
		return domain.AssetGatewayBinding{}, fmt.Errorf("list asset gateway bindings: %w", err)
	}
	found := false
	enabledCount := 0
	for _, binding := range bindings {
		if binding.Enabled {
			enabledCount++
		}
		if binding.GatewayID == gatewayID {
			found = true
		}
	}
	if !found {
		return domain.AssetGatewayBinding{}, fmt.Errorf("asset gateway binding not found: %w", repository.ErrNotFound)
	}
	if !input.Enabled && asset.Status == domain.ResourceStatusEnabled && enabledCount <= 1 {
		return domain.AssetGatewayBinding{}, fmt.Errorf("an enabled asset must retain a gateway binding: %w", ErrValidation)
	}
	var value domain.AssetGatewayBinding
	err = InTx(ctx, s.db, func(q repository.DBTX) error {
		var updateErr error
		value, updateErr = s.gateways.UpdateAssetBinding(ctx, q, assetID, gatewayID, input.Enabled, input.Priority)
		if updateErr != nil {
			return updateErr
		}
		return s.appendAudit(ctx, q, domain.AuditEvent{
			EventType: "asset.gateway_binding_updated", ActorType: "admin", ActorID: stringPtr(actorID),
			RegionID: stringPtr(asset.RegionID), AssetID: stringPtr(asset.ID), Result: stringPtr("success"),
			Metadata: map[string]any{"gateway_id": value.GatewayID, "enabled": value.Enabled, "priority": value.Priority},
		})
	})
	if err != nil {
		return domain.AssetGatewayBinding{}, fmt.Errorf("update asset gateway binding: %w", err)
	}
	return value, nil
}

func (s *AccessService) CreateAssetPort(ctx context.Context, actorID, assetID string, value domain.AssetPort) (domain.AssetPort, error) {
	if err := s.requireAdmin(ctx, actorID); err != nil {
		return domain.AssetPort{}, err
	}
	value.Protocol = strings.ToLower(strings.TrimSpace(value.Protocol))
	if value.Port < 1 || value.Port > 65535 || value.Protocol != "tcp" {
		return domain.AssetPort{}, fmt.Errorf("asset port is invalid: %w", ErrValidation)
	}
	if err := validateUUID(assetID, "asset ID"); err != nil {
		return domain.AssetPort{}, err
	}
	asset, err := s.assets.GetByID(ctx, s.db, assetID)
	if err != nil {
		return domain.AssetPort{}, fmt.Errorf("validate port asset: %w", err)
	}
	value.ID = id.New()
	value.AssetID = assetID
	value.Enabled = true
	err = InTx(ctx, s.db, func(q repository.DBTX) error {
		var createErr error
		value, createErr = s.assets.CreatePort(ctx, q, value)
		if createErr != nil {
			return createErr
		}
		return s.appendAudit(ctx, q, domain.AuditEvent{EventType: "asset_port.created", ActorType: "admin", ActorID: stringPtr(actorID), RegionID: stringPtr(asset.RegionID), AssetID: stringPtr(assetID), TargetPort: intPtr(value.Port), Result: stringPtr("success")})
	})
	if err != nil {
		return domain.AssetPort{}, fmt.Errorf("create asset port: %w", err)
	}
	return value, nil
}

func (s *AccessService) CreateAssetApprover(ctx context.Context, actorID, assetID string, value domain.AssetApprover) (domain.AssetApprover, error) {
	if err := s.requireAdmin(ctx, actorID); err != nil {
		return domain.AssetApprover{}, err
	}
	value.Role = strings.TrimSpace(value.Role)
	value.UserID = strings.TrimSpace(value.UserID)
	if value.ApprovalLevel < 1 || value.ApprovalLevel > 100 || value.Role == "" || value.UserID == "" {
		return domain.AssetApprover{}, requestValidation("请选择审批人、填写审批角色及 1–100 的审批级别")
	}
	if err := validateAdminText(value.Role, "approver role", 64, true); err != nil {
		return domain.AssetApprover{}, err
	}
	if err := validateUUID(assetID, "asset ID"); err != nil {
		return domain.AssetApprover{}, err
	}
	if err := validateUUID(value.UserID, "approver user ID"); err != nil {
		return domain.AssetApprover{}, err
	}
	asset, err := s.assets.GetByID(ctx, s.db, assetID)
	if err != nil {
		return domain.AssetApprover{}, fmt.Errorf("validate approver asset: %w", err)
	}
	user, err := s.users.GetByID(ctx, s.db, value.UserID)
	if err != nil {
		return domain.AssetApprover{}, fmt.Errorf("validate approver user: %w", err)
	}
	if user.Status != domain.UserStatusActive {
		return domain.AssetApprover{}, requestValidation("所选审批人已停用，请重新选择启用的账户")
	}
	value.ID = id.New()
	value.AssetID = assetID
	value.Enabled = true
	err = InTx(ctx, s.db, func(q repository.DBTX) error {
		var createErr error
		value, createErr = s.assets.CreateApprover(ctx, q, value)
		if createErr != nil {
			return createErr
		}
		return s.appendAudit(ctx, q, domain.AuditEvent{EventType: "asset_approver.created", ActorType: "admin", ActorID: stringPtr(actorID), RegionID: stringPtr(asset.RegionID), AssetID: stringPtr(assetID), Metadata: map[string]any{"approver_id": value.UserID}, Result: stringPtr("success")})
	})
	if err != nil {
		return domain.AssetApprover{}, fmt.Errorf("create asset approver: %w", err)
	}
	return value, nil
}

func (s *AccessService) requireAdmin(ctx context.Context, userID string) error {
	return s.Authorize(ctx, userID, authz.PermissionCatalogManage)
}

func validResourceStatus(value domain.ResourceStatus) bool {
	return value == domain.ResourceStatusEnabled || value == domain.ResourceStatusDisabled || value == domain.ResourceStatusMaint
}

func validRiskLevel(value domain.RiskLevel) bool {
	return value == domain.RiskLevelNormal || value == domain.RiskLevelSensitive || value == domain.RiskLevelCritical
}

func validateManagementEndpoint(value string) error {
	if err := validateAdminText(value, "management endpoint", 512, true); err != nil {
		return err
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed == nil || !parsed.IsAbs() || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.Opaque != "" {
		return fmt.Errorf("management endpoint is invalid: %w", ErrValidation)
	}
	if parsed.Path != "" && !strings.HasPrefix(parsed.Path, "/") {
		return fmt.Errorf("management endpoint is invalid: %w", ErrValidation)
	}
	if err := validateEndpointHost(parsed, false); err != nil {
		return fmt.Errorf("management endpoint is invalid: %w", ErrValidation)
	}
	return nil
}

func validatePublicEndpoint(value string) error {
	if err := validateAdminText(value, "public endpoint", 512, true); err != nil {
		return err
	}
	// Public endpoints are exposed to clients and must always identify a concrete
	// listener. Accept host:port or an http(s) URL with an explicit port, but do
	// not persist paths, queries, fragments, or credentials.
	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err != nil || parsed == nil || !parsed.IsAbs() || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.Opaque != "" || (parsed.Scheme != "https" && parsed.Scheme != "http") || (parsed.Path != "" && parsed.Path != "/") {
			return fmt.Errorf("public endpoint is invalid: %w", ErrValidation)
		}
		if err := validateEndpointHost(parsed, true); err != nil {
			return fmt.Errorf("public endpoint is invalid: %w", ErrValidation)
		}
		return nil
	}
	host, port, err := net.SplitHostPort(value)
	if err != nil || strings.TrimSpace(host) == "" || strings.TrimSpace(port) == "" || strings.ContainsAny(host, "/?#@[]") {
		return fmt.Errorf("public endpoint is invalid: %w", ErrValidation)
	}
	if err := validatePort(port); err != nil {
		return fmt.Errorf("public endpoint is invalid: %w", ErrValidation)
	}
	if err := validateHost(host); err != nil {
		return fmt.Errorf("public endpoint is invalid: %w", ErrValidation)
	}
	return nil
}

func validateAdminText(value, field string, maxRunes int, required bool) error {
	if required && strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is required: %w", field, ErrValidation)
	}
	if !utf8.ValidString(value) || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return fmt.Errorf("%s contains invalid control characters: %w", field, ErrValidation)
	}
	if maxRunes > 0 && utf8.RuneCountInString(value) > maxRunes {
		return fmt.Errorf("%s is too long: %w", field, ErrValidation)
	}
	return nil
}

func validateEndpointHost(parsed *url.URL, requirePort bool) error {
	host := parsed.Hostname()
	if err := validateHost(host); err != nil {
		return err
	}
	port := parsed.Port()
	explicitPort, hasExplicitPort, err := endpointPort(parsed.Host)
	if err != nil {
		return err
	}
	if hasExplicitPort {
		port = explicitPort
	}
	if requirePort && (!hasExplicitPort || port == "") {
		return fmt.Errorf("endpoint port is required")
	}
	if hasExplicitPort && port == "" {
		return fmt.Errorf("endpoint port is invalid")
	}
	if port != "" {
		if err := validatePort(port); err != nil {
			return err
		}
	}
	// A percent-encoded host is ambiguous across URL and HTTP parsers. Scoped
	// IPv6 addresses are not needed for configured gateway endpoints, so reject
	// all percent escapes in the authority.
	if strings.Contains(parsed.Host, "%") {
		return fmt.Errorf("endpoint host contains an escape")
	}
	return nil
}

func endpointPort(authority string) (string, bool, error) {
	if authority == "" {
		return "", false, nil
	}
	if strings.HasPrefix(authority, "[") {
		closing := strings.LastIndex(authority, "]")
		if closing < 0 {
			return "", false, fmt.Errorf("endpoint host is invalid")
		}
		if len(authority) == closing+1 {
			return "", false, nil
		}
		if authority[closing+1] != ':' {
			return "", false, fmt.Errorf("endpoint host is invalid")
		}
		return authority[closing+2:], true, nil
	}
	if strings.Count(authority, ":") == 0 {
		return "", false, nil
	}
	if strings.Count(authority, ":") != 1 {
		return "", false, fmt.Errorf("endpoint host is invalid")
	}
	parts := strings.SplitN(authority, ":", 2)
	return parts[1], true, nil
}

func validateHost(host string) error {
	if host == "" || strings.IndexFunc(host, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) >= 0 {
		return fmt.Errorf("endpoint host is invalid")
	}
	if net.ParseIP(host) != nil {
		return nil
	}
	if len(host) > 253 || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return fmt.Errorf("endpoint host is invalid")
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("endpoint host is invalid")
		}
		for _, character := range label {
			if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '-' || character == '_' {
				continue
			}
			return fmt.Errorf("endpoint host is invalid")
		}
	}
	return nil
}

func validatePort(value string) error {
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("endpoint port is invalid")
	}
	return nil
}
