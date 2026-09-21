package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/srex-run/access-gateway/internal/cmdb"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/repository"
)

type CMDBSyncResult struct {
	Revision string
	Created  int
	Updated  int
	Disabled int
	Skipped  bool
}

func (s *AccessService) SyncCMDB(ctx context.Context) (CMDBSyncResult, error) {
	if s.cmdb == nil {
		return CMDBSyncResult{}, fmt.Errorf("CMDB synchronization is not configured: %w", ErrNotConfigured)
	}
	snapshot, err := s.cmdb.FetchSnapshot(ctx)
	if err != nil {
		return CMDBSyncResult{}, fmt.Errorf("fetch CMDB snapshot: %w", err)
	}
	if !snapshot.Authoritative || strings.TrimSpace(snapshot.Revision) == "" {
		return CMDBSyncResult{}, fmt.Errorf("CMDB snapshot is not authoritative: %w", ErrValidation)
	}
	for index := range snapshot.Assets {
		if err := validateCMDBAsset(&snapshot.Assets[index]); err != nil {
			return CMDBSyncResult{}, fmt.Errorf("validate CMDB asset %d: %w", index, err)
		}
	}

	result := CMDBSyncResult{Revision: strings.TrimSpace(snapshot.Revision)}
	syncGeneration := id.New()
	revokeAssetIDs := make(map[string]struct{})
	err = InTx(ctx, s.db, func(q repository.DBTX) error {
		acquired, lockErr := s.assets.TryExternalSyncLock(ctx, q, s.cmdbSource)
		if lockErr != nil {
			return lockErr
		}
		if !acquired {
			result.Skipped = true
			return nil
		}
		for _, external := range snapshot.Assets {
			region, getErr := s.regions.GetByCode(ctx, q, external.RegionCode)
			if getErr != nil {
				return fmt.Errorf("resolve CMDB region %q: %w", external.RegionCode, getErr)
			}
			for _, gatewayID := range external.GatewayIDs {
				gatewayRecord, gatewayErr := s.gateways.GetByID(ctx, q, gatewayID)
				if gatewayErr != nil {
					return fmt.Errorf("resolve CMDB gateway: %w", gatewayErr)
				}
				if gatewayRecord.RegionID != region.ID {
					return fmt.Errorf("CMDB gateway and asset regions differ: %w", ErrValidation)
				}
			}

			assetID := id.New()
			existing, getErr := s.assets.GetByExternalIdentity(ctx, q, s.cmdbSource, external.ExternalID)
			if getErr == nil && existing.DeletedAt != nil {
				continue
			}
			switch {
			case getErr == nil:
				assetID = existing.ID
				result.Updated++
			case errors.Is(getErr, repository.ErrNotFound):
				result.Created++
			default:
				return getErr
			}
			ciphertext, encryptErr := s.protectAssetTarget(ctx, assetID, external.Target, "")
			if encryptErr != nil {
				return encryptErr
			}
			source := s.cmdbSource
			externalID := external.ExternalID
			generation := syncGeneration
			value, upsertErr := s.assets.UpsertExternal(ctx, q, domain.Asset{
				ID: assetID, RegionID: region.ID, GatewayID: external.GatewayIDs[0], Name: external.Name,
				AssetType: external.AssetType, TargetCiphertext: ciphertext,
				RiskLevel: domain.RiskLevel(external.RiskLevel), MaxTTLSeconds: external.MaxTTLSeconds,
				Status: domain.ResourceStatus(external.Status), ExternalSource: &source,
				ExternalID: &externalID, SyncGeneration: &generation,
			})
			if upsertErr != nil {
				return upsertErr
			}
			for priority, gatewayID := range external.GatewayIDs {
				if bindErr := s.gateways.BindAsset(ctx, q, value.ID, gatewayID, priority); bindErr != nil {
					return bindErr
				}
			}
			if _, disableErr := s.gateways.DisableAssetBindingsExcept(ctx, q, value.ID, external.GatewayIDs); disableErr != nil {
				return disableErr
			}
			ports := make([]int, 0, len(external.Ports))
			for _, port := range external.Ports {
				ports = append(ports, port.Port)
				if _, portErr := s.assets.UpsertPort(ctx, q, domain.AssetPort{
					ID: id.New(), AssetID: value.ID, Port: port.Port, Protocol: port.Protocol, Enabled: true,
				}); portErr != nil {
					return portErr
				}
			}
			if _, disableErr := s.assets.DisablePortsExcept(ctx, q, value.ID, ports); disableErr != nil {
				return disableErr
			}
			if value.Status != domain.ResourceStatusEnabled {
				revokeAssetIDs[value.ID] = struct{}{}
			}
		}
		disabled, disableErr := s.assets.DisableExternalMissing(ctx, q, s.cmdbSource, syncGeneration)
		if disableErr != nil {
			return disableErr
		}
		result.Disabled = len(disabled)
		for _, value := range disabled {
			revokeAssetIDs[value.ID] = struct{}{}
		}
		return s.appendAudit(ctx, q, domain.AuditEvent{
			EventType: "cmdb.sync_completed", ActorType: "system", Result: stringPtr("success"),
			Metadata: map[string]any{
				"source": s.cmdbSource, "revision": result.Revision,
				"created": result.Created, "updated": result.Updated, "disabled": result.Disabled,
			},
		})
	})
	if err != nil {
		return CMDBSyncResult{}, fmt.Errorf("apply CMDB snapshot: %w", err)
	}
	if result.Skipped {
		return result, nil
	}
	for assetID := range revokeAssetIDs {
		if err := s.enqueueAssetRevocations(ctx, assetID, "asset_disabled_by_cmdb"); err != nil {
			return result, fmt.Errorf("revoke sessions for disabled CMDB asset: %w", err)
		}
	}
	return result, nil
}

func validateCMDBAsset(value *cmdb.Asset) error {
	value.ExternalID = strings.TrimSpace(value.ExternalID)
	value.RegionCode = strings.TrimSpace(value.RegionCode)
	value.Name = strings.TrimSpace(value.Name)
	value.AssetType = strings.TrimSpace(value.AssetType)
	value.Target = strings.TrimSpace(value.Target)
	value.RiskLevel = strings.TrimSpace(value.RiskLevel)
	value.Status = strings.TrimSpace(value.Status)
	if err := validateAdminText(value.ExternalID, "CMDB external ID", 256, true); err != nil {
		return err
	}
	if err := validateAdminText(value.RegionCode, "CMDB region code", 64, true); err != nil {
		return err
	}
	if err := validateAdminText(value.Name, "CMDB asset name", 128, true); err != nil {
		return err
	}
	if err := validateAdminText(value.AssetType, "CMDB asset type", 64, true); err != nil {
		return err
	}
	if value.Target == "" || len([]byte(value.Target)) > 4096 || strings.IndexFunc(value.Target, unicode.IsControl) >= 0 {
		return fmt.Errorf("CMDB asset target is invalid: %w", ErrValidation)
	}
	if !validRiskLevel(domain.RiskLevel(value.RiskLevel)) || !validResourceStatus(domain.ResourceStatus(value.Status)) || value.MaxTTLSeconds < 1 || value.MaxTTLSeconds > maxGatewayAssetTTLSeconds {
		return fmt.Errorf("CMDB asset policy is invalid: %w", ErrValidation)
	}
	if len(value.GatewayIDs) < 1 || len(value.GatewayIDs) > 100 || len(value.Ports) < 1 || len(value.Ports) > 1000 {
		return fmt.Errorf("CMDB asset routing or ports are invalid: %w", ErrValidation)
	}
	seenGateways := make(map[string]struct{}, len(value.GatewayIDs))
	for index, gatewayID := range value.GatewayIDs {
		gatewayID = strings.TrimSpace(gatewayID)
		if err := validateUUID(gatewayID, "CMDB gateway ID"); err != nil {
			return err
		}
		if _, exists := seenGateways[gatewayID]; exists {
			return fmt.Errorf("CMDB asset contains duplicate gateways: %w", ErrValidation)
		}
		seenGateways[gatewayID] = struct{}{}
		value.GatewayIDs[index] = gatewayID
	}
	seenPorts := make(map[int]struct{}, len(value.Ports))
	for index := range value.Ports {
		value.Ports[index].Protocol = strings.ToLower(strings.TrimSpace(value.Ports[index].Protocol))
		if value.Ports[index].Port < 1 || value.Ports[index].Port > 65535 || value.Ports[index].Protocol != "tcp" {
			return fmt.Errorf("CMDB asset port is invalid: %w", ErrValidation)
		}
		if _, exists := seenPorts[value.Ports[index].Port]; exists {
			return fmt.Errorf("CMDB asset contains duplicate ports: %w", ErrValidation)
		}
		seenPorts[value.Ports[index].Port] = struct{}{}
	}
	return nil
}

func validExternalSource(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}
