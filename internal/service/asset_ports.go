package service

import (
	"context"
	"fmt"

	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/repository"
)

func (s *AccessService) DeleteAssetPort(ctx context.Context, actorID, assetID, portID string) error {
	if err := s.requireAdmin(ctx, actorID); err != nil {
		return err
	}
	if err := validateUUID(assetID, "asset ID"); err != nil {
		return err
	}
	if err := validateUUID(portID, "asset port ID"); err != nil {
		return err
	}
	err := InTx(ctx, s.db, func(q repository.DBTX) error {
		asset, err := s.assets.GetByIDForUpdate(ctx, q, assetID)
		if err != nil {
			return err
		}
		port, err := s.assets.DeletePort(ctx, q, assetID, portID)
		if err != nil {
			return err
		}
		if err := s.removeAssetPortAudit(ctx, q, actorID, asset, port.Port); err != nil {
			return err
		}
		return s.appendAudit(ctx, q, domain.AuditEvent{
			EventType: "asset_port.deleted", ActorType: "admin", ActorID: stringPtr(actorID),
			RegionID: stringPtr(asset.RegionID), AssetID: stringPtr(assetID), TargetPort: intPtr(port.Port),
			Result: stringPtr("success"), Metadata: map[string]any{"port_id": port.ID, "protocol": port.Protocol},
		})
	})
	if err != nil {
		return fmt.Errorf("delete asset port: %w", err)
	}
	return nil
}
