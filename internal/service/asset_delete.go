package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/repository"
)

func (s *AccessService) DeleteAsset(ctx context.Context, actorID, assetID string) error {
	if err := s.requireAdmin(ctx, actorID); err != nil {
		return err
	}
	if err := validateUUID(assetID, "asset ID"); err != nil {
		return err
	}
	err := InTx(ctx, s.db, func(q repository.DBTX) error {
		asset, err := s.assets.Delete(ctx, q, assetID)
		if errors.Is(err, repository.ErrNotFound) {
			// A retry must still enqueue revocations if the first call lost its
			// connection after committing the deletion.
			_, err = s.assets.GetIncludingDeleted(ctx, q, assetID)
			return err
		}
		if err != nil {
			return err
		}
		return s.appendAudit(ctx, q, domain.AuditEvent{
			EventType: "asset.deleted", ActorType: "admin", ActorID: stringPtr(actorID),
			RegionID: stringPtr(asset.RegionID), AssetID: stringPtr(assetID), Result: stringPtr("success"),
		})
	})
	if err != nil {
		return fmt.Errorf("delete asset: %w", err)
	}
	return s.enqueueAssetRevocations(ctx, assetID, "asset_deleted")
}
