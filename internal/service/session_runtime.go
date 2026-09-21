package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/gateway"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/secretstore"
)

type GatewayRuntimeView struct {
	Mode       string `json:"mode"`
	PublicHost string `json:"public_host,omitempty"`
	PublicURL  string `json:"public_url,omitempty"`
}

// Base grant for ports without protocol auditing. newSession applies the
// asset's explicit audit policy before the grant is persisted.
func (s *AccessService) newNativeSession(asset domain.Asset, request domain.AccessRequest) (domain.Session, error) {
	if _, ok := s.gateway.(gateway.ApprovedSessionClient); !ok {
		return domain.Session{}, requestValidation("当前网关运行模式不支持原生加密隧道，请将 GATEWAY_RUNTIME 配置为 local、docker 或 kubernetes，并重启 access-gateway")
	}
	expiresAt := s.clock().UTC().Add(time.Duration(request.TTLSeconds) * time.Second)
	return domain.Session{ID: id.New(), RequestID: request.ID, GatewayID: asset.GatewayID, Status: domain.SessionProvisioning, ConnectionMode: gateway.ConnectionModeNative, ExpiresAt: &expiresAt}, nil
}

func approvedSessionExpiry(session domain.Session, request domain.AccessRequest) time.Time {
	if session.ExpiresAt != nil {
		return session.ExpiresAt.UTC()
	}
	// Sessions created before approval-based deadlines use their original
	// creation time, so a delayed retry cannot renew the approved grant.
	return session.CreatedAt.UTC().Add(time.Duration(request.TTLSeconds) * time.Second)
}

func (s *AccessService) GetGatewayRuntime(ctx context.Context, actorID string) (GatewayRuntimeView, error) {
	if err := s.requireAdmin(ctx, actorID); err != nil {
		return GatewayRuntimeView{}, err
	}
	if runtime, ok := s.gateway.(gateway.ApprovedSessionClient); ok {
		return GatewayRuntimeView{Mode: runtime.RuntimeMode(), PublicHost: s.publicHost(), PublicURL: s.publicURL}, nil
	}
	return GatewayRuntimeView{Mode: "http", PublicHost: s.publicHost(), PublicURL: s.publicURL}, nil
}

func (s *AccessService) createGatewaySession(ctx context.Context, route domain.Gateway, asset domain.Asset, request gateway.CreateSessionRequest) (gateway.CreateSessionResponse, error) {
	runtime, ok := s.gateway.(gateway.ApprovedSessionClient)
	if !ok {
		return s.gateway.CreateSession(ctx, route.ManagementEndpoint, request)
	}
	plaintext, err := s.decryptAssetTarget(ctx, asset)
	if err != nil {
		return gateway.CreateSessionResponse{}, err
	}
	defer clear(plaintext)
	return runtime.CreateApprovedSession(ctx, route.ID, request, string(plaintext))
}

func (s *AccessService) decryptAssetTarget(ctx context.Context, asset domain.Asset) ([]byte, error) {
	cipher, _ := s.assetEncryptor.(secretstore.Cipher)
	aad := []byte(asset.ID)
	if asset.ExternalSource != nil && strings.HasPrefix(*asset.ExternalSource, "cloud.") {
		cipher, aad = s.cloudCipher, cloudTargetAAD(asset.ID)
	}
	if cipher == nil {
		return nil, fmt.Errorf("approved asset target cannot be decrypted")
	}
	plaintext, err := cipher.Decrypt(ctx, asset.TargetCiphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("approved asset target cannot be decrypted")
	}
	return plaintext, nil
}

func (s *AccessService) ReconcileSessionResources(ctx context.Context) error {
	runtime, ok := s.gateway.(gateway.SessionResourceReconciler)
	if !ok {
		return nil
	}
	ended, err := runtime.Reconcile(ctx)
	failures := []error{err}
	for _, sessionID := range ended {
		closed, err := s.RevokeSession(ctx, sessionID, "session_agent_stopped")
		if err != nil {
			failures = append(failures, fmt.Errorf("reconcile stopped session %s: %w", sessionID, err))
			continue
		}
		if !isTerminalSession(closed.Status) || closed.Status == domain.SessionManualIntervention {
			continue
		}
		if err := runtime.AcknowledgeClosure(ctx, sessionID); err != nil {
			failures = append(failures, fmt.Errorf("acknowledge reconciled session %s: %w", sessionID, err))
		}
	}
	return errors.Join(failures...)
}
