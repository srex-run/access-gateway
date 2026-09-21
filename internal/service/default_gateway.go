package service

import (
	"context"
	"net/url"

	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/gateway"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/repository"
)

func (s *AccessService) publicHost() string {
	if endpoint, err := url.Parse(s.publicURL); err == nil && endpoint.Hostname() != "" {
		return endpoint.Hostname()
	}
	if runtime, ok := s.gateway.(gateway.ApprovedSessionClient); ok {
		return runtime.PublicHost()
	}
	return ""
}

// resolveAssetGateway retains explicit legacy routes; new forms omit gatewayID.
// The caller owns the transaction so an unsuccessful asset/sync creates no route.
func (s *AccessService) resolveAssetGateway(ctx context.Context, q repository.DBTX, regionID, gatewayID string) (domain.Gateway, error) {
	if gatewayID != "" {
		value, err := s.gateways.GetByID(ctx, q, gatewayID)
		if err != nil {
			return domain.Gateway{}, err
		}
		if regionID != "" && value.RegionID != regionID {
			return domain.Gateway{}, requestValidation("网关与资产的接入分组不匹配")
		}
		return value, nil
	}
	var region domain.Region
	var err error
	if regionID == "" {
		region, err = s.regions.EnsureDefault(ctx, q, id.New())
	} else {
		region, err = s.regions.GetByID(ctx, q, regionID)
	}
	if err != nil {
		return domain.Gateway{}, err
	}
	if region.Status != domain.ResourceStatusEnabled {
		return domain.Gateway{}, requestValidation("资产接入分组已停用")
	}
	endpoint, host := s.gatewayBaseURL, s.publicHost()
	if runtime, ok := s.gateway.(gateway.ApprovedSessionClient); ok {
		endpoint = "https://session-runtime.invalid/" + runtime.RuntimeMode()
	}
	if endpoint == "" || host == "" {
		return domain.Gateway{}, requestValidation("服务的网关运行环境未配置，请检查 PUBLIC_URL 与 GATEWAY_RUNTIME")
	}
	capacity := s.gatewayMaxSessions
	if capacity == 0 {
		capacity = defaultGatewayMaxSessions
	}
	return s.gateways.EnsureDefault(ctx, q, domain.Gateway{ID: id.New(), RegionID: region.ID,
		ManagementEndpoint: endpoint, PublicEndpoint: host, MaxSessions: capacity})
}
