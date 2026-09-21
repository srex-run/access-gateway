package service

import (
	"context"
	"errors"
	"net"
	"strconv"
	"time"

	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/sessionproxy"
	"github.com/srex-run/access-gateway/internal/settings"
)

func (s *AccessService) GenerateMySQLAuditCertificate(ctx context.Context, actorID string, input settings.CertificateRequest) (settings.CertificateBundle, error) {
	if err := s.Authorize(ctx, actorID, authz.PermissionRoleManage); err != nil {
		return settings.CertificateBundle{}, err
	}
	if err := s.requireAdmin(ctx, actorID); err != nil {
		return settings.CertificateBundle{}, err
	}
	if validateUUID(input.AssetID, "asset ID") != nil || input.TargetPort < 1 || input.TargetPort > 65535 || input.Purpose != "mysql" || input.Protocol != "" || input.Target != "" {
		return settings.CertificateBundle{}, requestValidation("请选择 MySQL 资产和有效的资产端口")
	}
	asset, err := s.assets.GetByID(ctx, s.db, input.AssetID)
	if err != nil {
		return settings.CertificateBundle{}, err
	}
	if _, err := s.assets.GetPort(ctx, s.db, input.AssetID, input.TargetPort, "tcp"); err != nil {
		return settings.CertificateBundle{}, requestValidation("所选资产未配置此 TCP 端口，请先检查资产端口")
	}
	bundle, err := settings.GenerateAuditCertificate(settings.CertificateRequest{Purpose: "gateway", Hosts: input.Hosts, ValidDays: input.ValidDays})
	if err != nil {
		return settings.CertificateBundle{}, requestValidation(err.Error())
	}
	plaintext, err := s.decryptAssetTarget(ctx, asset)
	if err != nil {
		return settings.CertificateBundle{}, err
	}
	defer clear(plaintext)
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	backend, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(string(plaintext), strconv.Itoa(input.TargetPort)))
	if err != nil {
		return settings.CertificateBundle{}, requestValidation("无法连接所选 MySQL 资产，请检查资产地址、端口及控制面到资产的网络")
	}
	defer backend.Close()
	pin, err := sessionproxy.InspectMySQLCertificate(ctx, backend)
	if err != nil {
		if errors.Is(err, sessionproxy.ErrIdentity) {
			return settings.CertificateBundle{}, requestValidation("MySQL 资产证书已过期或尚未生效，请先更新服务器证书")
		}
		if errors.Is(err, sessionproxy.ErrProtocol) {
			return settings.CertificateBundle{}, requestValidation("所选资产端口未提供支持 TLS 的 MySQL 服务")
		}
		return settings.CertificateBundle{}, requestValidation("无法读取 MySQL 资产证书，请检查服务器 TLS 配置及控制面到资产的网络")
	}
	bundle.TargetCertificateSHA256 = pin
	return bundle, nil
}
