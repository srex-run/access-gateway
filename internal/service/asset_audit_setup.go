package service

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/operationaudit"
	"github.com/srex-run/access-gateway/internal/sessionproxy"
	"github.com/srex-run/access-gateway/internal/settings"
	"k8s.io/apimachinery/pkg/util/validation"
)

func (s *AccessService) generateAssetAuditSetup(ctx context.Context, actorID string, input settings.CertificateRequest) (settings.CertificateBundle, error) {
	// Outbound enrollment has the same additional permission as the existing
	// MySQL enrollment endpoint, including for an unsaved asset draft.
	if err := s.Authorize(ctx, actorID, authz.PermissionRoleManage); err != nil {
		return settings.CertificateBundle{}, err
	}
	input.Protocol = operationaudit.NormalizeProtocol(input.Protocol)
	if !operationaudit.ValidProtocol(input.Protocol) || input.TargetPort < 1 || input.TargetPort > 65535 || input.ValidDays < 0 || input.ValidDays > 825 {
		return settings.CertificateBundle{}, requestValidation("请先选择有效的协议和 TCP 端口，证书有效期为 1–825 天")
	}
	if input.AssetID != "" {
		if err := validateUUID(input.AssetID, "asset ID"); err != nil {
			return settings.CertificateBundle{}, err
		}
		asset, err := s.assets.GetByID(ctx, s.db, input.AssetID)
		if err != nil {
			return settings.CertificateBundle{}, err
		}
		if input.Target != "" && asset.ExternalSource != nil && *asset.ExternalSource != "" {
			return settings.CertificateBundle{}, requestValidation("外部同步资产请使用已保存的目标地址")
		}
		if input.Target == "" {
			target, err := s.decryptAssetTarget(ctx, asset)
			if err != nil {
				return settings.CertificateBundle{}, err
			}
			input.Target = string(target)
			clear(target)
		}
	}
	host, err := auditSetupHost(input.Target)
	if err != nil {
		return settings.CertificateBundle{}, err
	}
	// The request cannot choose the gateway certificate's SANs.
	input.Hosts = []string{s.publicHost()}
	if input.Protocol != "ssh" {
		if input.Hosts[0] == "" {
			return settings.CertificateBundle{}, requestValidation("服务尚未配置 PUBLIC_URL，无法生成网关证书")
		}
		clientHost, err := s.clientAccessHost(ctx)
		if err != nil {
			return settings.CertificateBundle{}, err
		}
		if clientHost != "" && clientHost != input.Hosts[0] {
			input.Hosts = append(input.Hosts, clientHost)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	backend, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(input.TargetPort)))
	if err != nil {
		return settings.CertificateBundle{}, requestValidation("无法连接目标服务，请检查目标地址、端口及控制平面到资产的网络")
	}
	defer backend.Close()
	return buildAssetAuditSetup(ctx, backend, host, input)
}

func auditSetupHost(value string) (string, error) {
	host := strings.ToLower(strings.TrimSpace(value))
	if ip := net.ParseIP(host); ip != nil && !ip.IsUnspecified() && !ip.IsMulticast() {
		return host, nil
	}
	if host != "" && len(validation.IsDNS1123Subdomain(host)) == 0 && net.ParseIP(host) == nil {
		return host, nil
	}
	return "", requestValidation("请先填写目标服务的 IP 或域名，不含协议、端口或路径")
}

func buildAssetAuditSetup(ctx context.Context, backend net.Conn, host string, input settings.CertificateRequest) (settings.CertificateBundle, error) {
	identity, err := sessionproxy.InspectTargetIdentity(ctx, backend, input.Protocol, host)
	if err != nil {
		if input.Protocol == "ssh" {
			return settings.CertificateBundle{}, requestValidation("无法读取目标 SSH 主机公钥，请确认所选端口提供 SSH 服务且网络可达")
		}
		if errors.Is(err, sessionproxy.ErrIdentity) {
			return settings.CertificateBundle{}, requestValidation("目标服务证书已过期或尚未生效，请先更新目标服务证书")
		}
		return settings.CertificateBundle{}, requestValidation("无法读取目标服务 TLS 证书，请确认目标端口已启用 TLS（HTTP 服务需使用 HTTPS）且协议匹配")
	}
	purpose := "gateway"
	if input.Protocol == "ssh" {
		purpose = "ssh"
	}
	bundle, err := settings.GenerateAuditCertificate(settings.CertificateRequest{Purpose: purpose, Hosts: input.Hosts, ValidDays: input.ValidDays})
	if err != nil {
		return settings.CertificateBundle{}, requestValidation(err.Error())
	}
	bundle.TargetCertificateSHA256 = identity.CertificateSHA256
	if identity.SSHHostPublicKey != "" {
		bundle.TargetHostKeys = []string{identity.SSHHostPublicKey}
	}
	return bundle, nil
}
