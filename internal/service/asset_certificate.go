package service

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"strings"

	"github.com/srex-run/access-gateway/internal/settings"
)

// Gateway certificates always identify the deployment's configured service host.
// Only target certificates accept hostnames supplied by an asset administrator.
func (s *AccessService) GenerateAssetAuditCertificate(ctx context.Context, actorID string, input settings.CertificateRequest) (settings.CertificateBundle, error) {
	if err := s.requireAdmin(ctx, actorID); err != nil {
		return settings.CertificateBundle{}, err
	}
	if input.Purpose == "setup" {
		return s.generateAssetAuditSetup(ctx, actorID, input)
	}
	if input.Purpose == "gateway" || input.Purpose == "mysql" {
		host := s.publicHost()
		if host == "" {
			return settings.CertificateBundle{}, requestValidation("服务尚未配置 PUBLIC_URL，无法生成网关证书")
		}
		input.Hosts = []string{host}
		clientHost, err := s.clientAccessHost(ctx)
		if err != nil {
			return settings.CertificateBundle{}, err
		}
		if clientHost != "" && clientHost != host {
			input.Hosts = append(input.Hosts, clientHost)
		}
	}
	if input.Purpose == "mysql" {
		return s.GenerateMySQLAuditCertificate(ctx, actorID, input)
	}
	bundle, err := settings.GenerateAuditCertificate(input)
	if err != nil {
		return settings.CertificateBundle{}, requestValidation(err.Error())
	}
	return bundle, nil
}

func validateAssetCertificateHost(host string, profiles []settings.AuditProfile) error {
	if host == "" {
		return nil
	}
	for _, profile := range profiles {
		if profile.Protocol == "ssh" {
			continue
		}
		if strings.TrimSpace(profile.Certificate) == "" {
			continue
		}
		block, _ := pem.Decode([]byte(profile.Certificate))
		if block == nil {
			return requestValidation("请生成或上传网关证书")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || cert.VerifyHostname(host) != nil {
			return requestValidation("网关证书与当前服务地址不匹配，请重新生成或上传包含 " + host + " 的证书")
		}
	}
	return nil
}
