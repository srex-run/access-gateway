package service

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/gateway"
	"github.com/srex-run/access-gateway/internal/operationaudit"
	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/settings"
)

// Every protocol uses the same session agent, protected grant and durable
// operation spool. Native ports remain native until audit is explicitly enabled.
func (s *AccessService) newSession(ctx context.Context, q repository.DBTX, asset domain.Asset, request domain.AccessRequest) (domain.Session, error) {
	session, err := s.newNativeSession(asset, request)
	if err != nil {
		return session, err
	}
	policy, err := s.sessionAuditPolicy(ctx, q, asset, request)
	if err != nil {
		return domain.Session{}, err
	}
	if policy != (operationaudit.Policy{}) {
		session.ConnectionMode, session.AuditPolicy = gateway.ConnectionModeAudit, policy
	}
	if err := validateWebAccess(request, policy); err != nil {
		return domain.Session{}, err
	}
	if request.SourceIP != nil {
		enabled, err := s.clientAccessEnabledIn(ctx, q)
		if err != nil {
			return domain.Session{}, err
		}
		if !enabled {
			return domain.Session{}, requestValidation("客户端访问已关闭，请重新申请站内访问")
		}
	}
	return session, nil
}

func (s *AccessService) sessionAuditPolicy(ctx context.Context, q repository.DBTX, asset domain.Asset, request domain.AccessRequest) (operationaudit.Policy, error) {
	value, err := s.loadSessionAudit(ctx, q, asset.ID)
	if err != nil {
		return operationaudit.Policy{}, err
	}
	return value.sessionPolicy(asset.AssetType, request)
}

func (s *AccessService) loadSessionAudit(ctx context.Context, q repository.DBTX, assetID string) (storedAssetAudit, error) {
	row, err := (repository.AssetAuditRepository{}).Get(ctx, q, assetID)
	if errors.Is(err, repository.ErrNotFound) {
		return storedAssetAudit{}, nil
	}
	if err != nil {
		return storedAssetAudit{}, err
	}
	if s.systemSettings == nil {
		return storedAssetAudit{}, ErrNotConfigured
	}
	return decodeAssetAudit(ctx, s.systemSettings.cipher, row)
}

func auditProfileRequiresAccount(p settings.AuditProfile) bool {
	return p.AuditEnabled && p.Protocol != "http"
}

func (v storedAssetAudit) targetAccountRequired(port int) bool {
	return slices.ContainsFunc(v.Profiles, func(p settings.AuditProfile) bool {
		return p.Port == port && auditProfileRequiresAccount(p)
	})
}

func (v storedAssetAudit) sessionPolicy(protocol string, request domain.AccessRequest) (operationaudit.Policy, error) {
	for _, p := range v.Profiles {
		if p.Port != request.TargetPort || !p.AuditEnabled {
			continue
		}
		if operationaudit.ValidAssetProtocol(protocol) && p.Protocol != operationaudit.NormalizeProtocol(protocol) {
			return operationaudit.Policy{}, requestValidation("端口审计协议与资产类型不一致，请重新配置")
		}
		if auditProfileRequiresAccount(p) && (request.TargetAccount == nil || *request.TargetAccount == "") {
			return operationaudit.Policy{}, requestValidation(fmt.Sprintf("端口 %d 已启用操作审计，请填写目标账号（登录 SSH 或数据库的用户名，例如 root、admin 或 test）", request.TargetPort))
		}
		registry, err := (settings.Config{AuditProfiles: []settings.AuditProfile{p}}).AuditRegistry(settings.Secrets{AuditProfiles: v.Keys})
		if err != nil {
			return operationaudit.Policy{}, requestValidation("端口审计证书或密钥配置无效，请联系管理员")
		}
		return registry.SelectForProtocol(nil, request.TargetPort, p.Protocol)
	}
	return operationaudit.Policy{}, nil
}

// Generate the agent identity once when audit is enabled. It is encrypted with
// the asset configuration and reused across sessions; private keys never need
// to pass through the browser. Target trust must still be supplied by the admin.
func prepareAuditIdentities(previous storedAssetAudit, input AssetAuditUpdate, host string, clientHosts ...string) (AssetAuditUpdate, error) {
	if input.Revision < 0 || input.Profiles == nil || len(input.Profiles) > 100 {
		return input, requestValidation("请提交有效的资源审计配置，最多 100 个端口")
	}
	input.Profiles = slices.Clone(input.Profiles)
	input.Keys = maps.Clone(input.Keys)
	if input.Keys == nil {
		input.Keys = map[string]settings.AuditKeyChanges{}
	}
	for i := range input.Profiles {
		p := &input.Profiles[i]
		if !p.AuditEnabled {
			continue
		}
		key, change := previous.Keys[p.Name], input.Keys[p.Name]
		purpose := "gateway"
		if operationaudit.NormalizeProtocol(p.Protocol) == "ssh" {
			purpose = "ssh"
			if key.SSHHostKey != "" || change.SSHHostKey != nil {
				continue
			}
		} else if key.PrivateKey != "" || change.PrivateKey != nil || p.Certificate != "" {
			continue
		}
		hosts := []string{host}
		for _, clientHost := range clientHosts {
			if clientHost != "" && clientHost != host {
				hosts = append(hosts, clientHost)
			}
		}
		bundle, err := settings.GenerateAuditCertificate(settings.CertificateRequest{Purpose: purpose, Hosts: hosts})
		if err != nil {
			return input, requestValidation("无法生成会话审计身份，请检查 PUBLIC_URL 配置")
		}
		if purpose == "ssh" {
			change.SSHHostKey = &bundle.SSHHostKey
		} else {
			p.Certificate, p.GatewayCA = bundle.Certificate, bundle.CA
			change.PrivateKey = &bundle.PrivateKey
		}
		input.Keys[p.Name] = change
	}
	return input, nil
}

// Public trust only. Never attach a proxy Config or its private keys to a view.
type SessionAuditTrust struct {
	CACertificate    string `json:"ca_certificate,omitempty"`
	SSHHostPublicKey string `json:"ssh_host_public_key,omitempty"`
}

func (s *AccessService) sessionAuditTrust(ctx context.Context, session domain.Session, assetID string) (*SessionAuditTrust, error) {
	if s.systemSettings == nil {
		return nil, nil
	}
	row, err := (repository.AssetAuditRepository{}).Get(ctx, s.db, assetID)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	value, err := decodeAssetAudit(ctx, s.systemSettings.cipher, row)
	if err != nil {
		return nil, err
	}
	return value.clientTrust(session.AuditPolicy), nil
}

func (v storedAssetAudit) clientTrust(policy operationaudit.Policy) *SessionAuditTrust {
	for _, p := range v.Profiles {
		if p.Name != policy.Profile {
			continue
		}
		registry, err := (settings.Config{AuditProfiles: []settings.AuditProfile{p}}).AuditRegistry(settings.Secrets{AuditProfiles: v.Keys})
		if err != nil {
			return nil
		}
		if _, err = registry.Resolve(policy); err != nil {
			// A changed configuration must not advertise a different identity for
			// an already running agent. Its original grant remains immutable.
			return nil
		}
		ca := p.GatewayCA
		if ca == "" {
			ca = p.Certificate
		}
		return &SessionAuditTrust{CACertificate: ca, SSHHostPublicKey: p.SSHHostPublicKey}
	}
	return nil
}
