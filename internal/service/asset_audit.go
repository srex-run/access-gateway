package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/label"
	"github.com/srex-run/access-gateway/internal/operationaudit"
	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/secretstore"
	"github.com/srex-run/access-gateway/internal/sessionproxy"
	"github.com/srex-run/access-gateway/internal/settings"
	"golang.org/x/crypto/ssh"
)

type AssetAuditUpdate struct {
	Revision int64                               `json:"revision"`
	Profiles []settings.AuditProfile             `json:"profiles"`
	Keys     map[string]settings.AuditKeyChanges `json:"keys"`
}

type AssetAuditView struct {
	Revision   int64                              `json:"revision"`
	Profiles   []settings.AuditProfile            `json:"profiles"`
	HasSecrets map[string]settings.AuditKeyStatus `json:"has_secrets"`
}

// The entire value, including public certificates, belongs in an encrypted row.
type storedAssetAudit struct {
	Profiles []settings.AuditProfile       `json:"profiles"`
	Keys     map[string]settings.AuditKeys `json:"keys"`
}

func assetAuditAAD(assetID string) []byte {
	return []byte("access-gateway/asset-audit/v1/" + assetID)
}

func decodeAssetAudit(ctx context.Context, cipher secretstore.Cipher, row repository.AssetAudit) (storedAssetAudit, error) {
	if cipher == nil {
		return storedAssetAudit{}, ErrNotConfigured
	}
	plaintext, err := cipher.Decrypt(ctx, row.ConfigCiphertext, assetAuditAAD(row.AssetID))
	if err != nil {
		return storedAssetAudit{}, fmt.Errorf("decrypt asset audit configuration failed")
	}
	defer clear(plaintext)
	var value storedAssetAudit
	if err := json.Unmarshal(plaintext, &value); err != nil {
		return value, fmt.Errorf("invalid encrypted asset audit configuration")
	}
	return value, nil
}

func (v storedAssetAudit) registry() (*sessionproxy.Registry, error) {
	profiles := make([]settings.AuditProfile, 0, len(v.Profiles))
	for _, p := range v.Profiles {
		if p.AuditEnabled || auditProfileHasManagedCredentials(p, v.Keys[p.Name]) {
			profiles = append(profiles, p)
		}
	}
	return (settings.Config{AuditProfiles: profiles}).AuditRegistry(settings.Secrets{AuditProfiles: v.Keys})
}

func (v storedAssetAudit) view(revision int64) AssetAuditView {
	profiles := append([]settings.AuditProfile{}, v.Profiles...)
	return AssetAuditView{Revision: revision, Profiles: profiles, HasSecrets: (settings.Secrets{AuditProfiles: v.Keys}).Status().AuditProfiles}
}

// Legacy rules are copied only when they already match this asset and an
// enabled port. Saving converts them to independent asset-owned identities.
func (s *AccessService) loadAssetAudit(ctx context.Context, q repository.DBTX, asset domain.Asset) (storedAssetAudit, int64, error) {
	row, err := (repository.AssetAuditRepository{}).Get(ctx, q, asset.ID)
	if err == nil {
		if s.systemSettings == nil {
			return storedAssetAudit{}, 0, ErrNotConfigured
		}
		value, err := decodeAssetAudit(ctx, s.systemSettings.cipher, row)
		return value, row.Revision, err
	}
	if !errors.Is(err, repository.ErrNotFound) {
		return storedAssetAudit{}, 0, err
	}
	value := storedAssetAudit{Profiles: []settings.AuditProfile{}, Keys: map[string]settings.AuditKeys{}}
	if s.systemSettings == nil {
		return value, 0, nil
	}
	legacy, err := s.systemSettings.read(ctx, q)
	if err != nil {
		return value, 0, err
	}
	config, secrets, err := s.systemSettings.decode(ctx, legacy)
	if err != nil || len(config.AuditProfiles) == 0 {
		return value, 0, err
	}
	policy, err := (repository.WorkflowRepository{}).AssetPolicy(ctx, q, asset.ID)
	if err != nil {
		return value, 0, err
	}
	ports, err := s.assets.ListPorts(ctx, q, asset.ID)
	if err != nil {
		return value, 0, err
	}
	for _, p := range config.AuditProfiles {
		if operationaudit.ValidAssetProtocol(asset.AssetType) && operationaudit.NormalizeProtocol(p.Protocol) != operationaudit.NormalizeProtocol(asset.AssetType) {
			continue
		}
		candidate := policy.Labels.Copy()
		if candidate == nil {
			candidate = label.Labels{}
		}
		if named := candidate[sessionproxy.ProfileLabel]; named != "" && named != sessionproxy.AutoProfile && named != p.Name {
			continue
		}
		candidate[sessionproxy.ProfileLabel] = p.Name
		selector, err := label.Parse(p.Selector)
		if err != nil || !selector.Matches(candidate) {
			continue
		}
		for _, port := range ports {
			if port.Protocol == "tcp" && port.Port == p.Port {
				value.Profiles = append(value.Profiles, p)
				value.Keys[p.Name] = secrets.AuditProfiles[p.Name]
				break
			}
		}
	}
	return value, 0, nil
}

func (s *AccessService) GetAssetAudit(ctx context.Context, actorID, assetID string) (AssetAuditView, error) {
	if err := s.requireAdmin(ctx, actorID); err != nil {
		return AssetAuditView{}, err
	}
	if err := validateUUID(assetID, "asset ID"); err != nil {
		return AssetAuditView{}, err
	}
	asset, err := s.assets.GetByID(ctx, s.db, assetID)
	if err != nil {
		return AssetAuditView{}, err
	}
	value, revision, err := s.loadAssetAudit(ctx, s.db, asset)
	return value.view(revision), err
}

func buildAssetAudit(asset domain.Asset, previous storedAssetAudit, input AssetAuditUpdate) (storedAssetAudit, error) {
	if input.Revision < 0 || input.Profiles == nil || len(input.Profiles) > 100 {
		return storedAssetAudit{}, requestValidation("请提交有效的资源审计配置，最多 100 个端口")
	}
	config := settings.Config{AuditProfiles: append([]settings.AuditProfile{}, input.Profiles...)}
	secrets := settings.Secrets{AuditProfiles: map[string]settings.AuditKeys{}}
	changes := map[string]settings.AuditKeyChanges{}
	seenNames, seenPorts := map[string]bool{}, map[int]bool{}
	for i := range config.AuditProfiles {
		p := &config.AuditProfiles[i]
		if p.Port < 1 || p.Port > 65535 || seenPorts[p.Port] || p.Name == "" || seenNames[p.Name] {
			return storedAssetAudit{}, requestValidation("审计端口必须在 1-65535 之间，且不能重复")
		}
		seenNames[p.Name], seenPorts[p.Port] = true, true
		p.Protocol = operationaudit.NormalizeProtocol(p.Protocol)
		if !operationaudit.ValidProtocol(p.Protocol) || (operationaudit.ValidAssetProtocol(asset.AssetType) && p.Protocol != operationaudit.NormalizeProtocol(asset.AssetType)) {
			return storedAssetAudit{}, requestValidation("审计协议必须与资源类型一致")
		}
		oldName := p.Name
		p.Name = "asset." + asset.ID + "." + strconv.Itoa(p.Port)
		p.Selector = sessionproxy.ProfileLabel + "=" + p.Name
		change, provided := input.Keys[oldName]
		if !p.AuditEnabled && provided && change.PrivateKey == nil && change.SSHHostKey == nil && change.TargetSSHKey == nil {
			// The native tunnel form sends an explicit empty entry. This clears
			// credentials retained by an older audit-mode configuration without
			// putting any secret values in the request.
			secrets.AuditProfiles[p.Name] = settings.AuditKeys{}
		} else {
			secrets.AuditProfiles[p.Name] = previous.Keys[oldName]
		}
		if provided {
			changes[p.Name] = change
		}
	}
	for name := range input.Keys {
		if !seenNames[name] {
			return storedAssetAudit{}, requestValidation("密钥必须属于当前资源的审计端口")
		}
	}
	if err := config.ApplyAudit(settings.Config{}, &secrets, changes); err != nil {
		return storedAssetAudit{}, requestValidation(err.Error())
	}
	legacyProfiles := make([]settings.AuditProfile, 0, len(config.AuditProfiles))
	legacySecrets := settings.Secrets{AuditProfiles: map[string]settings.AuditKeys{}}
	for _, p := range config.AuditProfiles {
		k := secrets.AuditProfiles[p.Name]
		if !p.AuditEnabled && !auditProfileHasManagedCredentials(p, k) {
			continue
		}
		legacyProfiles = append(legacyProfiles, p)
		legacySecrets.AuditProfiles[p.Name] = k
		if p.Protocol == "ssh" {
			if p.Certificate != "" || p.GatewayCA != "" || p.TargetCA != "" || p.TargetCertificateSHA256 != "" || p.TargetServerName != "" || k.PrivateKey != "" {
				return storedAssetAudit{}, requestValidation("SSH 使用主机密钥，请清除 TLS 证书和私钥")
			}
			if k.SSHHostKey == "" {
				return storedAssetAudit{}, requestValidation(fmt.Sprintf("端口 %d：请先生成或上传网关 SSH 私钥", p.Port))
			}
			if len(p.TargetHostKeys) == 0 {
				return storedAssetAudit{}, requestValidation(fmt.Sprintf("端口 %d：请填写资产 SSH 主机公钥，可从 ECS 的 /etc/ssh/ssh_host_ed25519_key.pub 读取", p.Port))
			}
			for _, field := range []struct {
				name string
				keys []string
			}{{"资产 SSH 主机公钥", p.TargetHostKeys}, {"允许的客户端公钥", p.AuthorizedKeys}} {
				for i, key := range field.keys {
					_, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(key))
					if err != nil || len(strings.TrimSpace(string(rest))) != 0 {
						return storedAssetAudit{}, requestValidation(fmt.Sprintf("端口 %d：%s第 %d 行格式无效，请填写完整的 OpenSSH 公钥，不能填写私钥或 SHA-256 指纹", p.Port, field.name, i+1))
					}
				}
			}
			if len(p.AuthorizedKeys) > 0 && k.TargetSSHKey == "" {
				return storedAssetAudit{}, requestValidation(fmt.Sprintf("端口 %d：公钥登录还需要资产登录私钥；使用密码登录时，请清空允许的客户端公钥", p.Port))
			}
			if k.TargetSSHKey != "" {
				if _, err := ssh.ParsePrivateKey([]byte(k.TargetSSHKey)); err != nil {
					return storedAssetAudit{}, requestValidation(fmt.Sprintf("端口 %d：资产登录私钥格式无效，请上传或粘贴不带口令的 OpenSSH 或 PEM 私钥", p.Port))
				}
			}
		} else {
			if k.SSHHostKey != "" || k.TargetSSHKey != "" || p.SSHHostPublicKey != "" || len(p.TargetHostKeys) > 0 || len(p.AuthorizedKeys) > 0 {
				return storedAssetAudit{}, requestValidation("当前协议使用 TLS 证书，请清除 SSH 密钥")
			}
			if p.Certificate == "" || k.PrivateKey == "" {
				return storedAssetAudit{}, requestValidation("请上传或生成网关证书与私钥")
			}
		}
	}
	if len(legacyProfiles) > 0 {
		if _, err := (settings.Config{AuditProfiles: legacyProfiles}).AuditRegistry(legacySecrets); err != nil {
			// Registry errors contain administrator-supplied names but never PEMs.
			return storedAssetAudit{}, requestValidation("审计证书或密钥无效：" + err.Error())
		}
	}
	return storedAssetAudit{Profiles: config.AuditProfiles, Keys: secrets.AuditProfiles}, nil
}

func auditProfileHasManagedCredentials(p settings.AuditProfile, k settings.AuditKeys) bool {
	return p.Certificate != "" || p.GatewayCA != "" || p.TargetCA != "" || p.TargetServerName != "" || p.TargetCertificateSHA256 != "" || p.SSHHostPublicKey != "" || len(p.TargetHostKeys) > 0 || len(p.AuthorizedKeys) > 0 || k.PrivateKey != "" || k.SSHHostKey != "" || k.TargetSSHKey != ""
}

// Cryptographic validation and encryption run before opening the write transaction.
func (s *AccessService) prepareAssetAudit(ctx context.Context, actorID string, asset domain.Asset, input AssetAuditUpdate, previous storedAssetAudit) (repository.AssetAudit, error) {
	if s.systemSettings == nil {
		return repository.AssetAudit{}, requestValidation("服务尚未配置资产配置加密，请联系管理员")
	}
	clientHost, err := s.clientAccessHost(ctx)
	if err != nil {
		return repository.AssetAudit{}, err
	}
	input, err = prepareAuditIdentities(previous, input, s.publicHost(), clientHost)
	if err != nil {
		return repository.AssetAudit{}, err
	}
	value, err := buildAssetAudit(asset, previous, input)
	if err != nil {
		return repository.AssetAudit{}, err
	}
	if err := validateAssetCertificateHost(s.publicHost(), value.Profiles); err != nil {
		return repository.AssetAudit{}, err
	}
	plaintext, err := json.Marshal(value)
	if err != nil {
		return repository.AssetAudit{}, err
	}
	defer clear(plaintext)
	if len(plaintext) > 450<<10 {
		return repository.AssetAudit{}, requestValidation("资源证书配置不能超过 450 KiB")
	}
	ciphertext, err := s.systemSettings.cipher.Encrypt(ctx, plaintext, assetAuditAAD(asset.ID))
	if err != nil {
		return repository.AssetAudit{}, fmt.Errorf("encrypt asset audit configuration failed")
	}
	return repository.AssetAudit{AssetID: asset.ID, ConfigCiphertext: ciphertext, UpdatedBy: actorID}, nil
}

// Remove the matching saved profile so later asset edits cannot restore a deleted port.
func (s *AccessService) removeAssetPortAudit(ctx context.Context, q repository.DBTX, actorID string, asset domain.Asset, port int) error {
	repo := repository.AssetAuditRepository{}
	stored, err := repo.Get(ctx, q, asset.ID)
	if errors.Is(err, repository.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if s.systemSettings == nil {
		return ErrNotConfigured
	}
	previous, err := decodeAssetAudit(ctx, s.systemSettings.cipher, stored)
	if err != nil {
		return err
	}
	input := AssetAuditUpdate{Revision: stored.Revision, Profiles: make([]settings.AuditProfile, 0, len(previous.Profiles))}
	for _, profile := range previous.Profiles {
		if profile.Port != port {
			input.Profiles = append(input.Profiles, profile)
		}
	}
	if len(input.Profiles) == len(previous.Profiles) {
		return nil
	}
	row, err := s.prepareAssetAudit(ctx, actorID, asset, input, previous)
	if err != nil {
		return err
	}
	_, err = repo.Save(ctx, q, row, input.Revision)
	return err
}

func (s *AccessService) saveAssetAudit(ctx context.Context, q repository.DBTX, row repository.AssetAudit, input AssetAuditUpdate, previous []settings.AuditProfile) error {
	if _, err := (repository.AssetAuditRepository{}).Save(ctx, q, row, input.Revision); err != nil {
		return err
	}
	// Configured audit ports become available in the same transaction as the asset.
	for _, p := range input.Profiles {
		if _, err := s.assets.UpsertPort(ctx, q, domain.AssetPort{ID: id.New(), AssetID: row.AssetID, Port: p.Port, Protocol: "tcp", Enabled: true}); err != nil {
			return err
		}
	}
	if len(previous) > 0 {
		removed := map[int]bool{}
		for _, p := range previous {
			removed[p.Port] = true
		}
		for _, p := range input.Profiles {
			delete(removed, p.Port)
		}
		if len(removed) > 0 {
			ports, err := s.assets.ListPorts(ctx, q, row.AssetID)
			if err != nil {
				return err
			}
			keep := []int{}
			for _, port := range ports {
				if !removed[port.Port] || port.Protocol != "tcp" {
					keep = append(keep, port.Port)
				}
			}
			if _, err := s.assets.DisablePortsExcept(ctx, q, row.AssetID, keep); err != nil {
				return err
			}
		}
	}
	return nil
}

// ResolveAuditProfile performs one primary-key lookup, never a scan of all
// resources and their secrets. Legacy grants keep their existing resolver.
func (s *SystemSettingsService) ResolveAuditProfile(ctx context.Context, policy operationaudit.Policy) (*sessionproxy.Config, error) {
	parts := strings.Split(policy.Profile, ".")
	if len(parts) == 3 && parts[0] == "asset" && validateUUID(parts[1], "asset ID") == nil {
		row, err := (repository.AssetAuditRepository{}).Get(ctx, s.db, parts[1])
		if err != nil {
			return nil, err
		}
		value, err := decodeAssetAudit(ctx, s.cipher, row)
		if err != nil {
			return nil, err
		}
		registry, err := value.registry()
		if err != nil {
			return nil, err
		}
		return registry.Resolve(policy)
	}
	registry, err := s.AuditRegistry(ctx)
	if err != nil {
		return nil, err
	}
	return registry.Resolve(policy)
}
