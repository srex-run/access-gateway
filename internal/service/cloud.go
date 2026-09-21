package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/catalogrelease"
	"github.com/srex-run/access-gateway/internal/cloudassets"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/secretstore"
)

type CloudAccountInput struct {
	Name         string  `json:"name"`
	Provider     string  `json:"provider"`
	Enabled      bool    `json:"enabled"`
	Revision     int64   `json:"revision"`
	AccessKey    string  `json:"access_key"`
	SecretKey    string  `json:"secret_key"`
	SessionToken *string `json:"session_token"`
}

type CloudValidationError struct{ Message string }

func (e *CloudValidationError) Error() string { return e.Message }
func (e *CloudValidationError) Unwrap() error { return ErrValidation }
func cloudValidation(message string) error    { return &CloudValidationError{Message: message} }

func (s *AccessService) ListCloudAccounts(ctx context.Context, actor string) ([]domain.CloudAccount, error) {
	if err := s.requireAdmin(ctx, actor); err != nil {
		return nil, err
	}
	return s.cloud.ListAccounts(ctx, s.db)
}

func (s *AccessService) SaveCloudAccount(ctx context.Context, actor, accountID string, input CloudAccountInput) (domain.CloudAccount, error) {
	if err := s.Authorize(ctx, actor, authz.PermissionRoleManage); err != nil {
		return domain.CloudAccount{}, err
	}
	if s.cloudCipher == nil {
		return domain.CloudAccount{}, ErrNotConfigured
	}
	input.Name, input.Provider = strings.TrimSpace(input.Name), strings.TrimSpace(input.Provider)
	if validateAdminText(input.Name, "cloud account name", 128, true) != nil || !cloudassets.ValidProvider(input.Provider) {
		return domain.CloudAccount{}, cloudValidation("云账号名称或云厂商无效")
	}
	if accountID != "" && validateUUID(accountID, "cloud account ID") != nil {
		return domain.CloudAccount{}, ErrValidation
	}
	creating := accountID == ""
	if creating {
		accountID = id.New()
	}
	var saved domain.CloudAccount
	err := InTx(ctx, s.db, func(q repository.DBTX) error {
		value := domain.CloudAccount{ID: accountID, Provider: input.Provider}
		if !creating {
			var err error
			value, err = s.cloud.GetAccount(ctx, q, accountID, true)
			if err != nil {
				return err
			}
			if value.Revision != input.Revision {
				return repository.ErrConflict
			}
			if value.Provider != input.Provider {
				return cloudValidation("已有云账号不能更换云厂商，请新增账号")
			}
		}
		credentials := cloudassets.Credentials{}
		if !creating {
			var err error
			credentials, err = s.cloudCredentials(ctx, value)
			if err != nil {
				return err
			}
		}
		credentials, err := mergeCloudCredentials(credentials, input)
		if err != nil {
			return err
		}
		plaintext, err := json.Marshal(credentials)
		if err != nil {
			return err
		}
		defer clear(plaintext)
		value.CredentialsCiphertext, err = s.cloudCipher.Encrypt(ctx, plaintext, cloudAccountAAD(accountID))
		if err != nil {
			return err
		}
		value.Name, value.Enabled = input.Name, input.Enabled
		if creating {
			saved, err = s.cloud.CreateAccount(ctx, q, value)
		} else {
			saved, err = s.cloud.UpdateAccount(ctx, q, value)
		}
		if err != nil {
			return err
		}
		return s.appendAudit(ctx, q, domain.AuditEvent{EventType: "cloud_account.saved", ActorType: "admin", ActorID: &actor,
			Result: stringPtr("success"), Metadata: map[string]any{"account_id": accountID, "provider": saved.Provider, "revision": saved.Revision, "enabled": saved.Enabled}})
	})
	return saved, err
}

func mergeCloudCredentials(existing cloudassets.Credentials, input CloudAccountInput) (cloudassets.Credentials, error) {
	ak, sk := strings.TrimSpace(input.AccessKey), strings.TrimSpace(input.SecretKey)
	if (ak == "") != (sk == "") {
		return cloudassets.Credentials{}, cloudValidation("更新凭据时需同时填写 AK 和 SK")
	}
	if ak != "" {
		existing.AccessKey, existing.SecretKey, existing.SessionToken = ak, sk, ""
	}
	if input.SessionToken != nil {
		existing.SessionToken = strings.TrimSpace(*input.SessionToken)
	}
	for _, value := range []string{existing.AccessKey, existing.SecretKey} {
		if value == "" || len(value) > 256 || strings.IndexFunc(value, unicode.IsSpace) >= 0 || strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return cloudassets.Credentials{}, cloudValidation("AK 和 SK 不能为空，且不能包含空白或控制字符")
		}
	}
	if len(existing.SessionToken) > 8192 || strings.IndexFunc(existing.SessionToken, unicode.IsControl) >= 0 {
		return cloudassets.Credentials{}, cloudValidation("临时凭据 Token 无效")
	}
	if input.Provider == "huaweicloud" && existing.SessionToken != "" {
		return cloudassets.Credentials{}, cloudValidation("华为云当前使用 AK/SK 认证")
	}
	return existing, nil
}

func (s *AccessService) cloudCredentials(ctx context.Context, account domain.CloudAccount) (cloudassets.Credentials, error) {
	plaintext, err := s.cloudCipher.Decrypt(ctx, account.CredentialsCiphertext, cloudAccountAAD(account.ID))
	if err != nil {
		return cloudassets.Credentials{}, ErrNotConfigured
	}
	defer clear(plaintext)
	var value cloudassets.Credentials
	if json.Unmarshal(plaintext, &value) != nil {
		return value, ErrNotConfigured
	}
	return value, nil
}

func cloudAccountAAD(accountID string) []byte {
	return []byte("access-gateway/cloud-account/v1/" + accountID)
}
func cloudTargetAAD(assetID string) []byte {
	return []byte("access-gateway/cloud-target/v1/" + assetID)
}
func cloudSource(accountID string) string { return "cloud." + accountID }

func (s *AccessService) QueueCloudSync(ctx context.Context, actor, accountID string, input domain.CloudSyncInput) (domain.CloudSyncJob, error) {
	if err := s.requireAdmin(ctx, actor); err != nil {
		return domain.CloudSyncJob{}, err
	}
	if s.cloudCipher == nil || s.cloudDiscoverer == nil {
		return domain.CloudSyncJob{}, ErrNotConfigured
	}
	if validateUUID(accountID, "cloud account ID") != nil {
		return domain.CloudSyncJob{}, ErrValidation
	}
	if err := normalizeCloudSync(&input); err != nil {
		return domain.CloudSyncJob{}, err
	}
	var job domain.CloudSyncJob
	err := InTx(ctx, s.db, func(q repository.DBTX) error {
		account, err := s.cloud.GetAccount(ctx, q, accountID, true)
		if err != nil {
			return err
		}
		if !account.Enabled {
			return cloudValidation("云账号已停用")
		}
		route, err := s.resolveAssetGateway(ctx, q, input.RegionID, input.GatewayID)
		if err != nil {
			return err
		}
		input.RegionID, input.GatewayID = route.RegionID, route.ID
		if err := s.validateCloudDestinations(ctx, q, input); err != nil {
			return err
		}
		job, err = s.cloud.CreateJob(ctx, q, domain.CloudSyncJob{ID: id.New(), AccountID: account.ID, AccountRevision: account.Revision, ActorID: actor, Input: input})
		if err != nil {
			return err
		}
		return s.appendAudit(ctx, q, domain.AuditEvent{EventType: "cloud_sync.queued", ActorType: "admin", ActorID: &actor,
			RegionID: &input.RegionID, Result: stringPtr("success"), Metadata: map[string]any{"account_id": accountID, "job_id": job.ID, "cloud_region": input.CloudRegion, "instance_count": len(input.InstanceIDs)}})
	})
	return job, err
}

func normalizeCloudSync(input *domain.CloudSyncInput) error {
	input.CloudRegion = strings.TrimSpace(input.CloudRegion)
	if !cloudassets.ValidRegion(input.CloudRegion) {
		return cloudValidation("请输入有效的云 Region 编码")
	}
	if input.RegionID != "" && validateUUID(input.RegionID, "region ID") != nil {
		return cloudValidation("接入分组 ID 无效")
	}
	if input.GatewayID != "" && validateUUID(input.GatewayID, "gateway ID") != nil {
		return cloudValidation("网关 ID 无效")
	}
	if validateUUID(input.ApproverID, "approver ID") != nil {
		return cloudValidation("审批人 ID 必须是有效的 UUID")
	}
	if len(input.InstanceIDs) > 100 {
		return cloudValidation("单次定向同步最多指定 100 个实例")
	}
	ids := make([]string, 0, len(input.InstanceIDs))
	for _, value := range input.InstanceIDs {
		value = strings.TrimSpace(value)
		if !cloudassets.ValidInstanceID(value) {
			return cloudValidation("实例 ID 无效")
		}
		ids = append(ids, value)
	}
	slices.Sort(ids)
	input.InstanceIDs = slices.Compact(ids)
	if len(input.Ports) == 0 || len(input.Ports) > 100 {
		return cloudValidation("新资产需配置 1 到 100 个 TCP 端口")
	}
	for _, port := range input.Ports {
		if port < 1 || port > 65535 {
			return cloudValidation("端口范围必须是 1 到 65535")
		}
	}
	input.Ports = slices.Clone(input.Ports)
	slices.Sort(input.Ports)
	input.Ports = slices.Compact(input.Ports)
	if !validRiskLevel(input.RiskLevel) || input.MaxTTLSeconds < 1 || input.MaxTTLSeconds > maxGatewayAssetTTLSeconds {
		return cloudValidation("新资产的风险等级或最长访问时限无效")
	}
	return nil
}

func (s *AccessService) validateCloudDestinations(ctx context.Context, q repository.DBTX, input domain.CloudSyncInput) error {
	region, err := s.regions.GetByID(ctx, q, input.RegionID)
	if err != nil {
		return err
	}
	gateway, err := s.gateways.GetByID(ctx, q, input.GatewayID)
	if err != nil {
		return err
	}
	if region.Status != domain.ResourceStatusEnabled || gateway.Status != domain.ResourceStatusEnabled || gateway.RegionID != region.ID {
		return cloudValidation("网关或其接入分组已停用，或接入分组不匹配")
	}
	user, err := s.users.GetByID(ctx, q, input.ApproverID)
	if err != nil {
		return err
	}
	if user.Status != domain.UserStatusActive {
		return cloudValidation("新资产审批人已停用")
	}
	return nil
}

func (s *AccessService) ListCloudSyncJobs(ctx context.Context, actor, regionID string) ([]domain.CloudSyncJob, error) {
	if err := s.requireAdmin(ctx, actor); err != nil {
		return nil, err
	}
	if regionID != "" && validateUUID(regionID, "region ID") != nil {
		return nil, ErrValidation
	}
	return s.cloud.ListJobs(ctx, s.db, regionID)
}

// ProcessCloudSync runs outside the session outbox so slow cloud APIs cannot delay revocation.
func (s *AccessService) ProcessCloudSync(ctx context.Context) error {
	if s.cloudCipher == nil || s.cloudDiscoverer == nil {
		return nil
	}
	job, err := s.cloud.ClaimJob(ctx, s.db, id.New())
	if errors.Is(err, repository.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	workCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	err = s.runCloudSync(workCtx, &job)
	cancel()
	if err == nil {
		return nil
	}
	job.Status, job.Error, job.Result = "failed", cloudSyncError(err), domain.CloudSyncResult{}
	finishCtx, finishCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer finishCancel()
	return InTx(finishCtx, s.db, func(q repository.DBTX) error {
		if err := s.cloud.FinishJob(finishCtx, q, job); err != nil {
			return err
		}
		return s.appendAudit(finishCtx, q, domain.AuditEvent{EventType: "cloud_sync.failed", ActorType: "system", ActorID: &job.ActorID,
			RegionID: &job.Input.RegionID, Result: stringPtr("failed"), Metadata: map[string]any{"job_id": job.ID, "account_id": job.AccountID, "reason": job.Error}})
	})
}

func cloudSyncError(err error) string {
	var validation *CloudValidationError
	if errors.As(err, &validation) {
		return validation.Message
	}
	var provider *cloudassets.Error
	if errors.As(err, &provider) {
		switch provider.Code {
		case "credentials_or_permissions":
			return "云凭据无效或缺少读取实例权限"
		case "rate_limited":
			return "云 API 请求被限流，请稍后重试"
		case "timeout", "cancelled":
			return "同步超时或服务正在关闭，请重试"
		case "region_unavailable":
			return "该 Region 未开通或没有访问权限"
		case "incomplete_pagination", "invalid_response":
			return "云 API 返回不完整，本次未写入资产"
		case "too_many_instances":
			return "单次同步超过 10000 个实例，请按实例 ID 缩小范围"
		}
		return "云 API 请求失败，请检查凭据、Region、只读权限和服务端网络"
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "同步超时或服务正在关闭，请重试"
	}
	if errors.Is(err, ErrForbidden) {
		return "发起人的资产管理权限已被撤销"
	}
	return "同步未完成，请检查目标区域、网关、审批人和数据库状态后重试"
}

func (s *AccessService) runCloudSync(ctx context.Context, job *domain.CloudSyncJob) error {
	if err := s.requireAdmin(ctx, job.ActorID); err != nil {
		return err
	}
	account, err := s.cloud.GetAccount(ctx, s.db, job.AccountID, false)
	if err != nil {
		return err
	}
	if !account.Enabled || account.Revision != job.AccountRevision {
		return cloudValidation("云账号配置已变化，请重新发起同步")
	}
	if err := s.validateCloudDestinations(ctx, s.db, job.Input); err != nil {
		return err
	}
	credentials, err := s.cloudCredentials(ctx, account)
	if err != nil {
		return err
	}
	instances, err := s.cloudDiscoverer.Discover(ctx, account.Provider, credentials, job.Input.CloudRegion, job.Input.InstanceIDs)
	if err != nil {
		return err
	}
	instances, result, err := prepareCloudInstances(instances, job.Input.InstanceIDs)
	if err != nil {
		return err
	}
	if err := s.requireAdmin(ctx, job.ActorID); err != nil {
		return err
	}
	return InTx(ctx, s.db, func(q repository.DBTX) error {
		current, err := s.cloud.GetAccount(ctx, q, account.ID, true)
		if err != nil {
			return err
		}
		if !current.Enabled || current.Revision != account.Revision {
			return cloudValidation("云账号配置已变化，请重新发起同步")
		}
		if err := s.cloud.LockJob(ctx, q, job.ID, *job.LeaseToken); err != nil {
			return err
		}
		if err := s.validateCloudDestinations(ctx, q, job.Input); err != nil {
			return err
		}
		source := cloudSource(account.ID)
		for _, instance := range instances {
			externalID := job.Input.CloudRegion + "." + instance.ID
			value, err := s.assets.GetByExternalIdentity(ctx, q, source, externalID)
			creating := errors.Is(err, repository.ErrNotFound)
			if err != nil && !creating {
				return err
			}
			if value.DeletedAt != nil {
				result.Skipped++
				continue
			}
			if creating {
				value = domain.Asset{ID: id.New(), RegionID: job.Input.RegionID, GatewayID: job.Input.GatewayID,
					AssetType: account.Provider + "_ecs", RiskLevel: job.Input.RiskLevel, MaxTTLSeconds: job.Input.MaxTTLSeconds,
					Status: domain.ResourceStatusEnabled, ExternalSource: &source, ExternalID: &externalID}
				if account.Provider == "aws" {
					value.AssetType = "aws_ec2"
				}
			} else if value.RegionID != job.Input.RegionID {
				return cloudValidation("已有实例属于其他平台区域，请在原区域同步")
			}
			value.Name, value.SyncGeneration = instance.Name, &job.ID
			value.TargetCiphertext, err = s.cloudCipher.Encrypt(ctx, []byte(instance.Host), cloudTargetAAD(value.ID))
			if err != nil {
				return err
			}
			if creating {
				value, err = s.assets.UpsertExternal(ctx, q, value)
				if err != nil {
					return err
				}
				if err := s.gateways.BindAsset(ctx, q, value.ID, job.Input.GatewayID, 0); err != nil {
					return err
				}
				for _, port := range job.Input.Ports {
					if _, err := s.assets.CreatePort(ctx, q, domain.AssetPort{ID: id.New(), AssetID: value.ID, Port: port, Protocol: "tcp", Enabled: true}); err != nil {
						return err
					}
				}
				if _, err := s.assets.CreateApprover(ctx, q, domain.AssetApprover{ID: id.New(), AssetID: value.ID,
					UserID: job.Input.ApproverID, ApprovalLevel: 1, Role: "owner", Enabled: true}); err != nil {
					return err
				}
				result.Created++
			} else {
				if err := s.cloud.UpdateDiscoveredAsset(ctx, q, value); err != nil {
					return err
				}
				result.Updated++
			}
		}
		job.Result, job.Status, job.Error = result, "success", ""
		if err := s.cloud.FinishJob(ctx, q, *job); err != nil {
			return err
		}
		return s.appendAudit(ctx, q, domain.AuditEvent{EventType: "cloud_sync.completed", ActorType: "system", ActorID: &job.ActorID,
			RegionID: &job.Input.RegionID, Result: stringPtr("success"), Metadata: map[string]any{"account_id": account.ID, "job_id": job.ID,
				"created": result.Created, "updated": result.Updated, "skipped": result.Skipped, "missing": len(result.MissingIDs)}})
	})
}

func prepareCloudInstances(values []cloudassets.Instance, ids []string) ([]cloudassets.Instance, domain.CloudSyncResult, error) {
	result := domain.CloudSyncResult{MissingIDs: []string{}}
	if len(values) > cloudassets.MaxInstances {
		return nil, result, &cloudassets.Error{Code: "too_many_instances"}
	}
	seen := make(map[string]bool)
	allowed := make(map[string]bool, len(ids))
	for _, value := range ids {
		allowed[value] = true
	}
	prepared := make([]cloudassets.Instance, 0, len(values))
	for _, value := range values {
		if len(ids) > 0 && !allowed[value.ID] {
			continue
		}
		if !cloudassets.ValidInstanceID(value.ID) || seen[value.ID] {
			return nil, result, &cloudassets.Error{Code: "invalid_response"}
		}
		seen[value.ID] = true
		result.Discovered++
		if value.Host == "" {
			result.Skipped++
			continue
		}
		address, err := netip.ParseAddr(value.Host)
		if err != nil || !address.IsGlobalUnicast() || address.IsLinkLocalUnicast() {
			return nil, result, &cloudassets.Error{Code: "invalid_response"}
		}
		value.Host = address.Unmap().String()
		value.Name = strings.TrimSpace(value.Name)
		if value.Name == "" {
			value.Name = value.ID
		}
		if validateAdminText(value.Name, "cloud instance name", 128, true) != nil {
			value.Name = value.ID
		}
		prepared = append(prepared, value)
	}
	for _, value := range ids {
		if !seen[value] {
			result.MissingIDs = append(result.MissingIDs, value)
		}
	}
	return prepared, result, nil
}

func (s *AccessService) ListCloudSyncGateways(ctx context.Context, actor, regionID string) ([]domain.Gateway, error) {
	if err := s.requireAdmin(ctx, actor); err != nil {
		return nil, err
	}
	if regionID != "" && validateUUID(regionID, "region ID") != nil {
		return nil, ErrValidation
	}
	return s.gateways.ListActiveByRegion(ctx, s.db, regionID)
}

func (s *AccessService) ExportGatewayRelease(ctx context.Context, actor, gatewayID string) (catalogrelease.Bundle, error) {
	if err := s.requireAdmin(ctx, actor); err != nil {
		return catalogrelease.Bundle{}, err
	}
	if validateUUID(gatewayID, "gateway ID") != nil {
		return catalogrelease.Bundle{}, ErrValidation
	}
	catalog := catalogrelease.Catalog{Version: 1, GatewayID: gatewayID, Assets: []catalogrelease.CatalogAsset{}}
	source := catalogrelease.TargetSource{Version: 1, Targets: []catalogrelease.SourceTarget{}}
	err := InTx(ctx, s.db, func(q repository.DBTX) error {
		gateway, err := s.gateways.GetByID(ctx, q, gatewayID)
		if err != nil {
			return err
		}
		if gateway.Status != domain.ResourceStatusEnabled {
			return cloudValidation("网关未启用")
		}
		entries, err := s.gateways.ListCatalogEntries(ctx, q, gatewayID)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			asset, err := s.assets.GetByID(ctx, q, entry.TargetID)
			if err != nil {
				return err
			}
			cipher, _ := s.assetEncryptor.(secretstore.Cipher)
			aad := []byte(asset.ID)
			if asset.ExternalSource != nil && strings.HasPrefix(*asset.ExternalSource, "cloud.") {
				cipher, aad = s.cloudCipher, cloudTargetAAD(asset.ID)
			}
			if cipher == nil {
				return cloudValidation("该网关含无法解密的手工资产，请使用 catalog-release 和可信目标清单发布")
			}
			plaintext, err := cipher.Decrypt(ctx, asset.TargetCiphertext, aad)
			if err != nil {
				return cloudValidation("资产目标无法解密，请检查资产加密密钥")
			}
			host := string(plaintext)
			clear(plaintext)
			catalog.Assets = append(catalog.Assets, catalogrelease.CatalogAsset{TargetID: entry.TargetID, ExternalSource: entry.ExternalSource, ExternalID: entry.ExternalID, Ports: entry.Ports})
			source.Targets = append(source.Targets, catalogrelease.SourceTarget{TargetID: entry.TargetID, ExternalSource: entry.ExternalSource, ExternalID: entry.ExternalID, Host: host, Ports: entry.Ports})
		}
		return nil
	})
	if err != nil {
		return catalogrelease.Bundle{}, err
	}
	bundle, err := catalogrelease.Build(catalog, source)
	if err != nil {
		return catalogrelease.Bundle{}, cloudValidation("网关资产目标或端口清单不完整，无法生成目录")
	}
	err = InTx(ctx, s.db, func(q repository.DBTX) error {
		return s.appendAudit(ctx, q, domain.AuditEvent{EventType: "gateway.catalog_exported", ActorType: "admin", ActorID: &actor,
			Result: stringPtr("success"), Metadata: map[string]any{"gateway_id": gatewayID, "asset_count": len(catalog.Assets), "release_id": bundle.Release.ReleaseID}})
	})
	if err != nil {
		return catalogrelease.Bundle{}, err
	}
	return bundle, nil
}
