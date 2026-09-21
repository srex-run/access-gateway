package service

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/operationaudit"
	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/secretstore"
	"github.com/srex-run/access-gateway/internal/sessionproxy"
	"github.com/srex-run/access-gateway/internal/settings"
)

func TestNativeAssetPortsNeedNoCertificatesOrKeys(t *testing.T) {
	for _, protocol := range []string{"mysql", "postgresql", "redis", "mongodb", "http", "https", "ssh", "sshd"} {
		t.Run(protocol, func(t *testing.T) {
			asset := domain.Asset{ID: id.New(), AssetType: protocol}
			input := AssetAuditUpdate{Profiles: []settings.AuditProfile{{Name: "port", Protocol: protocol, Port: 60022}}}
			value, err := buildAssetAudit(asset, storedAssetAudit{}, input)
			if err != nil {
				t.Fatal(err)
			}
			profile := value.Profiles[0]
			if profile.Port != 60022 || profile.Protocol != operationaudit.NormalizeProtocol(protocol) || value.Keys[profile.Name] != (settings.AuditKeys{}) {
				t.Fatalf("unexpected native port configuration: %+v", value)
			}
			if err := validateAssetCertificateHost("gateway.example.com", value.Profiles); err != nil {
				t.Fatalf("native asset requires a certificate: %v", err)
			}
			// A second save must not acquire any dependency on legacy keys.
			if _, err := buildAssetAudit(asset, value, AssetAuditUpdate{Revision: 1, Profiles: value.Profiles}); err != nil {
				t.Fatalf("edit native asset: %v", err)
			}
		})
	}
}

func TestAssetAuditCertificatesAreScopedAndPreserved(t *testing.T) {
	bundle, err := settings.GenerateAuditCertificate(settings.CertificateRequest{Purpose: "gateway", Hosts: []string{"gateway.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, protocol := range []string{"mysql", "postgresql", "redis", "mongodb", "http"} {
		t.Run(protocol, func(t *testing.T) {
			asset := domain.Asset{ID: id.New(), AssetType: protocol}
			input := AssetAuditUpdate{Profiles: []settings.AuditProfile{{Name: "draft", Protocol: protocol, Port: 12345, Certificate: bundle.Certificate, GatewayCA: bundle.CA}}, Keys: map[string]settings.AuditKeyChanges{"draft": {PrivateKey: &bundle.PrivateKey}}}
			value, err := buildAssetAudit(asset, storedAssetAudit{}, input)
			if err != nil {
				t.Fatal(err)
			}
			name := value.Profiles[0].Name
			if !strings.HasPrefix(name, "asset."+asset.ID+".") || input.Profiles[0].Name != "draft" {
				t.Fatal("resource identity or caller snapshot changed")
			}
			registry, err := value.registry()
			if err != nil {
				t.Fatal(err)
			}
			policy, err := registry.SelectForProtocol(nil, 12345, protocol)
			if err != nil {
				t.Fatal(err)
			}
			profile, err := registry.Resolve(policy)
			if err != nil || profile.PrivateKey != bundle.PrivateKey {
				t.Fatal("agent did not receive configured identity")
			}
			if _, err := registry.SelectForProtocol(nil, 12345, "ssh"); err == nil {
				t.Fatal("wrong protocol selected")
			}
			view := value.view(1)
			encoded, _ := json.Marshal(view)
			if strings.Contains(string(encoded), "PRIVATE KEY") || !view.HasSecrets[name].PrivateKey || view.Profiles[0].Certificate != bundle.Certificate {
				t.Fatal("public view leaked or lost certificate state")
			}
			updated, err := buildAssetAudit(asset, value, AssetAuditUpdate{Revision: 1, Profiles: view.Profiles})
			if err != nil || updated.Keys[name].PrivateKey != bundle.PrivateKey {
				t.Fatal("omitted private key was not preserved")
			}
			nativeProfiles := append([]settings.AuditProfile(nil), view.Profiles...)
			nativeProfiles[0].Certificate, nativeProfiles[0].GatewayCA = "", ""
			cleared, err := buildAssetAudit(asset, value, AssetAuditUpdate{Revision: 1, Profiles: nativeProfiles, Keys: map[string]settings.AuditKeyChanges{name: {}}})
			if err != nil || cleared.Keys[name].PrivateKey != "" {
				t.Fatal("explicit native form did not clear legacy private key")
			}
			// A profile name from a different resource cannot inherit its secrets.
			foreign := domain.Asset{ID: id.New(), AssetType: protocol}
			if _, err := buildAssetAudit(foreign, storedAssetAudit{}, AssetAuditUpdate{Profiles: view.Profiles}); err == nil {
				t.Fatal("foreign key reference accepted")
			}
			empty := ""
			if _, err := buildAssetAudit(asset, value, AssetAuditUpdate{Profiles: view.Profiles, Keys: map[string]settings.AuditKeyChanges{name: {PrivateKey: &empty}}}); err == nil {
				t.Fatal("required private key cleared")
			}
		})
	}
}

func TestAssetAuditRejectsInvalidAndMixedProtocolMaterial(t *testing.T) {
	tls, err := settings.GenerateAuditCertificate(settings.CertificateRequest{Purpose: "gateway", Hosts: []string{"localhost"}})
	if err != nil {
		t.Fatal(err)
	}
	ssh, err := settings.GenerateAuditCertificate(settings.CertificateRequest{Purpose: "ssh"})
	if err != nil {
		t.Fatal(err)
	}
	asset := domain.Asset{ID: id.New(), AssetType: "sshd"}
	valid := AssetAuditUpdate{Profiles: []settings.AuditProfile{{Name: "ssh", Port: 22, Protocol: "ssh", TargetHostKeys: []string{ssh.SSHPublicKey}}}, Keys: map[string]settings.AuditKeyChanges{"ssh": {SSHHostKey: &ssh.SSHHostKey}}}
	value, err := buildAssetAudit(asset, storedAssetAudit{}, valid)
	if err != nil || value.Profiles[0].SSHHostPublicKey != ssh.SSHPublicKey {
		t.Fatalf("SSH identity: %v", err)
	}
	for _, mutate := range []func(*AssetAuditUpdate){
		func(v *AssetAuditUpdate) { v.Profiles[0].Certificate = tls.Certificate },
		func(v *AssetAuditUpdate) { v.Profiles[0].Protocol = "mysql" },
		func(v *AssetAuditUpdate) { v.Profiles = append(v.Profiles, v.Profiles[0]) },
		func(v *AssetAuditUpdate) { v.Profiles[0].Port = 0 },
		func(v *AssetAuditUpdate) { v.Profiles[0].TargetHostKeys = []string{"invalid"} },
		func(v *AssetAuditUpdate) { v.Profiles[0].TargetHostKeys = []string{ssh.SSHPublicKey + tls.PrivateKey} },
		func(v *AssetAuditUpdate) { v.Profiles[0].AuthorizedKeys = []string{ssh.SSHPublicKey} },
	} {
		candidate := valid
		candidate.Profiles = append([]settings.AuditProfile{}, valid.Profiles...)
		mutate(&candidate)
		if _, err := buildAssetAudit(asset, storedAssetAudit{}, candidate); err == nil {
			t.Fatal("invalid audit configuration accepted")
		}
	}
	empty, err := buildAssetAudit(asset, value, AssetAuditUpdate{Profiles: []settings.AuditProfile{}})
	if err != nil || len(empty.Keys) != 0 {
		t.Fatal("removed keys retained")
	}
	r, err := empty.registry()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Select(nil, 22); err == nil {
		t.Fatal("empty resource audit silently downgraded")
	}
}

func TestAssetSSHValidationAndAuthenticationModes(t *testing.T) {
	gateway, err := settings.GenerateAuditCertificate(settings.CertificateRequest{Purpose: "ssh"})
	if err != nil {
		t.Fatal(err)
	}
	target, err := settings.GenerateAuditCertificate(settings.CertificateRequest{Purpose: "ssh"})
	if err != nil {
		t.Fatal(err)
	}
	client, err := settings.GenerateAuditCertificate(settings.CertificateRequest{Purpose: "ssh"})
	if err != nil {
		t.Fatal(err)
	}
	asset := domain.Asset{ID: id.New(), AssetType: "aliyun_ecs"}
	password := func() AssetAuditUpdate {
		return AssetAuditUpdate{
			Profiles: []settings.AuditProfile{{Name: "draft", Protocol: "ssh", Port: 22, TargetHostKeys: []string{target.SSHPublicKey}}},
			Keys:     map[string]settings.AuditKeyChanges{"draft": {SSHHostKey: &gateway.SSHHostKey}},
		}
	}
	publicKey := password()
	publicKey.Profiles[0].AuthorizedKeys = []string{client.SSHPublicKey}
	publicKey.Keys["draft"] = settings.AuditKeyChanges{SSHHostKey: &gateway.SSHHostKey, TargetSSHKey: &client.SSHHostKey}
	for _, input := range []AssetAuditUpdate{password(), publicKey} {
		stored, err := buildAssetAudit(asset, storedAssetAudit{}, input)
		if err != nil {
			t.Fatalf("valid SSH configuration for cloud asset: %v", err)
		}
		view := stored.view(1)
		encoded, err := json.Marshal(view)
		if err != nil || strings.Contains(string(encoded), "PRIVATE KEY") {
			t.Fatal("SSH private key leaked into edit view")
		}
		name := view.Profiles[0].Name
		updated, err := buildAssetAudit(asset, stored, AssetAuditUpdate{Revision: 1, Profiles: view.Profiles})
		if err != nil || updated.Keys[name] != stored.Keys[name] {
			t.Fatal("editing discarded saved SSH credentials")
		}
		if len(input.Profiles[0].AuthorizedKeys) > 0 {
			empty := ""
			_, err = buildAssetAudit(asset, stored, AssetAuditUpdate{Revision: 1, Profiles: view.Profiles, Keys: map[string]settings.AuditKeyChanges{name: {TargetSSHKey: &empty}}})
			if !errors.Is(err, ErrValidation) || !strings.Contains(err.Error(), "公钥登录还需要资产登录私钥") {
				t.Fatalf("clearing a required saved credential: %v", err)
			}
		}
	}
	for _, tc := range []struct {
		name, message string
		mutate        func(*AssetAuditUpdate)
	}{
		{"missing gateway key", "请先生成或上传网关 SSH 私钥", func(v *AssetAuditUpdate) { v.Keys = nil }},
		{"missing host key", "请填写资产 SSH 主机公钥", func(v *AssetAuditUpdate) { v.Profiles[0].TargetHostKeys = nil }},
		{"fingerprint is not a host key", "资产 SSH 主机公钥第 1 行格式无效", func(v *AssetAuditUpdate) { v.Profiles[0].TargetHostKeys = []string{"SHA256:invalid-fingerprint"} }},
		{"private key in public field", "资产 SSH 主机公钥第 2 行格式无效", func(v *AssetAuditUpdate) {
			v.Profiles[0].TargetHostKeys = append(v.Profiles[0].TargetHostKeys, target.SSHHostKey)
		}},
		{"invalid client key", "允许的客户端公钥第 1 行格式无效", func(v *AssetAuditUpdate) { v.Profiles[0].AuthorizedKeys = []string{"invalid-client-key"} }},
		{"missing target login key", "公钥登录还需要资产登录私钥", func(v *AssetAuditUpdate) { v.Profiles[0].AuthorizedKeys = []string{client.SSHPublicKey} }},
		{"public key is not a private key", "资产登录私钥格式无效", func(v *AssetAuditUpdate) {
			v.Keys["draft"] = settings.AuditKeyChanges{SSHHostKey: &gateway.SSHHostKey, TargetSSHKey: &client.SSHPublicKey}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := password()
			tc.mutate(&input)
			_, err := buildAssetAudit(asset, storedAssetAudit{}, input)
			var validation *RequestValidationError
			if !errors.As(err, &validation) || !strings.Contains(validation.Message, "端口 22："+tc.message) {
				t.Fatalf("expected actionable validation %q, got %v", tc.message, err)
			}
			for _, secret := range []string{gateway.SSHHostKey, target.SSHHostKey, client.SSHHostKey} {
				if strings.Contains(validation.Message, secret) {
					t.Fatal("validation leaked private key material")
				}
			}
		})
	}
}

func TestAssetAuditEncryptedEnvelopeRejectsAnotherResource(t *testing.T) {
	cipher, err := secretstore.NewAESGCM("test", []byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	assetID := id.New()
	value := storedAssetAudit{Profiles: []settings.AuditProfile{}, Keys: map[string]settings.AuditKeys{"test": {PrivateKey: "private-key-value"}}}
	plaintext, _ := json.Marshal(value)
	defer clear(plaintext)
	ciphertext, err := cipher.Encrypt(context.Background(), plaintext, assetAuditAAD(assetID))
	if err != nil || strings.Contains(ciphertext, "private-key-value") {
		t.Fatal("plaintext persisted")
	}
	row := repository.AssetAudit{AssetID: assetID, ConfigCiphertext: ciphertext}
	decoded, err := decodeAssetAudit(context.Background(), cipher, row)
	if err != nil || decoded.Keys["test"].PrivateKey != "private-key-value" {
		t.Fatal("encrypted configuration could not be restored")
	}
	row.AssetID = id.New()
	if _, err := decodeAssetAudit(context.Background(), cipher, row); err == nil {
		t.Fatal("ciphertext moved between assets")
	}
}

type assetProfileResolverStub struct{ called bool }

func (s *assetProfileResolverStub) AuditRegistry(context.Context) (*sessionproxy.Registry, error) {
	panic("resource resolver must not enumerate unrelated certificates")
}
func (s *assetProfileResolverStub) ResolveAuditProfile(ctx context.Context, policy operationaudit.Policy) (*sessionproxy.Config, error) {
	s.called = true
	return &sessionproxy.Config{Name: policy.Profile}, nil
}

func TestAssetAuditUsesTargetedResolver(t *testing.T) {
	source := &assetProfileResolverStub{}
	ctx := context.Background()
	if config, err := sessionproxy.ResolveProfile(ctx, source, operationaudit.Policy{}); err != nil || config != nil || source.called {
		t.Fatal("empty policy loaded secrets")
	}
	policy := operationaudit.Policy{Profile: "asset." + id.New() + ".3306", Protocol: "mysql"}
	config, err := sessionproxy.ResolveProfile(ctx, source, policy)
	if err != nil || !source.called || config.Name != policy.Profile {
		t.Fatal("targeted profile resolver not used")
	}
}
