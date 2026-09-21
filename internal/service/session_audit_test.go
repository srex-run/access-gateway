package service

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/operationaudit"
	"github.com/srex-run/access-gateway/internal/settings"
)

func TestSessionAuditAllProtocolsShareAgentPolicy(t *testing.T) {
	target, err := settings.GenerateAuditCertificate(settings.CertificateRequest{Purpose: "ssh"})
	if err != nil {
		t.Fatal(err)
	}
	for _, protocol := range []string{"mysql", "postgresql", "redis", "mongodb", "http", "ssh"} {
		t.Run(protocol, func(t *testing.T) {
			profile := settings.AuditProfile{Name: "draft", Protocol: protocol, Port: 60022, AuditEnabled: true}
			if protocol == "ssh" {
				profile.TargetHostKeys = []string{target.SSHPublicKey}
			}
			input := AssetAuditUpdate{Profiles: []settings.AuditProfile{profile}}
			prepared, err := prepareAuditIdentities(storedAssetAudit{}, input, "gateway.test")
			if err != nil {
				t.Fatal(err)
			}
			if len(input.Keys) != 0 || input.Profiles[0].Certificate != "" {
				t.Fatal("caller mutated")
			}
			value, err := buildAssetAudit(domain.Asset{ID: id.New(), AssetType: protocol}, storedAssetAudit{}, prepared)
			if err != nil {
				t.Fatal(err)
			}
			account := "reader"
			request := domain.AccessRequest{TargetPort: 60022, TargetAccount: &account}
			policy, err := value.sessionPolicy(protocol, request)
			if err != nil || policy.Protocol != protocol || policy.Revision == "" {
				t.Fatalf("policy: %+v %v", policy, err)
			}
			// One asset may combine an audited port and a native port.
			value.Profiles = append(value.Profiles, settings.AuditProfile{Name: "native", Port: 12345, Protocol: protocol})
			registry, err := value.registry()
			if err != nil {
				t.Fatal(err)
			}
			cfg, err := registry.Resolve(policy)
			if err != nil || !cfg.AuditEnabled || cfg.Port != 60022 {
				t.Fatalf("protected agent config missing: %v", err)
			}
			if protocol == "ssh" && cfg.SSHHostKey == "" || protocol != "ssh" && cfg.PrivateKey == "" {
				t.Fatal("agent identity missing")
			}
			trust := value.clientTrust(policy)
			if trust == nil || protocol == "ssh" && trust.SSHHostPublicKey == "" || protocol != "ssh" && trust.CACertificate == "" {
				t.Fatal("public client trust missing")
			}
			publicTrust, _ := json.Marshal(trust)
			if strings.Contains(string(publicTrust), "PRIVATE KEY") {
				t.Fatal("private material leaked in session")
			}
			encoded, _ := json.Marshal(value.view(1))
			if strings.Contains(string(encoded), "PRIVATE KEY") {
				t.Fatal("private material leaked")
			}
			request.TargetAccount = nil
			if required := value.targetAccountRequired(request.TargetPort); required != (protocol != "http") {
				t.Fatalf("port account requirement disagrees with audit policy for %s: %t", protocol, required)
			}
			if _, err = value.sessionPolicy(protocol, request); err == nil && protocol != "http" {
				t.Fatal("audit accepted an unspecified account")
			}
			request.TargetPort = 12345
			if value.targetAccountRequired(request.TargetPort) || value.targetAccountRequired(9999) {
				t.Fatal("native or unconfigured port requires an account")
			}
			if native, err := value.sessionPolicy(protocol, request); err != nil || native != (operationaudit.Policy{}) {
				t.Fatal("native port changed")
			}
			request.TargetPort = 60022
			request.TargetAccount = &account
			value.Profiles[0].AuditEnabled = false
			if value.targetAccountRequired(request.TargetPort) {
				t.Fatal("disabling audit did not clear account requirement")
			}
			if value.clientTrust(policy) != nil {
				t.Fatal("changed profile advertised as original session identity")
			}
			registry, err = value.registry()
			if err != nil {
				t.Fatal(err)
			}
			if _, err = registry.Resolve(policy); err == nil {
				t.Fatal("disabled audit reused approved grant")
			}
			if native, err := value.sessionPolicy(protocol, request); err != nil || native != (operationaudit.Policy{}) {
				t.Fatal("legacy credentials implicitly enabled audit")
			}
		})
	}
}

func TestSessionAuditIdentityPreservedAndTrustRequired(t *testing.T) {
	input := AssetAuditUpdate{Profiles: []settings.AuditProfile{{Name: "draft", Protocol: "ssh", Port: 22, AuditEnabled: true}}}
	prepared, err := prepareAuditIdentities(storedAssetAudit{}, input, "gateway.test")
	if err != nil {
		t.Fatal(err)
	}
	asset := domain.Asset{ID: id.New(), AssetType: "sshd"}
	if _, err = buildAssetAudit(asset, storedAssetAudit{}, prepared); err == nil {
		t.Fatal("unpinned SSH target accepted")
	}
	target, _ := settings.GenerateAuditCertificate(settings.CertificateRequest{Purpose: "ssh"})
	prepared.Profiles[0].TargetHostKeys = []string{target.SSHPublicKey}
	value, err := buildAssetAudit(asset, storedAssetAudit{}, prepared)
	if err != nil {
		t.Fatal(err)
	}
	p := value.Profiles[0]
	edit, err := prepareAuditIdentities(value, AssetAuditUpdate{Revision: 1, Profiles: value.Profiles, Keys: map[string]settings.AuditKeyChanges{p.Name: {}}}, "gateway.test")
	if err != nil {
		t.Fatal(err)
	}
	updated, err := buildAssetAudit(asset, value, edit)
	if err != nil || updated.Keys[p.Name].SSHHostKey != value.Keys[p.Name].SSHHostKey {
		t.Fatalf("identity changed on save: %v", err)
	}
	// Bad TLS trust cannot silently switch a configured port back to native.
	p.Protocol, p.TargetHostKeys = "mysql", nil
	if _, err := buildAssetAudit(domain.Asset{ID: asset.ID, AssetType: "mysql"}, storedAssetAudit{}, AssetAuditUpdate{Profiles: []settings.AuditProfile{p}}); err == nil {
		t.Fatal("invalid required audit downgraded")
	}
}
