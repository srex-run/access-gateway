package settings

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"maps"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/srex-run/access-gateway/internal/sessionproxy"
	"golang.org/x/crypto/ssh"
	"k8s.io/apimachinery/pkg/util/validation"
)

// AuditProfile is the administrator-facing configuration. Its certificates are
// encrypted at rest with the private keys, which are never returned by Get.
type AuditProfile struct {
	AuditEnabled            bool     `json:"audit_enabled,omitempty"`
	Name                    string   `json:"name"`
	Selector                string   `json:"selector"`
	Port                    int      `json:"port"`
	Protocol                string   `json:"protocol"`
	Certificate             string   `json:"certificate"`
	GatewayCA               string   `json:"gateway_ca"`
	TargetCA                string   `json:"target_ca"`
	TargetServerName        string   `json:"target_server_name"`
	TargetCertificateSHA256 string   `json:"target_certificate_sha256"`
	SSHHostPublicKey        string   `json:"ssh_host_public_key"`
	TargetHostKeys          []string `json:"target_host_keys"`
	AuthorizedKeys          []string `json:"authorized_keys"`
}

type AuditKeys struct {
	Certificate  string `json:"certificate,omitempty"`
	GatewayCA    string `json:"gateway_ca,omitempty"`
	TargetCA     string `json:"target_ca,omitempty"`
	PrivateKey   string `json:"private_key"`
	SSHHostKey   string `json:"ssh_host_key"`
	TargetSSHKey string `json:"target_ssh_key"`
}

type AuditKeyChanges struct {
	PrivateKey   *string `json:"private_key"`
	SSHHostKey   *string `json:"ssh_host_key"`
	TargetSSHKey *string `json:"target_ssh_key"`
}

type AuditKeyStatus struct {
	PrivateKey   bool `json:"private_key"`
	SSHHostKey   bool `json:"ssh_host_key"`
	TargetSSHKey bool `json:"target_ssh_key"`
}

// Keep runtime snapshots intact while moving PEM contents into the encrypted
// settings envelope. Non-certificate rule fields remain queryable configuration.
func (c Config) StoreAuditCertificates(secrets *Secrets) Config {
	c.AuditProfiles = slices.Clone(c.AuditProfiles)
	secrets.AuditProfiles = maps.Clone(secrets.AuditProfiles)
	if secrets.AuditProfiles == nil {
		secrets.AuditProfiles = make(map[string]AuditKeys)
	}
	for i := range c.AuditProfiles {
		p := &c.AuditProfiles[i]
		keys := secrets.AuditProfiles[p.Name]
		keys.Certificate, keys.GatewayCA, keys.TargetCA = p.Certificate, p.GatewayCA, p.TargetCA
		secrets.AuditProfiles[p.Name] = keys
		p.Certificate, p.GatewayCA, p.TargetCA = "", "", ""
	}
	return c
}

func (c *Config) RestoreAuditCertificates(secrets Secrets) {
	for i := range c.AuditProfiles {
		p := &c.AuditProfiles[i]
		keys := secrets.AuditProfiles[p.Name]
		// Legacy rows retain public PEM fields until their next settings save.
		if p.Certificate == "" {
			p.Certificate = keys.Certificate
		}
		if p.GatewayCA == "" {
			p.GatewayCA = keys.GatewayCA
		}
		if p.TargetCA == "" {
			p.TargetCA = keys.TargetCA
		}
	}
}

func (p AuditProfile) proxy(keys AuditKeys) sessionproxy.Config {
	return sessionproxy.Config{Name: p.Name, Selector: p.Selector, Port: p.Port, Protocol: p.Protocol, AuditEnabled: p.AuditEnabled,
		Certificate: p.Certificate, PrivateKey: keys.PrivateKey, TargetCA: p.TargetCA, TargetServerName: p.TargetServerName,
		TargetCertificateSHA256: p.TargetCertificateSHA256, SSHHostKey: keys.SSHHostKey,
		TargetHostKeys: p.TargetHostKeys, AuthorizedKeys: p.AuthorizedKeys, TargetSSHKey: keys.TargetSSHKey}
}

func (c Config) AuditRegistry(secrets Secrets) (*sessionproxy.Registry, error) {
	profiles := make([]sessionproxy.Config, 0, len(c.AuditProfiles))
	for _, p := range c.AuditProfiles {
		for _, field := range []struct{ name, value string }{{"网关证书", p.Certificate}, {"网关 CA", p.GatewayCA}, {"资产 CA", p.TargetCA}} {
			if err := certificatePEM(field.value); err != nil {
				return nil, fmt.Errorf("%s: %w", field.name, err)
			}
		}
		if p.TargetServerName != "" && net.ParseIP(p.TargetServerName) == nil && len(validation.IsDNS1123Subdomain(strings.ToLower(p.TargetServerName))) != 0 {
			return nil, fmt.Errorf("资产证书名称必须是域名或 IP，不能包含协议、路径或端口")
		}
		if p.Protocol != "ssh" && p.GatewayCA != "" {
			pair, err := tls.X509KeyPair([]byte(p.Certificate), []byte(secrets.AuditProfiles[p.Name].PrivateKey))
			if err != nil {
				return nil, fmt.Errorf("网关证书与私钥不匹配")
			}
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM([]byte(p.GatewayCA)) {
				return nil, fmt.Errorf("网关 CA 必须是 PEM 证书")
			}
			chain := x509.NewCertPool()
			for _, der := range pair.Certificate[1:] {
				cert, err := x509.ParseCertificate(der)
				if err != nil {
					return nil, fmt.Errorf("网关证书链无效")
				}
				chain.AddCert(cert)
			}
			// Check the public trust bundle matches the stored server identity.
			// An expired identity must still allow local administrator login so
			// it can be replaced; TLS handshakes enforce the current validity.
			leaf, err := x509.ParseCertificate(pair.Certificate[0])
			if err != nil {
				return nil, fmt.Errorf("网关服务证书无效")
			}
			if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: chain, CurrentTime: leaf.NotBefore.Add(time.Second)}); err != nil {
				return nil, fmt.Errorf("网关 CA 不能验证网关服务证书")
			}
		}
		profiles = append(profiles, p.proxy(secrets.AuditProfiles[p.Name]))
	}
	return sessionproxy.NewRegistry(profiles)
}

// Public settings accept certificates only, so misplaced private keys cannot
// be stored in plaintext or echoed by the settings endpoint.
func certificatePEM(value string) error {
	remaining := bytes.TrimSpace([]byte(value))
	for len(remaining) > 0 {
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
			return fmt.Errorf("只接受 PEM 证书，请将私钥填写到私钥字段")
		}
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return fmt.Errorf("PEM 证书格式无效")
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return fmt.Errorf("证书格式无效")
		}
		remaining = bytes.TrimSpace(rest)
	}
	return nil
}

// Preserve omitted secrets, prune removed profiles, and reject typoed key names.
func (c *Config) ApplyAudit(previous Config, secrets *Secrets, changes map[string]AuditKeyChanges) error {
	if c.AuditProfiles == nil {
		c.AuditProfiles = previous.AuditProfiles
	}
	c.AuditProfiles = slices.Clone(c.AuditProfiles)
	keys := make(map[string]AuditKeys, len(c.AuditProfiles))
	for i := range c.AuditProfiles {
		p := &c.AuditProfiles[i]
		p.Name = strings.TrimSpace(p.Name)
		p.Selector = strings.TrimSpace(p.Selector)
		if p.Selector == "" {
			p.Selector = sessionproxy.ProfileLabel + "=" + p.Name
		}
		p.TargetServerName = strings.TrimSpace(p.TargetServerName)
		p.TargetCertificateSHA256 = strings.TrimSpace(p.TargetCertificateSHA256)
		k := secrets.AuditProfiles[p.Name]
		change := changes[p.Name]
		if change.PrivateKey != nil {
			k.PrivateKey = *change.PrivateKey
		}
		if change.SSHHostKey != nil {
			k.SSHHostKey = *change.SSHHostKey
		}
		if change.TargetSSHKey != nil {
			k.TargetSSHKey = *change.TargetSSHKey
		}
		if p.Protocol == "ssh" && k.SSHHostKey != "" {
			signer, err := ssh.ParsePrivateKey([]byte(k.SSHHostKey))
			if err != nil {
				return fmt.Errorf("网关 SSH 私钥格式无效")
			}
			p.SSHHostPublicKey = string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
		}
		keys[p.Name] = k
	}
	for name := range changes {
		if _, ok := keys[name]; !ok {
			return fmt.Errorf("私钥必须属于当前审计规则")
		}
	}
	secrets.AuditProfiles = keys
	return nil
}
