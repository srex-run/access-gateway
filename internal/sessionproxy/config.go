// Package sessionproxy terminates application encryption inside an approved
// single-session agent and records requests before forwarding them.
package sessionproxy

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/srex-run/access-gateway/internal/label"
	"github.com/srex-run/access-gateway/internal/operationaudit"
	"golang.org/x/crypto/ssh"
)

const ProfileLabel = label.PrefixSecurity + "audit-profile"
const AutoProfile = "auto"

// Config is assembled from public settings and decrypted private keys, then
// copied into a mode-0400 session grant / Kubernetes Secret. The assembled
// value never belongs in a command line, plaintext database row, ConfigMap,
// log, or ordinary settings response.
type Config struct {
	mysqlStartup    *mysqlClientStartup
	postgresCancels *postgresCancelRegistry
	// Set only for an in-worker native terminal. Never accepted from settings
	// or grants; the ephemeral client identity protects local proxy endpoints.
	TerminalClientCA        string   `json:"-"`
	AuditEnabled            bool     `json:"audit_enabled,omitempty"`
	Name                    string   `json:"name"`
	Selector                string   `json:"selector"`
	Port                    int      `json:"port"`
	Protocol                string   `json:"protocol"`
	Certificate             string   `json:"certificate,omitempty"`
	PrivateKey              string   `json:"private_key,omitempty"`
	TargetCA                string   `json:"target_ca,omitempty"`
	TargetServerName        string   `json:"target_server_name,omitempty"`
	TargetCertificateSHA256 string   `json:"target_certificate_sha256,omitempty"`
	SSHHostKey              string   `json:"ssh_host_key,omitempty"`
	TargetHostKeys          []string `json:"target_host_keys,omitempty"`
	AuthorizedKeys          []string `json:"authorized_keys,omitempty"`
	TargetSSHKey            string   `json:"target_ssh_key,omitempty"`
}

type Registry struct{ profiles []Config }

// ProfileSource resolves the latest committed settings for new grants.
type ProfileSource interface {
	AuditRegistry(context.Context) (*Registry, error)
}

// ProfileResolver allows resource-owned profiles to be resolved by identity.
type ProfileResolver interface {
	ResolveAuditProfile(context.Context, operationaudit.Policy) (*Config, error)
}

func (r *Registry) AuditRegistry(context.Context) (*Registry, error) { return r, nil }

func NewRegistry(profiles []Config) (*Registry, error) {
	if len(profiles) > 100 {
		return nil, fmt.Errorf("最多配置 100 条操作审计规则")
	}
	r := &Registry{}
	seen := map[string]bool{}
	for _, p := range profiles {
		if err := p.Validate(); err != nil {
			return nil, fmt.Errorf("审计规则 %s: %w", p.Name, err)
		}
		if seen[p.Name] {
			return nil, fmt.Errorf("审计规则名称不能重复")
		}
		seen[p.Name] = true
		p.TargetHostKeys = append([]string(nil), p.TargetHostKeys...)
		p.AuthorizedKeys = append([]string(nil), p.AuthorizedKeys...)
		r.profiles = append(r.profiles, p)
	}
	return r, nil
}

func ResolveProfile(ctx context.Context, source ProfileSource, policy operationaudit.Policy) (*Config, error) {
	if policy == (operationaudit.Policy{}) {
		return nil, nil
	}
	if resolver, ok := source.(ProfileResolver); ok {
		return resolver.ResolveAuditProfile(ctx, policy)
	}
	var registry *Registry
	if source != nil {
		var err error
		registry, err = source.AuditRegistry(ctx)
		if err != nil {
			return nil, err
		}
	}
	return registry.Resolve(policy)
}

func (c Config) Policy() operationaudit.Policy {
	b, _ := json.Marshal(c)
	sum := sha256.Sum256(b)
	clear(b)
	return operationaudit.Policy{Profile: c.Name, Revision: hex.EncodeToString(sum[:]), Protocol: c.Protocol}
}

// Select returns public configuration errors containing only the requested port
// and corrective guidance, never certificates, keys or target addresses.
func (r *Registry) Select(labels label.Labels, port int) (operationaudit.Policy, error) {
	return r.selectProfile(labels, port, "")
}

// SelectForProtocol narrows automatic profile selection to the asset protocol
// before checking the port and label selector. This prevents a same-port rule
// for another protocol from receiving the session certificate.
func (r *Registry) SelectForProtocol(labels label.Labels, port int, protocol string) (operationaudit.Policy, error) {
	return r.selectProfile(labels, port, operationaudit.NormalizeProtocol(protocol))
}

func (r *Registry) selectProfile(labels label.Labels, port int, protocol string) (operationaudit.Policy, error) {
	// A missing label follows the persisted "auto" default too, including
	// callers using older asset snapshots. Missing configuration fails closed.
	named := labels[ProfileLabel]
	if named == "" {
		named = AutoProfile
	}
	var selected operationaudit.Policy
	if r != nil {
		for _, p := range r.profiles {
			if protocol != "" && operationaudit.NormalizeProtocol(p.Protocol) != protocol {
				continue
			}
			if named != AutoProfile && named != p.Name {
				continue
			}
			candidate := labels
			if named == AutoProfile {
				// Resolve only the profile reference. All other selector terms
				// (environment, owner, application, etc.) must still match.
				candidate = labels.Copy()
				if candidate == nil {
					candidate = label.Labels{}
				}
				candidate[ProfileLabel] = p.Name
			}
			sel, _ := label.Parse(p.Selector)
			if p.Port == port && sel.Matches(candidate) {
				if selected.Profile != "" {
					return operationaudit.Policy{}, fmt.Errorf("端口 %d 匹配了多条审计规则，请编辑资源的审计配置，确保每个端口只有一条规则", port)
				}
				selected = p.Policy()
			}
		}
	}
	if selected.Profile == "" {
		return operationaudit.Policy{}, fmt.Errorf("端口 %d 没有匹配的审计规则，请在资源编辑页面配置此端口的审计证书", port)
	}
	return selected, nil
}

func (r *Registry) Resolve(ref operationaudit.Policy) (*Config, error) {
	if ref == (operationaudit.Policy{}) {
		return nil, nil
	}
	if r != nil {
		for _, p := range r.profiles {
			if p.Policy() == ref {
				c := p
				return &c, nil
			}
		}
	}
	return nil, fmt.Errorf("approved audit profile changed or is unavailable; create a new session")
}

func (c Config) Validate() error {
	encoded, err := json.Marshal(c)
	if err != nil || len(encoded) > 512<<10 {
		return fmt.Errorf("audit profile is too large")
	}
	clear(encoded)
	sel, err := label.Parse(c.Selector)
	if err != nil || sel.Empty() || c.Name == "" || c.Name == AutoProfile || label.ValidateValue(c.Name) != nil || c.Port < 1 || c.Port > 65535 || !operationaudit.ValidProtocol(c.Protocol) {
		return fmt.Errorf("invalid audit profile")
	}
	if c.Protocol == "ssh" {
		if _, err := ssh.ParsePrivateKey([]byte(c.SSHHostKey)); err != nil {
			return fmt.Errorf("audit SSH host key required")
		}
		if len(c.TargetHostKeys) == 0 {
			return fmt.Errorf("pinned target SSH host keys required")
		}
		for _, key := range append(append([]string{}, c.TargetHostKeys...), c.AuthorizedKeys...) {
			if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key)); err != nil {
				return fmt.Errorf("invalid SSH public key")
			}
		}
		if len(c.AuthorizedKeys) > 0 {
			if _, err := ssh.ParsePrivateKey([]byte(c.TargetSSHKey)); err != nil {
				return fmt.Errorf("target SSH key required for public key authentication")
			}
		}
		return nil
	}
	_, _, err = c.TLS("validation.invalid")
	return err
}

func (c Config) TLS(target string) (*tls.Config, *tls.Config, error) {
	key, err := tls.X509KeyPair([]byte(c.Certificate), []byte(c.PrivateKey))
	if err != nil {
		return nil, nil, fmt.Errorf("audit proxy TLS certificate and key required")
	}
	var roots *x509.CertPool
	if c.TargetCA != "" {
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM([]byte(c.TargetCA)) {
			return nil, nil, fmt.Errorf("invalid target TLS CA")
		}
	}
	name := c.TargetServerName
	if name == "" {
		name = target
	}
	upstream := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: name}
	if c.TargetCertificateSHA256 != "" {
		pin, err := hex.DecodeString(c.TargetCertificateSHA256)
		if err != nil || len(pin) != sha256.Size || c.TargetCA != "" {
			return nil, nil, fmt.Errorf("target certificate pin must be 64 hex characters and cannot be combined with a CA")
		}
		// An exact, administrator-configured leaf certificate pin replaces
		// PKI hostname verification, including self-signed MySQL certificates.
		// There is deliberately no option to disable both forms of verification.
		upstream.InsecureSkipVerify = true
		upstream.VerifyConnection = func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return ErrIdentity
			}
			cert := state.PeerCertificates[0]
			sum := sha256.Sum256(cert.Raw)
			if subtle.ConstantTimeCompare(sum[:], pin) != 1 {
				return ErrIdentity
			}
			now := time.Now()
			if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
				return x509.CertificateInvalidError{Cert: cert, Reason: x509.Expired}
			}
			return nil
		}
	}
	frontend := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{key}}
	if c.TerminalClientCA != "" {
		frontend.ClientCAs = x509.NewCertPool()
		if !frontend.ClientCAs.AppendCertsFromPEM([]byte(c.TerminalClientCA)) {
			return nil, nil, fmt.Errorf("invalid terminal client CA")
		}
		frontend.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return frontend, upstream, nil
}
