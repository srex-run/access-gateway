package gatewayagent

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"crypto/ed25519"

	"github.com/srex-run/access-gateway/internal/gateway"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/sessionproxy"
)

const SessionListenerPort = 20000
const SessionManagementPort = 8090
const SessionHealthPort = 8091
const SessionConfigPath = "/run/session/private/session.json"

type SessionConfig struct {
	Proxy           *sessionproxy.Config         `json:"proxy,omitempty"`
	Version         int                          `json:"version"`
	GatewayID       string                       `json:"gateway_id"`
	Request         gateway.CreateSessionRequest `json:"request"`
	TargetHost      string                       `json:"target_host"`
	StartedAt       time.Time                    `json:"started_at"`
	ExpiresAt       time.Time                    `json:"expires_at"`
	Certificate     string                       `json:"certificate"`
	PrivateKey      string                       `json:"private_key"`
	AuditToken      string                       `json:"audit_token"`
	ControlPlaneURL string                       `json:"control_plane_url"`
	AuditAllowHTTP  bool                         `json:"audit_allow_http"`
	Network         *SessionNetwork              `json:"network,omitempty"`
}

// A nil network preserves the isolated Pod's fixed listener ports.
type SessionNetwork struct {
	ListenerHost   string `json:"listener_host"`
	ListenerPort   int    `json:"listener_port"`
	ManagementPort int    `json:"management_port"`
}

func (c SessionConfig) ListenerAddress() (string, int) {
	if c.Request.WebOnly {
		if c.Network != nil {
			return "127.0.0.1", c.Network.ListenerPort
		}
		return "127.0.0.1", SessionListenerPort
	}
	if c.Network != nil {
		return c.Network.ListenerHost, c.Network.ListenerPort
	}
	return "0.0.0.0", SessionListenerPort
}

func (c SessionConfig) ManagementAddress() string {
	if c.Network != nil {
		return net.JoinHostPort("127.0.0.1", fmt.Sprint(c.Network.ManagementPort))
	}
	return fmt.Sprintf(":%d", SessionManagementPort)
}

func (c SessionConfig) Validate() error {
	if c.Version != 1 || !id.IsUUID(c.GatewayID) || !id.IsUUID(c.Request.SessionID) || !id.IsUUID(c.Request.TargetID) ||
		(c.Request.ConnectionMode != gateway.ConnectionModeNative && c.Request.ConnectionMode != gateway.ConnectionModeAudit) || gateway.ValidateCreateRequest(c.Request) != nil ||
		!validTargetHost(c.TargetHost) || c.Request.TTLSeconds > 5*60*60 || c.StartedAt.IsZero() ||
		(c.Request.ExpiresAt == nil && !c.ExpiresAt.Equal(c.StartedAt.Add(time.Duration(c.Request.TTLSeconds)*time.Second))) ||
		(c.Request.ExpiresAt != nil && !c.ExpiresAt.Equal(c.Request.ExpiresAt.UTC())) || !c.ExpiresAt.After(c.StartedAt) ||
		c.ExpiresAt.After(c.StartedAt.Add(time.Duration(c.Request.TTLSeconds)*time.Second)) {
		return fmt.Errorf("invalid single-session agent configuration: %w", ErrInvalidInput)
	}
	if c.Request.ConnectionMode == gateway.ConnectionModeAudit {
		if c.Proxy == nil || c.Proxy.Validate() != nil || c.Proxy.Policy() != c.Request.AuditPolicy || c.Proxy.Port != c.Request.TargetPort {
			return fmt.Errorf("invalid session audit profile: %w", ErrInvalidInput)
		}
	} else if c.Proxy != nil || c.Request.AuditPolicy.Profile != "" {
		return fmt.Errorf("audit profile requires audit connection mode: %w", ErrInvalidInput)
	}
	if n := c.Network; n != nil && (net.ParseIP(n.ListenerHost) == nil || n.ListenerPort < 1024 || n.ListenerPort > 65535 ||
		n.ManagementPort < 1024 || n.ManagementPort > 65535 || n.ManagementPort == n.ListenerPort) {
		return fmt.Errorf("invalid host session network: %w", ErrInvalidInput)
	}
	return nil
}

// PrepareSessionConfig copies the Kubernetes Secret projection into a private
// regular file. Only this init-container step follows projection symlinks.
func PrepareSessionConfig(source string) error {
	file, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("open session configuration projection: %w", err)
	}
	defer file.Close()
	encoded, err := io.ReadAll(io.LimitReader(file, maxProtectedFileBytes+1))
	if err != nil || len(encoded) > maxProtectedFileBytes {
		return fmt.Errorf("read session configuration projection: %w", ErrInvalidInput)
	}
	defer clear(encoded)
	if _, err := DecodeSessionConfig(encoded); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(SessionConfigPath), 0o700); err != nil {
		return fmt.Errorf("create private session directory: %w", err)
	}
	if err := os.WriteFile(SessionConfigPath, encoded, 0o400); err != nil {
		return fmt.Errorf("write private session configuration: %w", err)
	}
	return nil
}

func LoadSessionConfig(path string) (SessionConfig, error) {
	encoded, _, err := readProtectedFile(path, "session configuration", maxProtectedFileBytes)
	if err != nil {
		return SessionConfig{}, err
	}
	defer clear(encoded)
	return DecodeSessionConfig(encoded)
}

func DecodeSessionConfig(encoded []byte) (SessionConfig, error) {
	var cfg SessionConfig
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return SessionConfig{}, fmt.Errorf("decode session configuration: %w", ErrInvalidInput)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return SessionConfig{}, err
	}
	if err := cfg.Validate(); err != nil {
		return SessionConfig{}, err
	}
	return cfg, nil
}

func NewSessionIdentity(expiresAt time.Time) (certificate, privateKey string, err error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate session management key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", fmt.Errorf("generate session certificate serial: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "session-agent"}, DNSNames: []string{"session-agent"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: expiresAt.Add(10 * time.Minute),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		IsCA:        true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		return "", "", fmt.Errorf("create session certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return "", "", fmt.Errorf("encode session management key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})), nil
}

func (c SessionConfig) ManagementTLS(server bool) (*tls.Config, error) {
	identity, err := tls.X509KeyPair([]byte(c.Certificate), []byte(c.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("load session management identity: %w", ErrInvalidInput)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(c.Certificate)) {
		return nil, fmt.Errorf("load session certificate trust: %w", ErrInvalidInput)
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{identity}}
	if server {
		cfg.ClientCAs, cfg.ClientAuth = pool, tls.RequireAndVerifyClientCert
	} else {
		cfg.RootCAs, cfg.ServerName = pool, "session-agent"
	}
	return cfg, nil
}
