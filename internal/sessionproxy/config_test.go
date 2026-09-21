package sessionproxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

type auditTLSFixture struct {
	pair             tls.Certificate
	certificate, key string
	pin              string
}

func newAuditTLSFixture(t *testing.T, names []string, notBefore, notAfter time.Time) auditTLSFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: names,
		NotBefore: notBefore, NotAfter: notAfter,
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	privateKey := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(certificate, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return auditTLSFixture{pair: pair, certificate: string(certificate), key: string(privateKey), pin: hex.EncodeToString(sum[:])}
}

func TestTargetTLSVerifiesTrustAndCertificatePins(t *testing.T) {
	now := time.Now()
	validFrom, validUntil := now.Add(-time.Hour), now.Add(time.Hour)
	gateway := newAuditTLSFixture(t, []string{"gateway.test"}, validFrom, validUntil)
	target := newAuditTLSFixture(t, []string{"target.test"}, validFrom, validUntil)
	withoutSAN := newAuditTLSFixture(t, nil, validFrom, validUntil)
	expired := newAuditTLSFixture(t, nil, now.Add(-2*time.Hour), validFrom)
	future := newAuditTLSFixture(t, nil, validUntil, now.Add(2*time.Hour))
	for _, tc := range []struct {
		name, targetCA, serverName, pin string
		target                          auditTLSFixture
		wantError                       bool
		wantExpired                     bool
	}{
		{name: "trusted CA and hostname", target: target, targetCA: target.certificate},
		{name: "explicit target hostname", target: target, targetCA: target.certificate, serverName: "target.test"},
		{name: "wrong hostname", target: target, targetCA: target.certificate, serverName: "wrong.test", wantError: true},
		{name: "wrong CA", target: target, targetCA: gateway.certificate, wantError: true},
		{name: "no configured trust", target: target, wantError: true},
		{name: "pinned certificate without SAN", target: withoutSAN, pin: withoutSAN.pin},
		{name: "wrong certificate pin", target: withoutSAN, pin: target.pin, wantError: true},
		{name: "expired pinned certificate", target: expired, pin: expired.pin, wantError: true, wantExpired: true},
		{name: "future pinned certificate", target: future, pin: future.pin, wantError: true, wantExpired: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := Config{
				Certificate: gateway.certificate, PrivateKey: gateway.key,
				TargetCA: tc.targetCA, TargetServerName: tc.serverName, TargetCertificateSHA256: tc.pin,
			}
			host := "target.test"
			if tc.serverName != "" {
				host = "192.0.2.10"
			}
			_, upstream, err := config.TLS(host)
			if err != nil {
				t.Fatal(err)
			}
			// TLS 1.3 can send a certificate alert while the peer is still
			// writing its handshake. Use TCP buffering so errors cannot be
			// masked by simultaneous writes blocking on net.Pipe.
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			client, err := net.DialTimeout("tcp", listener.Addr().String(), 2*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			server, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			serverResult := make(chan error, 1)
			go func() {
				serverResult <- tls.Server(server, &tls.Config{Certificates: []tls.Certificate{tc.target.pair}}).HandshakeContext(ctx)
			}()
			err = tls.Client(client, upstream).HandshakeContext(ctx)
			if err != nil {
				client.Close()
			}
			serverErr := <-serverResult
			if (err != nil) != tc.wantError {
				t.Fatalf("target handshake error = %v, want rejection = %t", err, tc.wantError)
			}
			if !tc.wantError && serverErr != nil {
				t.Fatalf("target server handshake: %v", serverErr)
			}
			if tc.wantExpired {
				var invalid x509.CertificateInvalidError
				if !errors.As(err, &invalid) || invalid.Reason != x509.Expired {
					t.Fatalf("certificate validity rejection = %v, want x509.Expired", err)
				}
			}
			if tc.wantError && tc.pin != "" && !tc.wantExpired && !errors.Is(err, ErrIdentity) {
				t.Fatalf("certificate pin rejection = %v, want ErrIdentity", err)
			}
			if tc.wantError && tc.pin == "" {
				var verificationError *tls.CertificateVerificationError
				if !errors.As(err, &verificationError) {
					t.Fatalf("target rejection = %v, want a certificate verification error", err)
				}
			}
		})
	}
}

func TestPinnedTargetTLSFailureDiagnostics(t *testing.T) {
	now := time.Now()
	gateway := newAuditTLSFixture(t, nil, now.Add(-time.Hour), now.Add(time.Hour))
	valid := newAuditTLSFixture(t, nil, now.Add(-time.Hour), now.Add(time.Hour))
	expired := newAuditTLSFixture(t, nil, now.Add(-2*time.Hour), now.Add(-time.Hour))
	future := newAuditTLSFixture(t, nil, now.Add(time.Hour), now.Add(2*time.Hour))
	for _, tc := range []struct {
		name   string
		target auditTLSFixture
		pin    string
		reason string
	}{
		{name: "matching certificate", target: valid, pin: valid.pin},
		{name: "wrong fingerprint", target: valid, pin: gateway.pin, reason: "target_certificate_pin_rejected"},
		{name: "expired matching certificate", target: expired, pin: expired.pin, reason: "target_certificate_expired_or_not_yet_valid"},
		{name: "future matching certificate", target: future, pin: future.pin, reason: "target_certificate_expired_or_not_yet_valid"},
		{name: "wrong expired certificate", target: expired, pin: valid.pin, reason: "target_certificate_pin_rejected"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := Config{Certificate: gateway.certificate, PrivateKey: gateway.key, TargetCertificateSHA256: tc.pin}
			_, upstream, err := config.TLS("target.test")
			if err != nil {
				t.Fatal(err)
			}
			certificate, err := x509.ParseCertificate(tc.target.pair.Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			err = upstream.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}})
			if tc.reason == "" {
				if err != nil {
					t.Fatalf("matching valid certificate rejected: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("invalid target certificate accepted")
			}
			diagnostic := DiagnoseTerminalFailure(errors.Join(ErrTargetTLS, err))
			if diagnostic.Stage != "target_tls" || diagnostic.Reason != tc.reason {
				t.Fatalf("target TLS diagnostic = %+v, want reason %s", diagnostic, tc.reason)
			}
		})
	}
}

func TestAuditConfigRejectsInvalidPinsAndReservedProfileName(t *testing.T) {
	now := time.Now()
	fixture := newAuditTLSFixture(t, []string{"gateway.test"}, now.Add(-time.Hour), now.Add(time.Hour))
	config := Config{
		Name: "mysql-audit", Selector: ProfileLabel + "=mysql-audit", Port: 3306, Protocol: "mysql",
		Certificate: fixture.certificate, PrivateKey: fixture.key,
	}
	if err := config.Validate(); err != nil {
		t.Fatalf("valid audit configuration: %v", err)
	}
	for _, tc := range []struct{ name, profile, pin, ca string }{
		{name: "reserved auto profile", profile: AutoProfile},
		{name: "short pin", profile: config.Name, pin: fixture.pin[:62]},
		{name: "non-hex pin", profile: config.Name, pin: strings.Repeat("z", 64)},
		{name: "pin and CA", profile: config.Name, pin: fixture.pin, ca: fixture.certificate},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := config
			candidate.Name, candidate.TargetCertificateSHA256, candidate.TargetCA = tc.profile, tc.pin, tc.ca
			if err := candidate.Validate(); err == nil {
				t.Fatal("invalid audit configuration accepted")
			}
		})
	}
}
