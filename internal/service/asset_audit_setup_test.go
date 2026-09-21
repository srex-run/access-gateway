package service

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/settings"
)

func TestAssetAuditSetupHost(t *testing.T) {
	for _, host := range []string{"mysql.internal", "localhost", "10.0.0.1", "::1"} {
		if got, err := auditSetupHost(" " + host + " "); err != nil || got != host {
			t.Fatalf("valid host rejected: %q %v", got, err)
		}
	}
	for _, host := range []string{"", "0.0.0.0", "::", "224.0.0.1", "https://mysql.internal", "mysql.internal:3306", "mysql.internal/path", "mysql.internal\nHost:other"} {
		if _, err := auditSetupHost(host); !errors.Is(err, ErrValidation) {
			t.Fatalf("invalid host accepted: %q %v", host, err)
		}
	}
	if _, err := (&AccessService{}).GenerateAssetAuditCertificate(context.Background(), "", settings.CertificateRequest{Purpose: "setup", Protocol: "mysql", Target: "mysql.internal", TargetPort: 3306}); !errors.Is(err, ErrForbidden) {
		t.Fatal("anonymous user reached target enrollment")
	}
}

func TestAssetAuditSetupProducesCompleteSaveableTLSConfiguration(t *testing.T) {
	target, err := settings.GenerateAuditCertificate(settings.CertificateRequest{Purpose: "target", Hosts: []string{"target.test"}})
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair([]byte(target.Certificate), []byte(target.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- tls.Server(server, &tls.Config{Certificates: []tls.Certificate{pair}, SessionTicketsDisabled: true}).HandshakeContext(ctx)
	}()
	bundle, err := buildAssetAuditSetup(ctx, client, "target.test", settings.CertificateRequest{Protocol: "http", Hosts: []string{"gateway.test", "client.test"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if bundle.TargetCertificateSHA256 != target.CertificateSHA256 || bundle.PrivateKey == "" || bundle.CA == "" || len(bundle.TargetHostKeys) != 0 {
		t.Fatal("one-click result is incomplete")
	}
	block, _ := pem.Decode([]byte(bundle.Certificate))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || cert.VerifyHostname("gateway.test") != nil || cert.VerifyHostname("client.test") != nil {
		t.Fatal("gateway certificate lost the configured hostnames")
	}
	asset := domain.Asset{ID: "11111111-1111-4111-8111-111111111111", AssetType: "http"}
	value, err := buildAssetAudit(asset, storedAssetAudit{}, AssetAuditUpdate{
		Profiles: []settings.AuditProfile{{Name: "draft", Protocol: "http", Port: 443, AuditEnabled: true, Certificate: bundle.Certificate, GatewayCA: bundle.CA, TargetCertificateSHA256: bundle.TargetCertificateSHA256}},
		Keys:     map[string]settings.AuditKeyChanges{"draft": {PrivateKey: &bundle.PrivateKey}},
	})
	if err != nil || len(value.Profiles) != 1 {
		t.Fatalf("generated setup still required manual fields: %v", err)
	}
}

func TestAssetAuditSetupFailureDoesNotReturnPartialCertificate(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	bundle, err := buildAssetAuditSetup(ctx, client, "target.test", settings.CertificateRequest{Protocol: "http", Hosts: []string{"gateway.test"}})
	if !errors.Is(err, ErrValidation) || bundle.Certificate != "" || bundle.PrivateKey != "" || bundle.TargetCertificateSHA256 != "" {
		t.Fatal("failed enrollment returned a partial configuration")
	}
}
