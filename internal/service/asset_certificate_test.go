package service

import (
	"context"
	"errors"
	"testing"

	"github.com/srex-run/access-gateway/internal/settings"
)

func TestAssetCertificateMustMatchServiceHost(t *testing.T) {
	for _, host := range []string{"access-gateway.srex.run", "127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			bundle, err := settings.GenerateAuditCertificate(settings.CertificateRequest{Purpose: "gateway", Hosts: []string{host}})
			if err != nil {
				t.Fatal(err)
			}
			profiles := []settings.AuditProfile{{Protocol: "mysql", Certificate: bundle.Certificate}}
			if err := validateAssetCertificateHost(host, profiles); err != nil {
				t.Fatal(err)
			}
			if err := validateAssetCertificateHost("unrelated.example.com", profiles); !errors.Is(err, ErrValidation) {
				t.Fatal("a certificate for a different service host was accepted")
			}
		})
	}
	if err := validateAssetCertificateHost("gateway.test", []settings.AuditProfile{{Protocol: "ssh"}}); err != nil {
		t.Fatal("SSH identity was incorrectly treated as a TLS certificate")
	}
	if err := validateAssetCertificateHost("gateway.test", []settings.AuditProfile{{Protocol: "mysql", Certificate: "invalid"}}); !errors.Is(err, ErrValidation) {
		t.Fatal("invalid gateway certificate was accepted")
	}
	if _, err := (&AccessService{}).GenerateAssetAuditCertificate(context.Background(), "", settings.CertificateRequest{Purpose: "gateway"}); !errors.Is(err, ErrForbidden) {
		t.Fatal("anonymous certificate generation was accepted")
	}
}
