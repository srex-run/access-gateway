package gatewayagent

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/srex-run/access-gateway/internal/gateway"
	"github.com/srex-run/access-gateway/internal/sessionproxy"
	"github.com/srex-run/access-gateway/internal/terminalclient"
)

func TestWebOnlyGrantRejectsEvenLocalTCP(t *testing.T) {
	c := &DirectController{}
	client, server := net.Pipe()
	defer client.Close()
	c.handleConnection(context.Background(), &directRuntime{request: gateway.CreateSessionRequest{WebOnly: true}}, server)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("web-only TCP connection accepted")
	}
}

func TestWebTerminalLogsFailureStageWithoutSecrets(t *testing.T) {
	for _, sample := range []struct {
		name, stage, reason, detail string
		err                         error
	}{
		{"unknown CA", "target_tls", "target_certificate_untrusted", "unknown authority", errors.Join(sessionproxy.ErrTargetTLS, x509.UnknownAuthorityError{})},
		{"certificate name", "target_tls", "target_certificate_name_mismatch", "server name", errors.Join(sessionproxy.ErrTargetTLS, x509.HostnameError{})},
		{"certificate expiry", "target_tls", "target_certificate_expired_or_not_yet_valid", "expired", errors.Join(sessionproxy.ErrTargetTLS, x509.CertificateInvalidError{Reason: x509.Expired})},
		{"certificate pin", "target_tls", "target_certificate_pin_rejected", "target TLS", errors.Join(sessionproxy.ErrTargetTLS, sessionproxy.ErrIdentity)},
		{"client TLS", "client_tls", "client_tls_handshake_failed", "EOF", errors.Join(sessionproxy.ErrClientTLS, io.ErrUnexpectedEOF)},
		{"client CA read", "client_tls_setup", "client_tls_ca_unreadable", "permission denied", &terminalclient.TLSMaterialError{File: "ca", Problem: "permission_denied"}},
		{"client identity parse", "client_tls_setup", "client_tls_identity_invalid", "client.pem", &terminalclient.TLSMaterialError{File: "identity", Problem: "invalid_pem"}},
		{"unrecognized client diagnostic", "client_tls_setup", "client_tls_material_invalid", "check failed", &terminalclient.TLSMaterialError{File: "password=must-not-be-logged", Problem: "key=must-not-be-logged"}},
		{"greeting", "target_greeting", "mysql_target_greeting_unavailable", "EOF", errors.Join(sessionproxy.ErrTargetGreeting, io.EOF)},
		{"authentication", "identity_verification", "application_identity_rejected", "identity", sessionproxy.ErrIdentity},
		{"audit", "audit", "operation_audit_unavailable", "audit", sessionproxy.ErrAudit},
		{"unknown", "application_proxy", "application_proxy_failed", "proxy failed", errors.New("password=must-not-be-logged")},
	} {
		t.Run(sample.name, func(t *testing.T) {
			var logs bytes.Buffer
			controller := &DirectController{logger: zerolog.New(&logs)}
			// Cancellation is a consequence; retain the original failure stage.
			err := errors.Join(fmt.Errorf("private_key=must-not-be-logged: %w", sample.err), context.Canceled)
			reason := controller.logTerminalFailure("session", "connection", sessionproxy.Config{Protocol: "mysql", PrivateKey: "must-not-be-logged", TargetCA: "test-public-ca"}, err)
			var event map[string]any
			if json.Unmarshal(logs.Bytes(), &event) != nil {
				t.Fatal("missing structured terminal diagnostic")
			}
			if reason != sample.reason || event["reason"] != sample.reason || event["failure_stage"] != sample.stage || !strings.Contains(event["error"].(string), sample.detail) {
				t.Fatalf("wrong diagnostic: %s", logs.String())
			}
			if event["session_id"] != "session" || event["connection_id"] != "connection" || event["protocol"] != "mysql" || event["target_ca_configured"] != true || event["target_pin_configured"] != false || event["error_types"] == nil {
				t.Fatal("missing connection or trust configuration context")
			}
			if strings.Contains(logs.String(), "must-not-be-logged") || strings.Contains(logs.String(), "test-public-ca") {
				t.Fatal("diagnostic contains credentials or certificate contents")
			}
		})
	}
}
