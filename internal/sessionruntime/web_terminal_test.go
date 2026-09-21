package sessionruntime

import (
	"context"
	"testing"
	"time"

	"github.com/srex-run/access-gateway/internal/gateway"
	"github.com/srex-run/access-gateway/internal/gatewayagent"
	"github.com/srex-run/access-gateway/internal/sessionproxy"
	"github.com/srex-run/access-gateway/internal/settings"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestWebOnlyRuntimeDoesNotCreatePublicService(t *testing.T) {
	for _, protocol := range []string{"ssh", "mysql", "postgresql", "redis", "mongodb", "http"} {
		t.Run(protocol, func(t *testing.T) {
			c, kube := newRuntime(t, true)
			key, err := settings.GenerateAuditCertificate(settings.CertificateRequest{Purpose: "ssh"})
			if err != nil {
				t.Fatal(err)
			}
			profile := sessionproxy.Config{Name: "ssh", Selector: "kind=ssh", Protocol: "ssh", Port: 60022, AuditEnabled: true, SSHHostKey: key.SSHHostKey, TargetHostKeys: []string{key.SSHPublicKey}}
			if protocol != "ssh" {
				key, err = settings.GenerateAuditCertificate(settings.CertificateRequest{Purpose: "gateway", Hosts: []string{"asset.test"}})
				if err != nil {
					t.Fatal(err)
				}
				profile = sessionproxy.Config{Name: protocol, Selector: "kind=" + protocol, Protocol: protocol, Port: 5432, AuditEnabled: true, Certificate: key.Certificate, PrivateKey: key.PrivateKey, TargetCA: key.CA, TargetServerName: "asset.test"}
			}
			c.options.AuditProfiles, err = sessionproxy.NewRegistry([]sessionproxy.Config{profile})
			if err != nil {
				t.Fatal(err)
			}
			request := requestFor(sessionID)
			request.WebOnly, request.SourceIP, request.TargetPort, request.ConnectionMode, request.AuditPolicy = true, "", profile.Port, "audit", profile.Policy()
			c.callAgent = func(_ context.Context, _ *corev1.Pod, cfg gatewayagent.SessionConfig, _ string, result any) error {
				host, _ := cfg.ListenerAddress()
				if host != "127.0.0.1" || !cfg.Request.WebOnly {
					t.Fatal("web-only grant exposes TCP")
				}
				*result.(*gateway.CreateSessionResponse) = gateway.CreateSessionResponse{SessionID: cfg.Request.SessionID, Status: "running", ConnectionMode: "audit", ListenerPort: gatewayagent.SessionListenerPort, ExternalPort: gatewayagent.SessionListenerPort, ExposureMode: "direct", ExposureRef: "direct/20000", StartedAt: cfg.StartedAt, ExpiresAt: cfg.ExpiresAt}
				return nil
			}
			ctx := context.Background()
			response, err := c.CreateApprovedSession(ctx, gatewayID, request, "ssh.internal")
			if err != nil || response.Status != "running" {
				t.Fatalf("web session: %v", err)
			}
			services, err := kube.CoreV1().Services(c.options.Namespace).List(ctx, metav1.ListOptions{})
			if err != nil || len(services.Items) != 0 {
				t.Fatal("web-only session created a public service")
			}
			// A second launch cannot silently turn a web grant into client access.
			request.WebOnly, request.SourceIP = false, "192.0.2.1"
			if _, err = c.CreateApprovedSession(ctx, gatewayID, request, "ssh.internal"); err == nil {
				t.Fatal("grant exposure could be changed")
			}
		})
	}
}

func TestTerminalRuntimeRejectsExpiredGrantBeforeDial(t *testing.T) {
	_, err := dialTerminal(context.Background(), "untrusted:443", gatewayagent.SessionConfig{ExpiresAt: time.Now().Add(-time.Second)}, "192.0.2.1")
	if err == nil {
		t.Fatal("expired grant reached the network")
	}
}
