package gatewayagent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"testing"

	"github.com/rs/zerolog"

	"github.com/srex-run/access-gateway/internal/gateway"
	"github.com/srex-run/access-gateway/internal/operationaudit"
	"github.com/srex-run/access-gateway/internal/sessionproxy"
)

type unexpectedOperationSink struct{ t *testing.T }

func (s unexpectedOperationSink) AppendOperation(context.Context, operationaudit.SessionEvent) error {
	s.t.Error("operation recorded before receiving the MySQL greeting")
	return sessionproxy.ErrAudit
}

func TestAuditMySQLEarlyTargetCloseIsLoggedAsFailure(t *testing.T) {
	controller, listener, _, events := pipeController(t)
	var logs bytes.Buffer
	controller.logger = zerolog.New(&logs)
	serverTLS, _ := nativeTLSConfigs(t, tls.VersionTLS12)
	pair := serverTLS.Certificates[0]
	key, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	controller.proxy = &sessionproxy.Config{
		Name: "mysql-test", Port: 3306, Protocol: "mysql",
		Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]})),
		PrivateKey:  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})),
	}
	controller.operations = unexpectedOperationSink{t}
	controller.dial = func(context.Context, string, string) (net.Conn, error) {
		back, target := net.Pipe()
		target.Close()
		return tcpPipe{back}, nil
	}
	request := nativeRequest()
	request.ConnectionMode, request.AuditPolicy = gateway.ConnectionModeAudit, controller.proxy.Policy()
	if _, err := controller.Start(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	client := connectNative(t, listener)
	if n, err := client.Read(make([]byte, 128)); n != 0 || err == nil {
		t.Fatalf("client unexpectedly received a greeting: n=%d err=%v", n, err)
	}
	event := waitForGatewayEvent(t, events, "disconnected")
	if event.Result != "failure" || event.Reason != "mysql_target_greeting_unavailable" {
		t.Fatalf("early target close was not recorded as a failed greeting: %+v", event)
	}
	var logged map[string]any
	if err := json.Unmarshal(logs.Bytes(), &logged); err != nil {
		t.Fatal(err)
	}
	if logged["session_id"] != request.SessionID || logged["reason"] != event.Reason {
		t.Fatalf("missing failure diagnostic: %v", logged)
	}
}
