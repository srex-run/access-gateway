package sessionproxy

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"

	"github.com/gorilla/websocket"
	"github.com/srex-run/access-gateway/internal/terminalclient"
)

// TerminalDiagnostic contains only fixed diagnostic text. Never log the raw
// error, command arguments, environment, certificate contents or terminal data.
type TerminalDiagnostic struct {
	Stage  string
	Reason string
	Detail string
}

func DiagnoseTerminalFailure(err error) TerminalDiagnostic {
	d := TerminalDiagnostic{Stage: "application_proxy", Reason: "application_proxy_failed", Detail: "application proxy failed"}
	var exitError *exec.ExitError
	var materialError *terminalclient.TLSMaterialError
	var sshError *sshTerminalError
	switch {
	case errors.Is(err, ErrAudit):
		return TerminalDiagnostic{"audit", "operation_audit_unavailable", "operation audit could not be persisted"}
	case errors.As(err, &materialError):
		reason, detail := materialError.Diagnostic()
		return TerminalDiagnostic{"client_tls_setup", reason, detail}
	case errors.Is(err, ErrTargetTLS):
		d = TerminalDiagnostic{"target_tls", TargetTLSFailureReason(err), "target TLS handshake or certificate verification failed"}
	case errors.Is(err, ErrClientTLS):
		d = TerminalDiagnostic{"client_tls", "client_tls_handshake_failed", "native client TLS handshake with the session proxy failed"}
	case errors.Is(err, ErrTargetGreeting):
		d = TerminalDiagnostic{"target_greeting", "mysql_target_greeting_unavailable", "target MySQL greeting was not received"}
	case errors.Is(err, ErrSSHPrivateKey):
		return TerminalDiagnostic{"ssh_private_key", "ssh_private_key_invalid", "SSH 私钥格式无效，请粘贴完整的 OpenSSH 或 PEM 私钥"}
	case errors.Is(err, ErrSSHKeyPassphrase):
		return TerminalDiagnostic{"ssh_private_key", "ssh_key_passphrase_invalid", "SSH 私钥口令缺失或不正确，请填写创建私钥时设置的口令"}
	case errors.Is(err, ErrSSHHostKey):
		return TerminalDiagnostic{"ssh_host_key", "ssh_host_key_mismatch", "目标 SSH 主机公钥与资产配置不一致，请核对资产的主机公钥"}
	case errors.As(err, &sshError):
		d = sshError.diagnostic()
	case errors.Is(err, ErrIdentity):
		return TerminalDiagnostic{"identity_verification", "application_identity_rejected", "target account or approved identity was rejected"}
	case errors.Is(err, ErrProtocol):
		return TerminalDiagnostic{"application_protocol", "unsupported_application_protocol", "application handshake or protocol packet was invalid"}
	case errors.Is(err, terminalclient.ErrUnavailable):
		return TerminalDiagnostic{"client_start", "terminal_client_unavailable", "native client or process isolation could not be started"}
	case errors.As(err, &exitError):
		d = TerminalDiagnostic{"client_process", "terminal_client_exited", "native client process exited unexpectedly"}
	}
	var unknown x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	var network net.Error
	var socketError *websocket.CloseError
	switch {
	case errors.As(err, &socketError):
		d.Detail += fmt.Sprintf(": WebSocket 连接关闭（关闭码 %d）", socketError.Code)
	case errors.As(err, &unknown):
		d.Detail = "x509: certificate signed by unknown authority"
	case errors.As(err, &hostname):
		d.Detail = "x509: certificate does not match the configured server name"
	case errors.As(err, &invalid) && invalid.Reason == x509.Expired:
		d.Detail = "x509: certificate has expired or is not yet valid"
	case errors.As(err, &invalid):
		d.Detail = "x509: certificate is invalid"
	case errors.Is(err, io.ErrUnexpectedEOF):
		d.Detail += ": unexpected EOF"
	case errors.Is(err, io.EOF):
		d.Detail += ": peer closed the connection (EOF)"
	case errors.Is(err, os.ErrPermission):
		d.Detail += ": permission denied"
	case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &network) && network.Timeout()):
		d.Detail += ": deadline exceeded"
	}
	return d
}
