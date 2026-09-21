package sessionproxy

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

type TargetIdentity struct {
	CertificateSHA256 string
	SSHHostPublicKey  string
}

// InspectTargetIdentity enrolls a target's public identity without logging in
// or sending application commands. The administrator's save establishes trust;
// subsequent sessions must verify the enrolled pin or host key.
func InspectTargetIdentity(ctx context.Context, backend net.Conn, protocol, serverName string) (TargetIdentity, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	if err := backend.SetDeadline(deadline); err != nil {
		return TargetIdentity{}, err
	}
	stop := context.AfterFunc(ctx, func() { _ = backend.Close() })
	defer stop()
	if err := ctx.Err(); err != nil {
		return TargetIdentity{}, err
	}
	if protocol == "ssh" {
		key, err := inspectSSHHostKey(backend)
		if ctx.Err() != nil {
			return TargetIdentity{}, ctx.Err()
		}
		return TargetIdentity{SSHHostPublicKey: key}, err
	}
	if protocol == "mysql" {
		pin, err := inspectMySQLCertificate(ctx, backend, serverName)
		return TargetIdentity{CertificateSHA256: pin}, err
	}
	switch protocol {
	case "postgresql":
		var request [8]byte
		binary.BigEndian.PutUint32(request[:4], 8)
		binary.BigEndian.PutUint32(request[4:], 80877103)
		if err := writeAll(backend, request[:]); err != nil {
			return TargetIdentity{}, err
		}
		var answer [1]byte
		if _, err := io.ReadFull(backend, answer[:]); err != nil {
			return TargetIdentity{}, err
		}
		if answer[0] != 'S' {
			return TargetIdentity{}, ErrProtocol
		}
	case "redis", "mongodb", "http":
	default:
		return TargetIdentity{}, ErrProtocol
	}
	pin, err := inspectTargetTLS(ctx, backend, serverName)
	return TargetIdentity{CertificateSHA256: pin}, err
}

func inspectTargetTLS(ctx context.Context, backend net.Conn, serverName string) (string, error) {
	var fingerprint string
	secure := tls.Client(backend, &tls.Config{
		MinVersion: tls.VersionTLS12, ServerName: serverName,
		// Enrollment intentionally accepts a self-signed identity. No login or
		// application data is sent; all later connections enforce this pin.
		InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return ErrIdentity
			}
			cert := state.PeerCertificates[0]
			now := time.Now()
			if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
				return ErrIdentity
			}
			sum := sha256.Sum256(cert.Raw)
			fingerprint = hex.EncodeToString(sum[:])
			return nil
		},
	})
	if err := secure.HandshakeContext(ctx); err != nil {
		return "", fmt.Errorf("%w: %w", ErrTargetTLS, err)
	}
	return fingerprint, nil
}

func inspectSSHHostKey(backend net.Conn) (string, error) {
	collected := errors.New("target host key collected")
	var publicKey string
	conn, _, _, err := ssh.NewClientConn(backend, backend.RemoteAddr().String(), &ssh.ClientConfig{
		User: "access-gateway-enroll", Timeout: 10 * time.Second,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			publicKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
			// Stop at host verification, before requesting user authentication.
			return collected
		},
	})
	if conn != nil {
		_ = conn.Close()
	}
	if !errors.Is(err, collected) || publicKey == "" || len(publicKey) > 32768 {
		return "", fmt.Errorf("%w: could not read SSH host key", ErrIdentity)
	}
	return publicKey, nil
}
