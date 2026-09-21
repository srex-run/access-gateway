package sessionproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"
)

const maxFrame = 16 << 20

var ErrClientTLS = errors.New("client TLS handshake failed")
var ErrTargetTLS = errors.New("target TLS verification or handshake failed")
var ErrTargetGreeting = errors.New("target MySQL greeting was not received")

func handshakeTLS(ctx context.Context, client, backend *tls.Conn) error {
	if err := client.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("%w: %w", ErrClientTLS, err)
	}
	if err := backend.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("%w: %w", ErrTargetTLS, err)
	}
	return nil
}

// TargetTLSFailureReason omits certificate names and target addresses from
// diagnostics exposed to clients and persisted in connection events.
func TargetTLSFailureReason(err error) string {
	var unknown x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	switch {
	case errors.As(err, &unknown):
		return "target_certificate_untrusted"
	case errors.As(err, &hostname):
		return "target_certificate_name_mismatch"
	case errors.As(err, &invalid) && invalid.Reason == x509.Expired:
		return "target_certificate_expired_or_not_yet_valid"
	case errors.Is(err, ErrIdentity):
		return "target_certificate_pin_rejected"
	default:
		return "target_tls_verification_failed"
	}
}

type countedConn struct {
	net.Conn
	read, written atomic.Int64
}

func (c *countedConn) Read(p []byte) (int, error) {
	n, e := c.Conn.Read(p)
	c.read.Add(int64(n))
	return n, e
}
func (c *countedConn) Write(p []byte) (int, error) {
	n, e := c.Conn.Write(p)
	c.written.Add(int64(n))
	return n, e
}

func Serve(ctx context.Context, config Config, client, backend net.Conn, binding Binding, sink Sink) (up, down int64, err error) {
	if sink == nil {
		return 0, 0, ErrAudit
	}
	c := &countedConn{Conn: client}
	b := &countedConn{Conn: backend}
	defer func() { up = c.read.Load(); down = c.written.Load() }()
	stop := context.AfterFunc(ctx, func() { c.Close(); b.Close() })
	defer stop()
	r := &recorder{ctx: ctx, binding: binding, protocol: config.Protocol, sink: sink, mysqlStartup: config.mysqlStartup}
	deadline := time.Now().Add(30 * time.Second)
	c.SetDeadline(deadline)
	b.SetDeadline(deadline)
	if config.Protocol == "ssh" {
		err = serveSSH(config, c, b, r)
		return
	}
	front, back, e := config.TLS(binding.TargetHost)
	if e != nil {
		err = e
		return
	}
	switch config.Protocol {
	case "mysql":
		err = serveMySQL(c, b, front, back, r)
	case "postgresql":
		err = servePostgres(c, b, front, back, r, config.postgresCancels)
	default:
		front.NextProtos = []string{"h2", "http/1.1"}
		if config.Protocol != "http" {
			front.NextProtos = nil
		}
		ct, bt := tls.Server(c, front), tls.Client(b, back)
		if err = handshakeTLS(ctx, ct, bt); err != nil {
			return
		}
		c.SetDeadline(time.Time{})
		b.SetDeadline(time.Time{})
		switch config.Protocol {
		case "redis":
			err = serveRedis(ct, bt, r)
		case "mongodb":
			err = serveMongo(ct, bt, r)
		case "http":
			err = serveHTTP(ct, bt, r)
		default:
			err = ErrProtocol
		}
	}
	if err == io.EOF {
		err = nil
	}
	return
}

func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, e := w.Write(b)
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}

func pumpResult(first, second error) error {
	for _, sentinel := range []error{ErrAudit, ErrIdentity, ErrProtocol} {
		if errors.Is(first, sentinel) {
			return first
		}
		if errors.Is(second, sentinel) {
			return second
		}
	}
	if first == nil || second == nil || errors.Is(first, io.EOF) || errors.Is(second, io.EOF) {
		return nil
	}
	return errors.Join(first, second)
}
