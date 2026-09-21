package sessionproxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/srex-run/access-gateway/internal/terminal"
	"github.com/srex-run/access-gateway/internal/terminalclient"
)

// ExtraTerminalConnection opens and audits additional physical connections
// used by a driver (for example MongoDB's monitoring connection). The agent
// applies the original grant and its shared connection limit to each one.
type ExtraTerminalConnection func(context.Context, net.Conn, Config) error

func ServeClientTerminal(ctx context.Context, cfg Config, backend net.Conn, binding Binding, sink Sink, start terminal.Message, channel terminal.Stream, extra ExtraTerminalConnection) error {
	return serveClientTerminal(ctx, cfg, backend, binding, sink, start, channel, extra, terminalclient.Run)
}

type clientRunner func(context.Context, terminalclient.Options, terminal.Stream, terminalclient.Bridge) error

func serveClientTerminal(ctx context.Context, cfg Config, backend net.Conn, binding Binding, sink Sink, start terminal.Message, channel terminal.Stream, extra ExtraTerminalConnection, run clientRunner) error {
	if cfg.Protocol == "ssh" || !start.ValidFor(cfg.Protocol) || sink == nil || (cfg.Protocol != "http" && binding.Account == "") {
		return ErrProtocol
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { backend.Close() })
	defer stop()
	// This identity exists only for the in-worker client/proxy connection. The
	// approved target CA/pin and account remain unchanged on the backend leg.
	certificate, key, err := terminalIdentity(x509.ExtKeyUsageServerAuth)
	if err != nil {
		return err
	}
	cfg.Certificate, cfg.PrivateKey = certificate, key
	clientCertificate, clientKey, err := terminalIdentity(x509.ExtKeyUsageClientAuth)
	if err != nil {
		return err
	}
	cfg.TerminalClientCA = clientCertificate
	r := &recorder{ctx: ctx, binding: binding, protocol: cfg.Protocol, sink: sink}
	op, err := r.begin("unverified", "client", "interactive "+cfg.Protocol+" client", "", map[string]any{"entry": "web", "cols": start.Cols, "rows": start.Rows})
	if err != nil {
		return err
	}
	if cfg.Protocol == "mysql" {
		cfg.mysqlStartup = &mysqlClientStartup{}
	}
	if cfg.Protocol == "postgresql" {
		cfg.postgresCancels = &postgresCancelRegistry{}
	}
	output := &auditedClientStream{Stream: channel, recorder: r, operation: op, mysqlStartup: cfg.mysqlStartup}

	var used atomic.Bool
	var mu sync.Mutex
	var proxyErr error
	bridge := func(ctx context.Context, client net.Conn) error {
		var e error
		if !used.Swap(true) {
			defer backend.Close()
			_, _, e = Serve(ctx, cfg, client, backend, binding, sink)
		} else if extra != nil {
			e = extra(ctx, client, cfg)
		} else {
			e = ErrProtocol
		}
		if e != nil && ctx.Err() == nil {
			mu.Lock()
			proxyErr = errors.Join(proxyErr, e)
			mu.Unlock()
			// Run closes the browser stream during cancellation. Deliver the
			// safe cause while it is still writable, before killing the client.
			diagnostic := DiagnoseTerminalFailure(e)
			_ = output.Send(terminal.Message{Type: "error", Data: diagnostic.Detail + " (" + diagnostic.Reason + ")"})
			cancel()
		}
		return e
	}
	err = run(ctx, terminalclient.Options{Protocol: cfg.Protocol, Account: binding.Account, Certificate: certificate, ClientCertificate: clientCertificate, ClientKey: clientKey, Start: start}, output, bridge)
	mu.Lock()
	err = errors.Join(err, proxyErr, output.err)
	mu.Unlock()
	result := "success"
	if err != nil && terminal.CloseReason(err) == "" {
		result = "failure"
	}
	return errors.Join(err, op.end(result))
}

type auditedClientStream struct {
	terminal.Stream
	mysqlStartup *mysqlClientStartup
	recorder     *recorder
	operation    *operation
	sequence     uint64
	err          error
}

func (s *auditedClientStream) Send(message terminal.Message) error {
	if message.Type == "exit" {
		if err := s.operation.end("success"); err != nil {
			s.err = err
			return err
		}
	}
	return s.Stream.Send(message)
}

// Database output is observation evidence. The protocol proxy independently
// authenticates the account and records parsed operations before forwarding.
func (s *auditedClientStream) Write(data []byte) (int, error) {
	s.mysqlStartup.observeOutput(data)
	written := 0
	for len(data) > 0 {
		chunk := data[:min(1024, len(data))]
		s.sequence++
		frame, err := s.recorder.begin("unverified", "terminal_output", string(chunk), "", map[string]any{
			"evidence": "terminal_output", "channel_id": s.operation.event.OperationID, "stream": "client",
			"sequence": s.sequence, "encoding": "base64", "data": base64.StdEncoding.EncodeToString(chunk),
		})
		if err == nil {
			err = frame.end("unknown")
		}
		if err != nil {
			s.err = err
			return written, err
		}
		if err = writeAll(s.Stream, chunk); err != nil {
			return written, err
		}
		written += len(chunk)
		data = data[len(chunk):]
	}
	return written, nil
}

func terminalIdentity(usage x509.ExtKeyUsage) (string, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", err
	}
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "session terminal"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(6 * time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"},
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", err
	}
	defer clear(private)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})), nil
}
