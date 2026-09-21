//go:build darwin || linux

package terminalclient

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/srex-run/access-gateway/internal/terminal"
)

// Reach mutual TLS with the installed MySQL/MariaDB client inside the real
// sandbox. An HTTP client alone does not exercise MySQL's TLS initialization.
func TestNativeMySQLPrivateTrust(t *testing.T) {
	if os.Getenv("RUN_TERMINAL_SANDBOX_TESTS") != "1" {
		t.Skip("requires a MySQL/MariaDB client and RUN_TERMINAL_SANDBOX_TESTS=1")
	}
	certificate, privateKey, serverTLS := nativeTestTLS(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	reader, writer := io.Pipe()
	defer writer.Close()
	stream := &nativeTestStream{input: reader, ready: make(chan struct{}), changed: make(chan struct{}, 1)}
	bridgeResult := make(chan error, 1)
	const marker = "native terminal mutual TLS verified"
	err := Run(ctx, Options{Protocol: "mysql", Account: "reader", Certificate: certificate, ClientCertificate: certificate, ClientKey: privateKey, Start: terminal.Message{Type: "start", Cols: 100, Rows: 30, Password: "temporary-mysql-login"}}, stream, func(ctx context.Context, conn net.Conn) (bridgeErr error) {
		defer func() { bridgeResult <- bridgeErr }()
		deadline, _ := ctx.Deadline()
		if err := conn.SetDeadline(deadline); err != nil {
			return err
		}
		// Protocol 4.1 greeting with SSL, secure authentication and plugin auth.
		const caps = uint32(1 | 1<<2 | 1<<9 | 1<<11 | 1<<13 | 1<<15 | 1<<19)
		greeting := append([]byte{10}, []byte("8.4.0-terminal-test\x00")...)
		fields := make([]byte, 31)
		binary.LittleEndian.PutUint32(fields, 1)
		copy(fields[4:], "12345678")
		binary.LittleEndian.PutUint16(fields[13:], uint16(caps&0xffff))
		fields[15] = 45
		binary.LittleEndian.PutUint16(fields[16:], 2)
		binary.LittleEndian.PutUint16(fields[18:], uint16(caps>>16))
		fields[20] = 21
		greeting = append(greeting, fields...)
		greeting = append(greeting, []byte("abcdefghijkl\x00caching_sha2_password\x00")...)
		if err := writeNativeMySQLPacket(conn, 0, greeting); err != nil {
			return err
		}
		request, err := readNativeMySQLPacket(conn, 1)
		if err != nil {
			return err
		}
		if len(request) != 32 || binary.LittleEndian.Uint32(request)&(1<<11) == 0 {
			return fmt.Errorf("client did not request TLS")
		}
		secure := tls.Server(conn, serverTLS)
		if err := secure.HandshakeContext(ctx); err != nil {
			return err
		}
		if _, err := readNativeMySQLPacket(secure, 2); err != nil {
			return err
		}
		// End the fixture after TLS with a recognizable MySQL error, without
		// requiring an actual database or accepting any SQL statements.
		return writeNativeMySQLPacket(secure, 3, append([]byte{0xff, 0x15, 0x04, '#', '2', '8', '0', '0', '0'}, []byte(marker)...))
	})
	if ctx.Err() != nil {
		t.Fatalf("native client timed out: %v, output=%s", err, stream.text())
	}
	select {
	case bridgeErr := <-bridgeResult:
		if bridgeErr != nil {
			t.Fatalf("native MySQL TLS handshake: %v, output=%s", bridgeErr, stream.text())
		}
	default:
		t.Fatalf("native MySQL never reached the proxy: %v, output=%s", err, stream.text())
	}
	if err == nil || !strings.Contains(stream.text(), marker) {
		t.Fatalf("client did not receive the response over TLS: %v, output=%s", err, stream.text())
	}
	if strings.Contains(stream.text(), "temporary-mysql-login") {
		t.Fatal("initial password appeared in terminal output")
	}
}

func writeNativeMySQLPacket(conn net.Conn, sequence byte, payload []byte) error {
	packet := make([]byte, 4, 4+len(payload))
	binary.LittleEndian.PutUint32(packet, uint32(len(payload)))
	packet[3] = sequence
	_, err := conn.Write(append(packet, payload...))
	return err
}

func readNativeMySQLPacket(conn net.Conn, sequence byte) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, err
	}
	length := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	if header[3] != sequence || length > 16384 {
		return nil, fmt.Errorf("unexpected MySQL packet sequence or size")
	}
	payload := make([]byte, length)
	_, err := io.ReadFull(conn, payload)
	return payload, err
}
