package sessionproxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
)

// InspectMySQLCertificate enrolls the current certificate without sending any
// authentication packet. Subsequent sessions must verify the resulting pin.
func InspectMySQLCertificate(ctx context.Context, backend net.Conn) (string, error) {
	identity, err := InspectTargetIdentity(ctx, backend, "mysql", "")
	return identity.CertificateSHA256, err
}

func inspectMySQLCertificate(ctx context.Context, backend net.Conn, serverName string) (string, error) {
	greeting, err := mysqlRead(backend)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrTargetGreeting, err)
	}
	if greeting.seq != 0 || len(greeting.data) < 34 || greeting.data[0] != 10 {
		return "", ErrProtocol
	}
	end := bytes.IndexByte(greeting.data[1:], 0)
	if end < 0 {
		return "", ErrProtocol
	}
	low := 1 + end + 1 + 4 + 8 + 1
	high := low + 2 + 1 + 2
	if len(greeting.data) < high+2 {
		return "", ErrProtocol
	}
	flags := uint32(binary.LittleEndian.Uint16(greeting.data[low:])) | uint32(binary.LittleEndian.Uint16(greeting.data[high:]))<<16
	const required = 1<<9 | 1<<11
	if flags&required != required {
		return "", ErrProtocol
	}
	ssl := mysqlPacket{seq: 1, data: make([]byte, 32)}
	binary.LittleEndian.PutUint32(ssl.data, flags&uint32(1|1<<9|1<<11|1<<15|1<<19))
	binary.LittleEndian.PutUint32(ssl.data[4:], maxFrame)
	ssl.data[8] = 45
	if err := ssl.write(backend); err != nil {
		return "", err
	}
	return inspectTargetTLS(ctx, backend, serverName)
}
