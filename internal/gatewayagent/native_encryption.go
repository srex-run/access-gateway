package gatewayagent

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"slices"
	"time"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/ssh"
)

var errNativeEncryption = errors.New("native connection requires SSH or TLS 1.2+")

// Reasons are fixed identifiers; never put peer payloads, credentials or target
// addresses into audit events or local diagnostic logs.
type nativeHandshakeError string

func (e nativeHandshakeError) Error() string { return string(e) }
func (e nativeHandshakeError) Unwrap() error { return errNativeEncryption }

func nativeHandshakeReason(err error) string {
	var failure nativeHandshakeError
	if errors.As(err, &failure) {
		return string(failure)
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return "native_handshake_timeout"
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) {
		return "native_handshake_closed"
	}
	return "native_encryption_required"
}

const nativeHandshakeTimeout = 10 * time.Second

type nativePeer struct {
	net.Conn
	reader *bufio.Reader
	ready  chan error
}

func (p *nativePeer) Read(b []byte) (int, error) { return p.reader.Read(b) }
func (p *nativePeer) CloseWrite() error {
	if conn, ok := p.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return p.Close()
}

type encryptedNativeStream struct {
	client, backend net.Conn
	protocol        string
	up, down        int64
}

// The endpoints perform cryptography and certificate/host-key verification.
// This guard allows only public protocol negotiation before encrypted traffic;
// it never terminates TLS/SSH or substitutes a gateway identity for the target.
func negotiateNativeEncryption(client, backend net.Conn) (stream encryptedNativeStream, err error) {
	deadline := time.Now().Add(nativeHandshakeTimeout)
	_ = client.SetDeadline(deadline)
	_ = backend.SetDeadline(deadline)
	peers := []*nativePeer{
		{Conn: client, reader: bufio.NewReader(client), ready: make(chan error, 1)},
		{Conn: backend, reader: bufio.NewReader(backend), ready: make(chan error, 1)},
	}
	type probe struct {
		index int
		first byte
		err   error
	}
	probes := make(chan probe, 2)
	for index, peer := range peers {
		go func() {
			first, readErr := peer.reader.Peek(1)
			value := byte(0)
			if len(first) != 0 {
				value = first[0]
			}
			peer.ready <- readErr
			probes <- probe{index, value, readErr}
		}()
	}
	defer func() {
		if err != nil {
			_ = client.Close()
			_ = backend.Close()
		}
		// Both probes must exit before returning their buffered readers.
		for _, peer := range peers {
			<-peer.ready
		}
		if err == nil {
			_ = client.SetDeadline(time.Time{})
			_ = backend.SetDeadline(time.Time{})
		}
	}()
	first := <-probes
	if first.err != nil {
		return stream, first.err
	}
	stream.client, stream.backend = peers[0], peers[1]
	sshBanner := false
	if first.first == 'S' {
		if err = waitNativePeer(peers[first.index]); err != nil {
			return stream, err
		}
		prefix, peekErr := peers[first.index].reader.Peek(4)
		if peekErr != nil {
			return stream, peekErr
		}
		sshBanner = bytes.Equal(prefix, []byte("SSH-"))
	}
	switch {
	case sshBanner:
		stream.protocol = "ssh"
		err = negotiateNativeSSH(peers[0], peers[1], &stream)
	case first.index == 0 && first.first == 22:
		stream.protocol = "tls"
		err = negotiateNativeTLS(peers[0], peers[1], &stream)
	case first.index == 0 && first.first == 0:
		stream.protocol = "postgresql_tls"
		err = negotiateNativePostgreSQL(peers[0], peers[1], &stream)
	case first.index == 1:
		stream.protocol = "mysql_tls"
		err = negotiateNativeMySQL(peers[0], peers[1], &stream)
	default:
		err = errNativeEncryption
	}
	return stream, err
}

// A probe only peeks. Waiting leaves its result available for the final join.
func waitNativePeer(p *nativePeer) error {
	err := <-p.ready
	p.ready <- err
	return err
}

func writeNative(conn net.Conn, value []byte, count *int64) error {
	n, err := conn.Write(value)
	*count += int64(n)
	if err == nil && n != len(value) {
		err = io.ErrShortWrite
	}
	return err
}

func readMySQLPacket(reader io.Reader, maximum int) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	size := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	if size < 1 || size > maximum {
		return nil, errNativeEncryption
	}
	packet := append(header, make([]byte, size)...)
	_, err := io.ReadFull(reader, packet[4:])
	return packet, err
}

func negotiateNativeMySQL(client, backend *nativePeer, stream *encryptedNativeStream) error {
	if err := waitNativePeer(backend); err != nil {
		return err
	}
	greeting, err := readMySQLPacket(backend, 4096)
	if err != nil {
		return err
	}
	if greeting[3] == 0 && greeting[4] == 0xff && len(greeting) >= 7 {
		return nativeHandshakeError("mysql_server_rejected_connection")
	}
	if greeting[3] != 0 || greeting[4] != 10 {
		return nativeHandshakeError("mysql_invalid_server_greeting")
	}
	versionEnd := bytes.IndexByte(greeting[5:], 0)
	if versionEnd < 0 || versionEnd > 255 {
		return nativeHandshakeError("mysql_invalid_server_greeting")
	}
	// Protocol 10: server version, connection ID, salt, filler, capabilities.
	capOffset := 5 + versionEnd + 1 + 4 + 8 + 1
	if len(greeting) < capOffset+8 {
		return nativeHandshakeError("mysql_invalid_server_greeting")
	}
	capabilities := binary.LittleEndian.Uint16(greeting[capOffset:])
	const clientSSL = 1 << 11
	const protocol41 = 1 << 9
	if capabilities&protocol41 == 0 {
		return nativeHandshakeError("mysql_protocol41_required")
	}
	if capabilities&clientSSL == 0 {
		return nativeHandshakeError("mysql_target_tls_unavailable")
	}
	if err := writeNative(client, greeting, &stream.down); err != nil {
		return err
	}
	if err := waitNativePeer(client); err != nil {
		return err
	}
	// Read only a bounded SSLRequest. A plaintext login can contain a password
	// response and must never be forwarded to the target.
	request, err := readMySQLPacket(client, 32)
	if err != nil {
		if errors.Is(err, errNativeEncryption) {
			return nativeHandshakeError("mysql_client_tls_required")
		}
		return err
	}
	if len(request) != 36 || request[3] != 1 || binary.LittleEndian.Uint32(request[4:])&(clientSSL|protocol41) != clientSSL|protocol41 {
		return nativeHandshakeError("mysql_client_tls_required")
	}
	if !bytes.Equal(request[13:], make([]byte, 23)) {
		return nativeHandshakeError("mysql_invalid_ssl_request")
	}
	if err := writeNative(backend, request, &stream.up); err != nil {
		return err
	}
	return negotiateNativeTLS(client, backend, stream)
}

// PostgreSQL starts TLS with an eight-byte SSLRequest before the regular TLS
// ClientHello. Forward only the exact request and the one-byte server answer;
// a plaintext startup packet is rejected before it reaches the target.
func negotiateNativePostgreSQL(client, backend *nativePeer, stream *encryptedNativeStream) error {
	if err := waitNativePeer(client); err != nil {
		return err
	}
	request := make([]byte, 8)
	if _, err := io.ReadFull(client, request[:4]); err != nil {
		return err
	}
	// Reject arbitrary binary/plaintext prefixes as soon as the packet length
	// is known instead of waiting for the full PostgreSQL request.
	if binary.BigEndian.Uint32(request[:4]) != 8 {
		return nativeHandshakeError("postgresql_client_tls_required")
	}
	if _, err := io.ReadFull(client, request[4:]); err != nil {
		return err
	}
	if binary.BigEndian.Uint32(request[4:]) != 80877103 {
		return nativeHandshakeError("postgresql_client_tls_required")
	}
	if err := writeNative(backend, request, &stream.up); err != nil {
		return err
	}
	if err := waitNativePeer(backend); err != nil {
		return err
	}
	answer := []byte{0}
	if _, err := io.ReadFull(backend, answer); err != nil {
		return err
	}
	switch answer[0] {
	case 'S':
		if err := writeNative(client, answer, &stream.down); err != nil {
			return err
		}
	case 'N':
		return nativeHandshakeError("postgresql_target_tls_unavailable")
	default:
		return nativeHandshakeError("postgresql_invalid_ssl_response")
	}
	return negotiateNativeTLS(client, backend, stream)
}

func readNativeTLSRecord(reader io.Reader) ([]byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(header[3:]))
	if header[1] != 3 || header[2] < 1 || header[2] > 3 || length < 1 || length > 16384+2048 {
		return nil, errNativeEncryption
	}
	record := append(header, make([]byte, length)...)
	_, err := io.ReadFull(reader, record[5:])
	return record, err
}

func readNativeTLSHello(reader io.Reader, kind byte, allowCCS bool) (wire, hello, extra []byte, err error) {
	for len(wire) < 128*1024 {
		var record []byte
		record, err = readNativeTLSRecord(reader)
		if err != nil {
			return
		}
		wire = append(wire, record...)
		if allowCCS && record[0] == 20 && bytes.Equal(record[5:], []byte{1}) {
			allowCCS = false
			continue
		}
		if record[0] != 22 {
			err = errNativeEncryption
			return
		}
		hello = append(hello, record[5:]...)
		if hello[0] != kind {
			err = errNativeEncryption
			return
		}
		if len(hello) < 4 {
			continue
		}
		size := int(hello[1])<<16 | int(hello[2])<<8 | int(hello[3])
		if size > 65536 {
			err = errNativeEncryption
			return
		}
		if len(hello) >= 4+size {
			extra = hello[4+size:]
			hello = hello[4 : 4+size]
			return
		}
	}
	err = errNativeEncryption
	return
}

func nativeTLSServerHello(hello []byte) (version uint16, retry bool, err error) {
	data := cryptobyte.String(hello)
	var random []byte
	var session, extensions cryptobyte.String
	var cipher uint16
	var compression uint8
	if !data.ReadUint16(&version) || !data.ReadBytes(&random, 32) || !data.ReadUint8LengthPrefixed(&session) ||
		len(session) > 32 || !data.ReadUint16(&cipher) || !data.ReadUint8(&compression) || compression != 0 {
		return 0, false, errNativeEncryption
	}
	if version != tls.VersionTLS12 {
		return 0, false, errNativeEncryption
	}
	if !data.Empty() && (!data.ReadUint16LengthPrefixed(&extensions) || !data.Empty()) {
		return 0, false, errNativeEncryption
	}
	seen := make(map[uint16]bool)
	for !extensions.Empty() {
		var kind uint16
		var value cryptobyte.String
		if !extensions.ReadUint16(&kind) || !extensions.ReadUint16LengthPrefixed(&value) || seen[kind] {
			return 0, false, errNativeEncryption
		}
		seen[kind] = true
		if kind == 43 {
			if !value.ReadUint16(&version) || !value.Empty() {
				return 0, false, errNativeEncryption
			}
		}
	}
	validCipher := false
	if version == tls.VersionTLS13 {
		validCipher = cipher == tls.TLS_AES_128_GCM_SHA256 || cipher == tls.TLS_AES_256_GCM_SHA384 || cipher == tls.TLS_CHACHA20_POLY1305_SHA256
	} else if version == tls.VersionTLS12 {
		validCipher = slices.Contains([]uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256}, cipher)
	}
	if !validCipher {
		return 0, false, errNativeEncryption
	}
	retryRandom := []byte{0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c}
	return version, version == tls.VersionTLS13 && bytes.Equal(random, retryRandom), nil
}

func validateNativeTLSClientHello(hello []byte) error {
	data := cryptobyte.String(hello)
	var legacyVersion uint16
	var session, ciphers, compression, extensions cryptobyte.String
	if !data.ReadUint16(&legacyVersion) || legacyVersion != tls.VersionTLS12 || !data.Skip(32) ||
		!data.ReadUint8LengthPrefixed(&session) || len(session) > 32 ||
		!data.ReadUint16LengthPrefixed(&ciphers) || len(ciphers) == 0 || len(ciphers)%2 != 0 ||
		!data.ReadUint8LengthPrefixed(&compression) || !bytes.Equal(compression, []byte{0}) {
		return errNativeEncryption
	}
	if !data.Empty() && (!data.ReadUint16LengthPrefixed(&extensions) || !data.Empty()) {
		return errNativeEncryption
	}
	seen := make(map[uint16]bool)
	for !extensions.Empty() {
		var kind uint16
		var value cryptobyte.String
		if !extensions.ReadUint16(&kind) || !extensions.ReadUint16LengthPrefixed(&value) || seen[kind] {
			return errNativeEncryption
		}
		seen[kind] = true
		if kind == 43 {
			var versions cryptobyte.String
			if !value.ReadUint8LengthPrefixed(&versions) || !value.Empty() || len(versions) == 0 || len(versions)%2 != 0 {
				return errNativeEncryption
			}
			supported := false
			for !versions.Empty() {
				var version uint16
				if !versions.ReadUint16(&version) {
					return errNativeEncryption
				}
				supported = supported || version == tls.VersionTLS12 || version == tls.VersionTLS13
			}
			if !supported {
				return errNativeEncryption
			}
		}
	}
	return nil
}

func negotiateNativeTLS(client, backend *nativePeer, stream *encryptedNativeStream) error {
	for attempt := 0; attempt < 2; attempt++ {
		var wire, hello, extra []byte
		err := nativeBoth(client, backend, func() error {
			if err := waitNativePeer(client); err != nil {
				return err
			}
			clientWire, clientHello, extra, err := readNativeTLSHello(client, 1, attempt > 0)
			if err != nil {
				return err
			}
			if validateNativeTLSClientHello(clientHello) != nil || len(extra) != 0 {
				return errNativeEncryption
			}
			return writeNative(backend, clientWire, &stream.up)
		}, func() error {
			if err := waitNativePeer(backend); err != nil {
				return err
			}
			var err error
			wire, hello, extra, err = readNativeTLSHello(backend, 2, attempt > 0)
			return err
		})
		if err != nil {
			return err
		}
		version, retry, err := nativeTLSServerHello(hello)
		if err != nil {
			return err
		}
		if version == tls.VersionTLS13 && len(extra) != 0 || retry && attempt != 0 {
			return errNativeEncryption
		}
		serverReader := &nativeTLSReader{reader: backend, conn: backend, deadline: time.Now().Add(nativeHandshakeTimeout), version: version, server: true}
		if err := serverReader.handshake(extra); err != nil {
			return err
		}
		if err := writeNative(client, wire, &stream.down); err != nil {
			return err
		}
		if retry {
			continue
		}
		stream.client = &nativeGuardConn{nativePeer: client, reader: &nativeTLSReader{reader: client, conn: client, deadline: serverReader.deadline, version: version}}
		stream.backend = &nativeGuardConn{nativePeer: backend, reader: serverReader}
		return nil
	}
	return errNativeEncryption
}

type nativeGuardConn struct {
	*nativePeer
	reader io.Reader
}

func (c *nativeGuardConn) Read(b []byte) (int, error) { return c.reader.Read(b) }

// Validate every TLS record, not just a sniffed prefix. TLS 1.2 must switch
// cipher state before application data; TLS 1.3 encrypts after ServerHello.
type nativeTLSReader struct {
	reader                          io.Reader
	conn                            net.Conn
	deadline                        time.Time
	version                         uint16
	server, encrypted, ccs, secured bool
	pending                         []byte
	wire                            []byte
	handshakeBytes                  int
	handshakeLeft                   int
}

func (r *nativeTLSReader) handshake(data []byte) error {
	r.handshakeBytes += len(data)
	if r.handshakeBytes > 1<<20 {
		return errNativeEncryption
	}
	for len(data) > 0 {
		if r.handshakeLeft > 0 {
			n := min(r.handshakeLeft, len(data))
			r.handshakeLeft -= n
			data = data[n:]
			continue
		}
		// Header fragments are held until their length is known.
		r.pending = append(r.pending, data[0])
		data = data[1:]
		if len(r.pending) == 1 {
			allowed := []byte{11, 15, 16}
			if r.server {
				allowed = []byte{4, 11, 12, 13, 14, 22}
			}
			if !slices.Contains(allowed, r.pending[0]) {
				return errNativeEncryption
			}
		}
		if len(r.pending) == 4 {
			r.handshakeLeft = int(r.pending[1])<<16 | int(r.pending[2])<<8 | int(r.pending[3])
			if r.handshakeLeft > 1<<20 {
				return errNativeEncryption
			}
			r.pending = nil
		}
	}
	return nil
}

func (r *nativeTLSReader) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if len(r.wire) == 0 {
		if !r.secured && r.conn != nil {
			_ = r.conn.SetReadDeadline(r.deadline)
		}
		record, err := readNativeTLSRecord(r.reader)
		if err != nil {
			return 0, err
		}
		switch record[0] {
		case 20:
			if r.ccs || !bytes.Equal(record[5:], []byte{1}) || r.handshakeLeft != 0 || len(r.pending) != 0 {
				return 0, errNativeEncryption
			}
			r.ccs = true
			if r.version == tls.VersionTLS12 {
				r.encrypted = true
			}
		case 22:
			if r.version == tls.VersionTLS13 {
				return 0, errNativeEncryption
			}
			if !r.encrypted {
				if err := r.handshake(record[5:]); err != nil {
					return 0, err
				}
			} else if len(record[5:]) < 16 {
				return 0, errNativeEncryption
			}
		case 23:
			if r.version == tls.VersionTLS12 && !r.encrypted || len(record[5:]) < 16 {
				return 0, errNativeEncryption
			}
		case 21:
			if r.version == tls.VersionTLS13 || !r.encrypted && len(record[5:]) != 2 || r.encrypted && len(record[5:]) < 16 {
				return 0, errNativeEncryption
			}
		default:
			return 0, errNativeEncryption
		}
		if record[0] == 23 || record[0] == 22 && r.encrypted {
			r.secured = true
			if r.conn != nil {
				_ = r.conn.SetReadDeadline(time.Time{})
			}
		}
		r.wire = record
	}
	n := copy(b, r.wire)
	r.wire = r.wire[n:]
	return n, nil
}

type nativeSSHKex struct {
	Cookie                                                                                                       [16]byte `sshtype:"20"`
	Kex, HostKey, CipherUp, CipherDown, MACUp, MACDown, CompressionUp, CompressionDown, LanguageUp, LanguageDown []string
	FirstKexFollows                                                                                              bool
	Reserved                                                                                                     uint32
}

func readNativeSSHPacket(reader io.Reader) (wire, payload []byte, err error) {
	header := make([]byte, 5)
	if _, err = io.ReadFull(reader, header); err != nil {
		return
	}
	size := int(binary.BigEndian.Uint32(header))
	padding := int(header[4])
	if size < 6 || size > 35000 || (size+4)%8 != 0 || padding < 4 || padding >= size-1 {
		return nil, nil, errNativeEncryption
	}
	wire = append(header, make([]byte, size-1)...)
	_, err = io.ReadFull(reader, wire[5:])
	return wire, wire[5 : len(wire)-padding], err
}

func nativeSSHAlgorithms(client, server nativeSSHKex) error {
	supported := ssh.SupportedAlgorithms()
	for _, lists := range [][3][]string{
		{client.Kex, server.Kex, supported.KeyExchanges}, {client.HostKey, server.HostKey, supported.HostKeys},
		{client.CipherUp, server.CipherUp, supported.Ciphers}, {client.CipherDown, server.CipherDown, supported.Ciphers},
		{client.CompressionUp, server.CompressionUp, {"none", "zlib@openssh.com"}},
		{client.CompressionDown, server.CompressionDown, {"none", "zlib@openssh.com"}},
	} {
		if !slices.Contains(lists[2], firstNativeCommon(lists[0], lists[1])) {
			return errNativeEncryption
		}
	}
	for _, lists := range [][4][]string{{client.CipherUp, server.CipherUp, client.MACUp, server.MACUp}, {client.CipherDown, server.CipherDown, client.MACDown, server.MACDown}} {
		cipher := firstNativeCommon(lists[0], lists[1])
		if cipher == "chacha20-poly1305@openssh.com" || cipher == "aes128-gcm@openssh.com" || cipher == "aes256-gcm@openssh.com" {
			continue
		}
		if !slices.Contains(supported.MACs, firstNativeCommon(lists[2], lists[3])) {
			return errNativeEncryption
		}
	}
	return nil
}

func firstNativeCommon(client, server []string) string {
	for _, value := range client {
		if slices.Contains(server, value) {
			return value
		}
	}
	return ""
}

func nativeBoth(client, backend net.Conn, operations ...func() error) error {
	results := make(chan error, len(operations))
	for _, operation := range operations {
		go func() { results <- operation() }()
	}
	var failures []error
	for range operations {
		if err := <-results; err != nil {
			failures = append(failures, err)
			_ = client.Close()
			_ = backend.Close()
		}
	}
	return errors.Join(failures...)
}

func negotiateNativeSSH(client, backend *nativePeer, stream *encryptedNativeStream) error {
	banner := func(from *nativePeer, to net.Conn, count *int64) error {
		if err := waitNativePeer(from); err != nil {
			return err
		}
		line, err := from.reader.ReadSlice('\n')
		if err != nil {
			return err
		}
		if len(line) > 255 || !bytes.HasPrefix(line, []byte("SSH-2.0-")) || !bytes.HasSuffix(line, []byte("\r\n")) {
			return errNativeEncryption
		}
		return writeNative(to, line, count)
	}
	if err := nativeBoth(client, backend, func() error { return banner(client, backend, &stream.up) }, func() error { return banner(backend, client, &stream.down) }); err != nil {
		return err
	}
	var clientKex, serverKex nativeSSHKex
	var clientWire, serverWire []byte
	readKex := func(from io.Reader, wire *[]byte, kex *nativeSSHKex) error {
		packet, payload, err := readNativeSSHPacket(from)
		if err != nil {
			return err
		}
		if err := ssh.Unmarshal(payload, kex); err != nil {
			return errNativeEncryption
		}
		*wire = packet
		return nil
	}
	if err := nativeBoth(client, backend, func() error { return readKex(client, &clientWire, &clientKex) }, func() error { return readKex(backend, &serverWire, &serverKex) }); err != nil {
		return err
	}
	if err := nativeSSHAlgorithms(clientKex, serverKex); err != nil {
		return err
	}
	if err := nativeBoth(client, backend, func() error { return writeNative(backend, clientWire, &stream.up) }, func() error { return writeNative(client, serverWire, &stream.down) }); err != nil {
		return err
	}
	deadline := time.Now().Add(nativeHandshakeTimeout)
	stream.client = &nativeGuardConn{nativePeer: client, reader: &nativeSSHReader{peer: client, deadline: deadline}}
	stream.backend = &nativeGuardConn{nativePeer: backend, reader: &nativeSSHReader{peer: backend, deadline: deadline}}
	return nil
}

// Each direction switches independently, so an encrypted server extension
// cannot block delivery of the client's NEWKEYS packet.
type nativeSSHReader struct {
	peer      *nativePeer
	deadline  time.Time
	wire      []byte
	encrypted bool
	packets   int
}

func (r *nativeSSHReader) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if len(r.wire) == 0 {
		if r.encrypted {
			_ = r.peer.SetReadDeadline(time.Time{})
			return r.peer.Read(b)
		}
		_ = r.peer.SetReadDeadline(r.deadline)
		r.packets++
		if r.packets > 32 {
			return 0, errNativeEncryption
		}
		wire, payload, err := readNativeSSHPacket(r.peer)
		if err != nil {
			return 0, err
		}
		kind := payload[0]
		if kind != 21 && (kind < 30 || kind > 49) || kind == 21 && len(payload) != 1 {
			return 0, errNativeEncryption
		}
		r.encrypted = kind == 21
		r.wire = wire
	}
	n := copy(b, r.wire)
	r.wire = r.wire[n:]
	return n, nil
}
