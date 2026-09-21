package gatewayagent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/crypto/ssh"

	"github.com/srex-run/access-gateway/internal/gateway"
)

func nativeTestRecord(kind byte, payload []byte) []byte {
	header := []byte{kind, 3, 3}
	header = binary.BigEndian.AppendUint16(header, uint16(len(payload)))
	return append(header, payload...)
}

func TestNativeEncryptionRejectsTLSRecordDowngrades(t *testing.T) {
	for _, test := range []struct {
		name    string
		version uint16
		wire    []byte
	}{
		{"plaintext after hello", tls.VersionTLS13, []byte("GET /password HTTP/1.1\r\n\r\n")},
		{"TLS12 application before cipher switch", tls.VersionTLS12, nativeTestRecord(23, bytes.Repeat([]byte{1}, 32))},
		{"TLS13 plaintext handshake", tls.VersionTLS13, nativeTestRecord(22, []byte{11, 0, 0, 0})},
		{"TLS12 unknown handshake", tls.VersionTLS12, nativeTestRecord(22, []byte{50, 0, 0, 8, 'p', 'a', 's', 's', 'w', 'o', 'r', 'd'})},
		{"CCS inside unfinished handshake", tls.VersionTLS12, append(nativeTestRecord(22, []byte{16, 0, 0, 4, 1}), nativeTestRecord(20, []byte{1})...)},
		{"repeated CCS", tls.VersionTLS12, append(nativeTestRecord(20, []byte{1}), nativeTestRecord(20, []byte{1})...)},
		{"unencrypted short application record", tls.VersionTLS13, nativeTestRecord(23, []byte("pass"))},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader := &nativeTLSReader{reader: bytes.NewReader(test.wire), version: test.version}
			if _, err := io.Copy(io.Discard, reader); !errors.Is(err, errNativeEncryption) {
				t.Fatalf("record downgrade accepted: %v", err)
			}
		})
	}
}

func TestNativeEncryptionRejectsTLSVersionAndCipherDowngrades(t *testing.T) {
	for _, value := range []struct{ version, cipher uint16 }{{tls.VersionTLS11, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}, {tls.VersionTLS12, 0}, {tls.VersionTLS12, tls.TLS_RSA_WITH_AES_128_GCM_SHA256}} {
		hello := binary.BigEndian.AppendUint16(nil, value.version)
		hello = append(hello, make([]byte, 33)...)
		hello = binary.BigEndian.AppendUint16(hello, value.cipher)
		hello = append(hello, 0)
		if _, _, err := nativeTLSServerHello(hello); err == nil {
			t.Fatalf("version/cipher downgrade accepted: %x %x", value.version, value.cipher)
		}
	}
}

func TestNativeEncryptionRejectsSSHAlgorithmDowngrades(t *testing.T) {
	secure := nativeSSHKex{Kex: []string{"curve25519-sha256"}, HostKey: []string{"ssh-ed25519"},
		CipherUp: []string{"aes128-gcm@openssh.com"}, CipherDown: []string{"aes128-gcm@openssh.com"},
		MACUp: []string{"hmac-sha2-256"}, MACDown: []string{"hmac-sha2-256"}, CompressionUp: []string{"none"}, CompressionDown: []string{"none"}}
	if err := nativeSSHAlgorithms(secure, secure); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"up", "down", "kex", "hostkey", "mac"} {
		client, server := secure, secure
		switch field {
		case "up":
			client.CipherUp, server.CipherUp = []string{"none"}, []string{"none"}
		case "down":
			client.CipherDown, server.CipherDown = []string{"none"}, []string{"none"}
		case "kex":
			client.Kex, server.Kex = []string{"diffie-hellman-group1-sha1"}, []string{"diffie-hellman-group1-sha1"}
		case "hostkey":
			client.HostKey, server.HostKey = []string{"ssh-dss"}, []string{"ssh-dss"}
		case "mac":
			client.CipherUp, server.CipherUp = []string{"aes128-ctr"}, []string{"aes128-ctr"}
			client.MACUp, server.MACUp = []string{"none"}, []string{"none"}
		}
		if err := nativeSSHAlgorithms(client, server); err == nil {
			t.Fatalf("insecure SSH %s accepted", field)
		}
	}
}

func TestNativeEncryptionRejectsSSHAuthBeforeNewKeys(t *testing.T) {
	client, backend := net.Pipe()
	defer client.Close()
	defer backend.Close()
	// A valid unencrypted SSH packet carrying USERAUTH_REQUEST.
	packet := []byte{0, 0, 0, 12, 10, 50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	done := make(chan struct{})
	go func() { defer close(done); _, _ = backend.Write(packet) }()
	reader := &nativeSSHReader{peer: &nativePeer{Conn: client, reader: bufio.NewReader(client)}, deadline: time.Now().Add(time.Second)}
	if _, err := reader.Read(make([]byte, 128)); !errors.Is(err, errNativeEncryption) {
		t.Fatalf("plaintext SSH authentication accepted: %v", err)
	}
	<-done
}

func TestNativeEncryptionRecoveryRevokesPlaintextSessions(t *testing.T) {
	now := time.Now().UTC()
	expires := now.Add(time.Minute)
	store := &memoryStateStore{sessions: []SessionRecord{{
		ConnectionMode: gateway.ConnectionModeDirect, SessionID: testGatewaySessionID, Status: sessionRunning,
		TargetID: testGatewayTargetID, TargetPort: 3306, SourceIP: "127.0.0.1", TargetAccount: "readonly", TTLSeconds: 60,
		MaxConnections: gateway.MaxSessionConnections, StartedAt: &now, ExpiresAt: &expires,
		ProcessID: "tcp-20000", ListenerPort: 20000, ExternalPort: 20000, ExposureMode: "direct", ExposureRef: "direct/20000",
	}}}
	controller := &controllerStub{}
	catalog, err := NewAssetCatalog([]AssetCatalogEntry{{TargetID: testGatewayTargetID, Ports: []int{3306}}})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(controller, store, catalog, time.Hour, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if controller.startCalls != 0 || controller.stopCalls != 1 {
		t.Fatal("plaintext session restored")
	}
	status, err := manager.Get(context.Background(), testGatewaySessionID)
	if err != nil || status.Status != sessionClosed {
		t.Fatalf("plaintext session was not revoked: %+v %v", status, err)
	}
}

func FuzzNativeEncryptionWireParsers(f *testing.F) {
	f.Add([]byte("GET / HTTP/1.1\r\n"))
	f.Add(mysqlGreeting(true))
	f.Add(nativeTestRecord(22, []byte{1, 0, 0, 0}))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 128*1024 {
			t.Skip()
		}
		_, _ = readMySQLPacket(bytes.NewReader(data), 4096)
		_, _ = readNativeTLSRecord(bytes.NewReader(data))
		_, _, _, _ = readNativeTLSHello(bytes.NewReader(data), 1, true)
		_, _, _ = nativeTLSServerHello(data)
		_ = validateNativeTLSClientHello(data)
		_, _, _ = readNativeSSHPacket(bytes.NewReader(data))
		var kex nativeSSHKex
		_ = ssh.Unmarshal(data, &kex)
	})
}
