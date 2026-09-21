package sessionproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"github.com/srex-run/access-gateway/internal/terminal"
	"github.com/srex-run/access-gateway/internal/terminalclient"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

const auditMySQLFlags = uint32(1 | 1<<2 | 1<<9 | 1<<11 | 1<<13 | 1<<15 | 1<<19)

// Exercise the same encrypted Serve entry point used by the per-session agent.
// No database daemon, extra collector process or host listener is needed.
func auditStream(t *testing.T, protocol string, target func(net.Conn) error, client func(net.Conn) error) []string {
	t.Helper()
	var operations []string
	for _, web := range []bool{false, true} {
		t.Run(fmt.Sprintf("web=%v", web), func(t *testing.T) { operations = auditStreamMode(t, protocol, target, client, web) })
	}
	return operations
}

type auditStreamOptions struct {
	userInput   string
	clientReady bool
	inspect     func(*recordingSink)
}

func auditStreamMode(t *testing.T, protocol string, target func(net.Conn) error, client func(net.Conn) error, web bool, options ...auditStreamOptions) []string {
	t.Helper()
	now := time.Now()
	identity := newAuditTLSFixture(t, []string{"asset.test"}, now.Add(-time.Hour), now.Add(time.Hour))
	cfg := Config{Protocol: protocol, Certificate: identity.certificate, PrivateKey: identity.key, TargetCA: identity.certificate, TargetServerName: "asset.test"}
	visitor, front := net.Pipe()
	back, asset := net.Pipe()
	for _, conn := range []net.Conn{visitor, front, back, asset} {
		t.Cleanup(func() { conn.Close() })
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { visitor.Close(); front.Close(); back.Close(); asset.Close() })
	defer stop()
	sink := &recordingSink{}
	proxyDone, targetDone := make(chan error, 1), make(chan error, 1)
	clientCA := make(chan terminalclient.Options, 1)
	go func() {
		defer front.Close()
		defer back.Close()
		binding := Binding{Account: "reader", TargetHost: "asset.test", TargetPort: 443}
		var err error
		if web {
			channel := &browserTerminal{}
			err = serveClientTerminal(ctx, cfg, back, binding, sink, terminal.Message{Type: "start", Password: "sensitive-value", Cols: 100, Rows: 30}, channel, nil,
				func(ctx context.Context, clientOptions terminalclient.Options, stream terminal.Stream, bridge terminalclient.Bridge) error {
					if clientOptions.Account != binding.Account || clientOptions.Protocol != protocol {
						return ErrIdentity
					}
					if len(options) > 0 && options[0].clientReady {
						// Exercise prompt detection across real terminal output frames.
						for _, data := range []string{"my", "sql>", " "} {
							if _, err := stream.Write([]byte(data)); err != nil {
								return err
							}
						}
					}
					if len(options) > 0 && options[0].userInput != "" {
						reader, writer := io.Pipe()
						channel.input = reader
						defer reader.Close()
						go func() { _, _ = writer.Write([]byte(options[0].userInput)); _ = writer.Close() }()
						if _, err := io.ReadFull(stream, make([]byte, len(options[0].userInput))); err != nil {
							return err
						}
					}
					clientCA <- clientOptions
					return bridge(ctx, front)
				})
		} else {
			clientCA <- terminalclient.Options{Certificate: identity.certificate}
			_, _, err = Serve(ctx, cfg, front, back, binding, sink)
		}
		proxyDone <- err
	}()
	go func() {
		defer asset.Close()
		if protocol == "postgresql" {
			ssl, err := pgStartup(asset)
			if err != nil || !bytes.Equal(ssl, []byte{0, 0, 0, 8, 4, 210, 22, 47}) {
				targetDone <- fmt.Errorf("invalid TLS upgrade: %v", err)
				return
			}
			if err = writeAll(asset, []byte("S")); err != nil {
				targetDone <- err
				return
			}
		}
		if protocol == "mysql" {
			if err := mysqlHandshakeGreeting(auditMySQLFlags).write(asset); err != nil {
				targetDone <- err
				return
			}
			ssl, err := mysqlRead(asset)
			if err != nil || ssl.seq != 1 || len(ssl.data) != 32 {
				targetDone <- fmt.Errorf("invalid MySQL TLS request: %v", err)
				return
			}
		}
		secure := tls.Server(asset, &tls.Config{Certificates: []tls.Certificate{identity.pair}, MinVersion: tls.VersionTLS12})
		targetDone <- target(secure)
	}()
	clientOptions := <-clientCA
	if protocol == "postgresql" {
		if err := writeAll(visitor, []byte{0, 0, 0, 8, 4, 210, 22, 47}); err != nil {
			t.Fatal(err)
		}
		var answer [1]byte
		if _, err := io.ReadFull(visitor, answer[:]); err != nil || answer[0] != 'S' {
			t.Fatalf("TLS upgrade: %v", err)
		}
	}
	if protocol == "mysql" {
		if _, err := mysqlRead(visitor); err != nil {
			t.Fatal(err)
		}
		ssl := mysqlPacket{seq: 1, data: make([]byte, 32)}
		binary.LittleEndian.PutUint32(ssl.data, auditMySQLFlags)
		ssl.data[8] = 45
		if err := ssl.write(visitor); err != nil {
			t.Fatal(err)
		}
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(clientOptions.Certificate))
	name := "asset.test"
	if web {
		name = "127.0.0.1"
	}
	clientTLS := &tls.Config{RootCAs: roots, ServerName: name, MinVersion: tls.VersionTLS12}
	if web {
		pair, err := tls.X509KeyPair([]byte(clientOptions.ClientCertificate), []byte(clientOptions.ClientKey))
		if err != nil {
			t.Fatal(err)
		}
		clientTLS.Certificates = []tls.Certificate{pair}
	}
	secure := tls.Client(visitor, clientTLS)
	if err := client(secure); err != nil {
		t.Fatal(err)
	}
	visitor.Close()
	if err := <-targetDone; err != nil {
		t.Fatal(err)
	}
	if err := <-proxyDone; err != nil {
		t.Fatal(err)
	}
	if len(options) > 0 && options[0].inspect != nil {
		options[0].inspect(sink)
	}
	var operations []string
	for _, e := range sink.events {
		if e.NormalizedOperation != nil && strings.Contains(*e.NormalizedOperation, "sensitive-value") {
			t.Fatal("operation value was not redacted")
		}
		if e.Phase == "completed" && (e.Result == "success" && e.ActualAccount == "reader" || protocol == "http" && e.Result == "http_200" && e.ActualAccount == "unverified") {
			operations = append(operations, e.OperationType)
		}
	}
	return operations
}

func TestProtocolAuditMySQLWebClient(t *testing.T) {
	auth := make([]byte, 32)
	binary.LittleEndian.PutUint32(auth, auditMySQLFlags)
	auth[8] = 45
	auth = append(auth, []byte("reader\x00\x00mysql_native_password\x00")...)
	query := append([]byte{3}, []byte("SELECT 'sensitive-value'")...)
	operations := auditStream(t, "mysql", func(c net.Conn) error {
		login, err := mysqlRead(c)
		if err != nil || login.seq != 2 || !bytes.Equal(login.data, auth) {
			return fmt.Errorf("MySQL approved identity changed: %v", err)
		}
		if err := (mysqlPacket{seq: 3, data: []byte{0, 0, 0, 2, 0, 0, 0}}).write(c); err != nil {
			return err
		}
		request, err := mysqlRead(c)
		if err != nil || !bytes.Equal(request.data, query) {
			return fmt.Errorf("MySQL query changed: %v", err)
		}
		if err := (mysqlPacket{seq: 1, data: []byte{0, 0, 0, 2, 0, 0, 0}}).write(c); err != nil {
			return err
		}
		_, err = mysqlRead(c)
		return err
	}, func(c net.Conn) error {
		if err := (mysqlPacket{seq: 2, data: auth}).write(c); err != nil {
			return err
		}
		if _, err := mysqlRead(c); err != nil {
			return err
		}
		if err := (mysqlPacket{seq: 0, data: query}).write(c); err != nil {
			return err
		}
		if _, err := mysqlRead(c); err != nil {
			return err
		}
		return (mysqlPacket{seq: 0, data: []byte{1}}).write(c)
	})
	if len(operations) == 0 || operations[0] != "query" {
		t.Fatalf("MySQL operation audit missing: %v", operations)
	}
}

func TestProtocolAuditHTTPWebClient(t *testing.T) {
	operations := auditStream(t, "http", func(c net.Conn) error {
		request, err := http.ReadRequest(bufio.NewReader(c))
		if err != nil {
			return err
		}
		defer request.Body.Close()
		if request.Host != "asset.test:443" || request.URL.RequestURI() != "/health?token=sensitive-value" {
			return fmt.Errorf("HTTP request escaped the approved target")
		}
		_, err = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
		return err
	}, func(c net.Conn) error {
		if _, err := io.WriteString(c, "GET /health?token=sensitive-value HTTP/1.1\r\nHost: unapproved.test\r\nConnection: close\r\n\r\n"); err != nil {
			return err
		}
		response, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil || response.StatusCode != 200 || string(body) != "OK" {
			return fmt.Errorf("HTTP response changed: %v", err)
		}
		return nil
	})
	if strings.Join(operations, ",") != "get" {
		t.Fatalf("HTTP operation audit missing: %v", operations)
	}
}

func TestProtocolAuditRedisTLSAndAccount(t *testing.T) {
	auth := "*3\r\n$4\r\nAUTH\r\n$6\r\nreader\r\n$15\r\nsensitive-value\r\n"
	query := "*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n"
	got := auditStream(t, "redis", func(c net.Conn) error {
		r := bufio.NewReader(c)
		for _, want := range []string{auth, query} {
			frame, err := respFrame(r)
			if err != nil || string(frame) != want {
				return fmt.Errorf("request changed: %v", err)
			}
			if err := writeAll(c, []byte("+OK\r\n")); err != nil {
				return err
			}
		}
		return nil
	}, func(c net.Conn) error {
		r := bufio.NewReader(c)
		for _, frame := range []string{auth, query} {
			if err := writeAll(c, []byte(frame)); err != nil {
				return err
			}
			reply, err := respFrame(r)
			if err != nil || string(reply) != "+OK\r\n" {
				return fmt.Errorf("reply changed: %v", err)
			}
		}
		return nil
	})
	if strings.Join(got, ",") != "get" {
		t.Fatalf("verified Redis command missing: %v", got)
	}
}

func TestProtocolAuditPostgresTLSAndQuery(t *testing.T) {
	got := auditStream(t, "postgresql", func(c net.Conn) error {
		if _, err := pgStartup(c); err != nil {
			return err
		}
		for _, p := range []pgMessage{{'R', []byte{0, 0, 0, 0}}, {'Z', []byte{'I'}}} {
			if err := p.write(c); err != nil {
				return err
			}
		}
		query, err := pgRead(c)
		if err != nil || query.kind != 'Q' || string(query.data) != "SELECT 'sensitive-value'\x00" {
			return fmt.Errorf("query changed: %v", err)
		}
		for _, p := range []pgMessage{{'C', []byte("SELECT 1\x00")}, {'Z', []byte{'I'}}} {
			if err := p.write(c); err != nil {
				return err
			}
		}
		return nil
	}, func(c net.Conn) error {
		startup := append([]byte{0, 0, 0, 0, 0, 3, 0, 0}, []byte("user\x00reader\x00database\x00app\x00\x00")...)
		binary.BigEndian.PutUint32(startup, uint32(len(startup)))
		if err := writeAll(c, startup); err != nil {
			return err
		}
		for range 2 {
			if _, err := pgRead(c); err != nil {
				return err
			}
		}
		if err := (pgMessage{'Q', []byte("SELECT 'sensitive-value'\x00")}).write(c); err != nil {
			return err
		}
		for range 2 {
			if _, err := pgRead(c); err != nil {
				return err
			}
		}
		return nil
	})
	if strings.Join(got, ",") != "query" {
		t.Fatalf("PostgreSQL operation missing: %v", got)
	}
}

func TestProtocolAuditPostgresQueryErrorRecovery(t *testing.T) {
	auth := []pgMessage{{'R', []byte{0, 0, 0, 0}}, {'Z', []byte{'I'}}}
	rounds := []struct {
		query   string
		replies []pgMessage
	}{
		{"SELECT * FROM missing_table;", []pgMessage{{'E', []byte("SERROR\x00C42P01\x00Mrelation does not exist\x00\x00")}, {'Z', []byte{'I'}}}},
		{"SELECT 1; SELECT 2;", []pgMessage{{'C', []byte("SELECT 1\x00")}, {'C', []byte("SELECT 1\x00")}, {'Z', []byte{'I'}}}},
		{"SELECT 3;", []pgMessage{{'C', []byte("SELECT 1\x00")}, {'Z', []byte{'I'}}}},
	}
	for _, web := range []bool{false, true} {
		t.Run(fmt.Sprintf("web=%v", web), func(t *testing.T) {
			auditStreamMode(t, "postgresql", func(c net.Conn) error {
				if _, err := pgStartup(c); err != nil {
					return err
				}
				for _, message := range auth {
					if err := message.write(c); err != nil {
						return err
					}
				}
				for _, round := range rounds {
					query, err := pgRead(c)
					if err != nil || query.kind != 'Q' || string(query.data) != round.query+"\x00" {
						return fmt.Errorf("query after SQL error changed: %v", err)
					}
					for _, reply := range round.replies {
						if err := reply.write(c); err != nil {
							return err
						}
					}
				}
				return nil
			}, func(c net.Conn) error {
				startup := append([]byte{0, 0, 0, 0, 0, 3, 0, 0}, []byte("user\x00reader\x00database\x00app\x00\x00")...)
				binary.BigEndian.PutUint32(startup, uint32(len(startup)))
				if err := writeAll(c, startup); err != nil {
					return err
				}
				for _, want := range auth {
					got, err := pgRead(c)
					if err != nil || got.kind != want.kind || !bytes.Equal(got.data, want.data) {
						return fmt.Errorf("startup response changed: %v", err)
					}
				}
				for _, round := range rounds {
					if err := (pgMessage{'Q', []byte(round.query + "\x00")}).write(c); err != nil {
						return err
					}
					for _, want := range round.replies {
						got, err := pgRead(c)
						if err != nil || got.kind != want.kind || !bytes.Equal(got.data, want.data) {
							return fmt.Errorf("SQL error recovery response changed: %v", err)
						}
					}
				}
				return nil
			}, web, auditStreamOptions{inspect: func(sink *recordingSink) {
				var results []string
				for _, event := range sink.events {
					if event.OperationType == "query" && event.Phase == "completed" {
						results = append(results, event.Result)
					}
				}
				if strings.Join(results, ",") != "failure,success,success" {
					t.Fatalf("query results after recovery = %v", results)
				}
			}})
		})
	}
}

func auditBSONString(name, value string) []byte {
	b := append([]byte{2}, []byte(name+"\x00")...)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(value)+1))
	return append(b, []byte(value+"\x00")...)
}
func auditBSONInt(name string, value uint32) []byte {
	return binary.LittleEndian.AppendUint32(append([]byte{16}, []byte(name+"\x00")...), value)
}
func auditMongoMessage(requestID, responseTo uint32, fields ...[]byte) []byte {
	doc := make([]byte, 4)
	for _, field := range fields {
		doc = append(doc, field...)
	}
	doc = append(doc, 0)
	binary.LittleEndian.PutUint32(doc, uint32(len(doc)))
	wire := make([]byte, 21)
	binary.LittleEndian.PutUint32(wire, uint32(21+len(doc)))
	binary.LittleEndian.PutUint32(wire[4:], requestID)
	binary.LittleEndian.PutUint32(wire[8:], responseTo)
	binary.LittleEndian.PutUint32(wire[12:], 2013)
	return append(wire, doc...)
}

func TestProtocolAuditMongoTLSAndCommand(t *testing.T) {
	payload := append([]byte{5}, []byte("payload\x00")...)
	scram := "n,,n=reader,r=sensitive-value"
	payload = binary.LittleEndian.AppendUint32(payload, uint32(len(scram)))
	payload = append(append(payload, 0), []byte(scram)...)
	commands := [][]byte{
		auditMongoMessage(1, 0, auditBSONInt("saslStart", 1), auditBSONString("mechanism", "SCRAM-SHA-256"), payload, auditBSONString("$db", "admin")),
		auditMongoMessage(2, 0, auditBSONInt("saslContinue", 1), auditBSONString("$db", "admin")),
		auditMongoMessage(3, 0, auditBSONString("find", "orders"), auditBSONString("$db", "app")),
	}
	got := auditStream(t, "mongodb", func(c net.Conn) error {
		for _, cmd := range commands {
			packet, err := mongoRead(c)
			if err != nil || !bytes.Equal(packet.raw, cmd) {
				return fmt.Errorf("Mongo request changed: %v", err)
			}
			if err := writeAll(c, auditMongoMessage(100+packet.requestID, packet.requestID, auditBSONInt("ok", 1), auditBSONInt("done", 1))); err != nil {
				return err
			}
		}
		return nil
	}, func(c net.Conn) error {
		for _, cmd := range commands {
			if err := writeAll(c, cmd); err != nil {
				return err
			}
			if _, err := mongoRead(c); err != nil {
				return err
			}
		}
		return nil
	})
	if strings.Join(got, ",") != "find" {
		t.Fatalf("Mongo verified operation missing: %v", got)
	}
}
