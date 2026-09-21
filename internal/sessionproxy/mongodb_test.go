package sessionproxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
)

func mongoTestDocument(fields ...[]byte) []byte {
	doc := make([]byte, 4)
	for _, field := range fields {
		doc = append(doc, field...)
	}
	doc = append(doc, 0)
	binary.LittleEndian.PutUint32(doc, uint32(len(doc)))
	return doc
}

func mongoTestNested(kind byte, name string, fields ...[]byte) []byte {
	return append(append([]byte{kind}, []byte(name+"\x00")...), mongoTestDocument(fields...)...)
}

func mongoTestBinary(name, value string) []byte {
	field := append([]byte{5}, []byte(name+"\x00")...)
	field = binary.LittleEndian.AppendUint32(field, uint32(len(value)))
	return append(append(field, 0), []byte(value)...)
}

func mongoTestLegacy(requestID, responseTo uint32, reply bool, fields ...[]byte) []byte {
	packet := make([]byte, 16)
	binary.LittleEndian.PutUint32(packet[4:], requestID)
	binary.LittleEndian.PutUint32(packet[8:], responseTo)
	if reply {
		binary.LittleEndian.PutUint32(packet[12:], 1) // OP_REPLY
		packet = append(packet, make([]byte, 20)...)
		binary.LittleEndian.PutUint32(packet[32:], 1)
	} else {
		binary.LittleEndian.PutUint32(packet[12:], 2004) // OP_QUERY
		packet = append(packet, make([]byte, 4)...)
		packet = append(packet, []byte("admin.$cmd\x00")...)
		packet = binary.LittleEndian.AppendUint32(packet, 0)
		packet = binary.LittleEndian.AppendUint32(packet, 1)
	}
	packet = append(packet, mongoTestDocument(fields...)...)
	binary.LittleEndian.PutUint32(packet, uint32(len(packet)))
	return packet
}

func TestProtocolAuditMongoNativeHandshake(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprintf("legacy=%v", legacy), func(t *testing.T) {
			command := "hello"
			if legacy {
				command = "ismaster"
			}
			// Node's MongoDB driver advertises ["none"] by default and folds
			// the first SCRAM message into the initial hello/isMaster request.
			fields := [][]byte{
				auditBSONInt(command, 1),
				mongoTestNested(4, "compression", auditBSONString("0", "none")),
				auditBSONString("saslSupportedMechs", "admin.reader"),
				mongoTestNested(3, "speculativeAuthenticate", auditBSONInt("saslStart", 1), auditBSONString("mechanism", "SCRAM-SHA-256"), mongoTestBinary("payload", "n,,n=reader,r=sensitive-value"), auditBSONString("db", "admin")),
			}
			hello := auditMongoMessage(1, 0, fields...)
			helloReply := auditMongoMessage(101, 1, auditBSONInt("ok", 1), mongoTestNested(4, "compression"), mongoTestNested(3, "speculativeAuthenticate", auditBSONInt("ok", 1), auditBSONInt("done", 0), mongoTestBinary("payload", "r=sensitive-value,s=salt,i=4096")))
			if legacy {
				hello = mongoTestLegacy(1, 0, false, fields...)
				helloReply = mongoTestLegacy(101, 1, true, auditBSONInt("ok", 1), mongoTestNested(4, "compression"), mongoTestNested(3, "speculativeAuthenticate", auditBSONInt("ok", 1), auditBSONInt("done", 0)))
			}
			requests := [][]byte{
				hello,
				auditMongoMessage(2, 0, auditBSONInt("saslContinue", 1), mongoTestBinary("payload", "c=biws,r=sensitive-value,p=sensitive-value"), auditBSONString("$db", "admin")),
				auditMongoMessage(3, 0, auditBSONString("find", "test"), auditBSONString("$db", "test")),
			}
			replies := [][]byte{
				helloReply,
				auditMongoMessage(102, 2, auditBSONInt("ok", 1), auditBSONInt("done", 1)),
				auditMongoMessage(103, 3, auditBSONInt("ok", 1)),
			}
			operations := auditStream(t, "mongodb", func(conn net.Conn) error {
				for index, want := range requests {
					packet, err := mongoRead(conn)
					if err != nil || !bytes.Equal(packet.raw, want) {
						return fmt.Errorf("native MongoDB request %d changed: %v", index, err)
					}
					if err = writeAll(conn, replies[index]); err != nil {
						return err
					}
				}
				return nil
			}, func(conn net.Conn) error {
				for index, request := range requests {
					if err := writeAll(conn, request); err != nil {
						return err
					}
					packet, err := mongoRead(conn)
					if err != nil || !bytes.Equal(packet.raw, replies[index]) {
						return fmt.Errorf("native MongoDB response %d changed: %v", index, err)
					}
				}
				return nil
			})
			if strings.Join(operations, ",") != "find" {
				t.Fatalf("verified MongoDB operation after speculative authentication missing: %v", operations)
			}
		})
	}
}

type mongoMemoryConn struct {
	net.Conn
	input  *bytes.Reader
	output bytes.Buffer
}

func (c *mongoMemoryConn) Read(data []byte) (int, error)  { return c.input.Read(data) }
func (c *mongoMemoryConn) Write(data []byte) (int, error) { return c.output.Write(data) }

func TestMongoHandshakeCompressionAndIdentity(t *testing.T) {
	for _, name := range []string{"omitted", "empty", "none", "snappy", "zlib", "zstd", "mixed", "invalid-array-item", "invalid-field-type", "wrong-account", "auth-not-complete"} {
		t.Run(name, func(t *testing.T) {
			compression := mongoTestNested(4, "compression", auditBSONString("0", "none"))
			want := error(io.EOF)
			account := "reader"
			switch name {
			case "omitted":
				compression = nil
			case "empty":
				compression = mongoTestNested(4, "compression")
			case "snappy", "zlib", "zstd":
				compression = mongoTestNested(4, "compression", auditBSONString("0", name))
				want = ErrProtocol
			case "mixed":
				compression = mongoTestNested(4, "compression", auditBSONString("0", "none"), auditBSONString("1", "zlib"))
				want = ErrProtocol
			case "invalid-array-item":
				compression = mongoTestNested(4, "compression", auditBSONInt("0", 1))
				want = ErrProtocol
			case "invalid-field-type":
				compression = auditBSONString("compression", "none")
				want = ErrProtocol
			case "wrong-account":
				account, want = "other", ErrIdentity
			case "auth-not-complete":
				want = ErrIdentity
			}
			request := auditMongoMessage(1, 0, auditBSONInt("hello", 1), compression, mongoTestNested(3, "speculativeAuthenticate", auditBSONInt("saslStart", 1), auditBSONString("mechanism", "SCRAM-SHA-256"), mongoTestBinary("payload", "n,,n="+account+",r=sensitive-value")))
			input := bytes.Clone(request)
			if name == "auth-not-complete" {
				input = append(input, auditMongoMessage(2, 0, auditBSONString("find", "test"), auditBSONString("$db", "test"))...)
			}
			client := &mongoMemoryConn{input: bytes.NewReader(input)}
			backend := &mongoMemoryConn{input: bytes.NewReader(auditMongoMessage(101, 1, auditBSONInt("ok", 1)))}
			err := serveMongo(client, backend, &recorder{ctx: context.Background(), binding: Binding{Account: "reader"}, protocol: "mongodb", sink: &recordingSink{}})
			if !errors.Is(err, want) {
				t.Fatalf("MongoDB handshake = %v, want %v", err, want)
			}
			if want == io.EOF || name == "auth-not-complete" {
				if !bytes.Equal(backend.output.Bytes(), request) {
					t.Fatal("handshake changed or unauthenticated command reached the target")
				}
			} else if backend.output.Len() != 0 {
				t.Fatal("rejected MongoDB handshake reached the target")
			}
		})
	}
}
