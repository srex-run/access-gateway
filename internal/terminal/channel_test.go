package terminal

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

type terminalTestResponse struct {
	net.Conn
	header http.Header
}

func (w terminalTestResponse) Header() http.Header { return w.header }
func (w terminalTestResponse) WriteHeader(int)     {}
func (w terminalTestResponse) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.Conn, bufio.NewReadWriter(bufio.NewReader(w.Conn), bufio.NewWriter(w.Conn)), nil
}

func terminalTestSocket(t *testing.T, handle func(*Channel)) *websocket.Conn {
	t.Helper()
	// Exercise real WebSocket framing over an in-memory duplex connection;
	// no listening port or external service is required by the protocol test.
	client, server := net.Pipe()
	t.Cleanup(func() { client.Close(); server.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		request, err := http.ReadRequest(bufio.NewReader(server))
		if err != nil {
			t.Error(err)
			return
		}
		upgrader := websocket.Upgrader{}
		socket, err := upgrader.Upgrade(terminalTestResponse{Conn: server, header: make(http.Header)}, request, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer socket.Close()
		socket.SetReadLimit(MaxMessage)
		_ = socket.SetReadDeadline(time.Now().Add(5 * time.Second))
		handle(&Channel{Socket: socket})
	}()
	socket, _, err := websocket.NewClient(client, &url.URL{Scheme: "ws", Host: "terminal.test"}, nil, 1024, 1024)
	if err != nil {
		t.Fatal(err)
	}
	_ = socket.SetReadDeadline(time.Now().Add(5 * time.Second))
	t.Cleanup(func() { socket.Close(); <-done })
	return socket
}

func TestTerminalChannelDistinguishesNormalAndBrokenConnection(t *testing.T) {
	for _, normal := range []bool{true, false} {
		t.Run(fmt.Sprint(normal), func(t *testing.T) {
			result := make(chan error, 1)
			socket := terminalTestSocket(t, func(channel *Channel) {
				_, err := channel.Read(make([]byte, 1))
				result <- err
			})
			if normal {
				if err := socket.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				_, _, _ = socket.ReadMessage()
			} else {
				_ = socket.Close()
			}
			err := <-result
			if (err == io.EOF) != normal || err == nil {
				t.Fatalf("normal=%v: %v", normal, err)
			}
		})
	}
}

func TestChannelPreservesTerminalBytesAndResize(t *testing.T) {
	wantInput := append([]byte("中文\r\x03\x1b[A"), 0x1b, '[', 'M', 0xff, 0x80, 0)
	wantOutput := []byte("\x1b[31m终端输出\x1b[0m\r\n")
	resized := make(chan [2]int, 1)
	socket := terminalTestSocket(t, func(channel *Channel) {
		channel.SetResize(func(rows, cols int) error { resized <- [2]int{rows, cols}; return nil })
		var received []byte
		for len(received) < len(wantInput) {
			buffer := make([]byte, 3)
			n, err := channel.Read(buffer)
			if err != nil {
				t.Error(err)
				return
			}
			received = append(received, buffer[:n]...)
		}
		if !bytes.Equal(received, wantInput) {
			t.Errorf("terminal input changed: %x", received)
		}
		// Split a UTF-8 character between output frames as a real PTY can.
		for _, chunk := range [][]byte{wantOutput[:6], wantOutput[6:]} {
			if _, err := channel.Write(chunk); err != nil {
				t.Error(err)
			}
		}
	})
	for _, message := range []Message{{Type: "resize", Rows: 40, Cols: 120}, {Type: "input", Data: "中文\r\x03\x1b[A"}} {
		if err := socket.WriteJSON(message); err != nil {
			t.Fatal(err)
		}
	}
	if err := socket.WriteMessage(websocket.BinaryMessage, []byte{0x1b, '[', 'M', 0xff, 0x80, 0}); err != nil {
		t.Fatal(err)
	}
	var output []byte
	for len(output) < len(wantOutput) {
		kind, data, err := socket.ReadMessage()
		if err != nil || kind != websocket.BinaryMessage {
			t.Fatalf("terminal output: kind=%d error=%v", kind, err)
		}
		output = append(output, data...)
	}
	if !bytes.Equal(output, wantOutput) {
		t.Fatalf("terminal output changed: %x", output)
	}
	select {
	case size := <-resized:
		if size != [2]int{40, 120} {
			t.Fatalf("resize changed: %v", size)
		}
	default:
		t.Fatal("resize was not delivered before input")
	}
}

func TestChannelRejectsInvalidInput(t *testing.T) {
	for _, test := range []struct {
		name string
		kind int
		data []byte
	}{
		{"empty binary", websocket.BinaryMessage, nil},
		{"oversized binary", websocket.BinaryMessage, bytes.Repeat([]byte{1}, 16385)},
		{"invalid JSON", websocket.TextMessage, []byte("not-json")},
		{"second login", websocket.TextMessage, []byte(`{"type":"input","data":"x","password":"secret"}`)},
		{"invalid resize", websocket.TextMessage, []byte(`{"type":"resize","cols":501,"rows":24}`)},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := make(chan error, 1)
			socket := terminalTestSocket(t, func(channel *Channel) {
				_, err := channel.Read(make([]byte, 16))
				result <- err
			})
			if err := socket.WriteMessage(test.kind, test.data); err != nil {
				t.Fatal(err)
			}
			if err := <-result; err == nil || err == io.EOF {
				t.Fatalf("invalid input not rejected: %v", err)
			}
		})
	}
}

func TestStartOptionsStayWithinProtocol(t *testing.T) {
	for _, protocol := range []string{"ssh", "mysql", "postgresql", "redis", "mongodb", "http"} {
		m := Message{Type: "start", Cols: 100, Rows: 30, Password: "temporary"}
		if !m.ValidFor(protocol) {
			t.Fatalf("valid %s login rejected", protocol)
		}
		m.Password = ""
		if m.ValidFor(protocol) != (protocol != "ssh") {
			t.Fatalf("empty password policy: %s", protocol)
		}
		m.Database = "application"
		if m.ValidFor(protocol) != (protocol == "mysql" || protocol == "postgresql" || protocol == "mongodb") {
			t.Fatalf("database option: %s", protocol)
		}
		m.Database, m.AuthSource = "", "admin"
		if m.ValidFor(protocol) != (protocol == "mongodb") {
			t.Fatalf("authentication database option: %s", protocol)
		}
		m.AuthSource, m.PrivateKey = "", "key"
		if m.ValidFor(protocol) != (protocol == "ssh") {
			t.Fatalf("SSH key allowed for %s", protocol)
		}
	}
	for _, database := range []string{"postgres host=other", "mongodb://remote/db", "db\x00host", "db\nother", "--host=remote", "a/b"} {
		m := Message{Type: "start", Cols: 80, Rows: 24, Database: database}
		if m.ValidFor("postgresql") || m.ValidFor("mongodb") {
			t.Fatalf("connection syntax accepted: %q", database)
		}
	}
	for _, database := range []string{"-1", "1.0", "2147483648"} {
		if (Message{Type: "start", Cols: 80, Rows: 24, Database: database}).ValidFor("redis") {
			t.Fatalf("invalid Redis database: %q", database)
		}
	}
}
