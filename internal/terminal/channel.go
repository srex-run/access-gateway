// Package terminal defines the bounded browser-to-worker terminal protocol.
// Credentials are accepted once, in the first encrypted WebSocket frame; they
// never enter a URL, a saved grant, or an audit event.
package terminal

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const MaxMessage = 64 << 10

type Message struct {
	Type       string `json:"type"`
	Data       string `json:"data,omitempty"`
	Password   string `json:"password,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
	Database   string `json:"database,omitempty"`
	AuthSource string `json:"auth_source,omitempty"`
	Cols       int    `json:"cols,omitempty"`
	Rows       int    `json:"rows,omitempty"`
}

func (m Message) ValidSize() bool {
	return m.Cols >= 2 && m.Cols <= 500 && m.Rows >= 2 && m.Rows <= 300
}

func (m Message) ValidStart() bool {
	return m.Type == "start" && m.ValidSize() && m.Data == "" &&
		((m.PrivateKey == "" && m.Passphrase == "") || (m.Password == "" && m.PrivateKey != "")) &&
		len(m.Password) <= 8192 && len(m.PrivateKey) <= 32768 && len(m.Passphrase) <= 8192 &&
		validDatabase(m.Database) && validDatabase(m.AuthSource) && !strings.ContainsRune(m.Password, 0)
}

// These are connection options only. Neither a target address nor an account
// can be supplied by the browser; both come from the approved session grant.
func (m Message) ValidFor(protocol string) bool {
	if !m.ValidStart() || !Supported(protocol) {
		return false
	}
	if protocol == "ssh" {
		return m.Database == "" && m.AuthSource == "" && (m.Password != "" || m.PrivateKey != "")
	}
	if m.PrivateKey != "" || m.Passphrase != "" || (protocol != "mongodb" && m.AuthSource != "") {
		return false
	}
	if protocol == "http" {
		return m.Database == ""
	}
	if protocol == "redis" && m.Database != "" {
		n, err := strconv.Atoi(m.Database)
		return err == nil && n >= 0 && n <= 2147483647
	}
	return true
}

func Supported(protocol string) bool {
	switch protocol {
	case "ssh", "mysql", "postgresql", "redis", "mongodb", "http":
		return true
	}
	return false
}

func validDatabase(value string) bool {
	if len(value) > 128 {
		return false
	}
	for _, c := range value {
		// Exclude URI/connection-string syntax and control characters. CLI
		// arguments are always separate argv entries, never shell fragments.
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

// KeepAlive must be installed before the single reader starts. Control writes
// are safe alongside the one data writer allowed by gorilla/websocket.
func KeepAlive(ctx context.Context, c *websocket.Conn) {
	c.SetReadLimit(MaxMessage)
	_ = c.SetReadDeadline(time.Now().Add(45 * time.Second))
	c.SetPongHandler(func(string) error { return c.SetReadDeadline(time.Now().Add(45 * time.Second)) })
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if c.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second)) != nil {
					_ = c.Close()
					return
				}
			}
		}
	}()
}

type Channel struct {
	Socket  *websocket.Conn
	Resize  func(rows, cols int) error
	mu      sync.Mutex
	pending []byte
}

type Stream interface {
	io.ReadWriteCloser
	Send(Message) error
	SetResize(func(int, int) error)
}

func (c *Channel) Close() error                          { return c.Socket.Close() }
func (c *Channel) SetResize(resize func(int, int) error) { c.Resize = resize }

func (c *Channel) Send(m Message) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = c.Socket.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return c.Socket.WriteJSON(m)
}

func (c *Channel) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = c.Socket.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := c.Socket.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *Channel) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for len(c.pending) == 0 {
		kind, data, err := c.Socket.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseNoStatusReceived) {
				return 0, io.EOF
			}
			return 0, err
		}
		// xterm's legacy mouse reports contain arbitrary bytes, not UTF-8.
		// Binary frames preserve these bytes exactly; text frames carry the
		// existing input and resize messages after the one-time login.
		if kind == websocket.BinaryMessage {
			if len(data) == 0 || len(data) > 16384 {
				return 0, errors.New("invalid terminal input size")
			}
			c.pending = data
			continue
		}
		var m Message
		if kind != websocket.TextMessage || json.Unmarshal(data, &m) != nil {
			return 0, errors.New("invalid terminal message")
		}
		if m.Password != "" || m.PrivateKey != "" || m.Passphrase != "" || m.Database != "" || m.AuthSource != "" {
			return 0, errors.New("unexpected terminal credentials")
		}
		switch m.Type {
		case "input":
			if len(m.Data) == 0 || len(m.Data) > 16384 {
				return 0, errors.New("invalid terminal input size")
			}
			c.pending = []byte(m.Data)
		case "resize":
			if !m.ValidSize() || m.Data != "" || c.Resize == nil {
				return 0, errors.New("invalid terminal resize")
			}
			if err := c.Resize(m.Rows, m.Cols); err != nil {
				return 0, err
			}
		default:
			return 0, errors.New("invalid terminal message")
		}
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}
