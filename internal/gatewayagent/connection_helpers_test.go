package gatewayagent

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// In-memory TCP-shaped transport exercises the real controller, listener
// lifecycle and TLS stack without binding host ports.
type pipeListener struct {
	queue chan net.Conn
	done  chan struct{}
	once  sync.Once
	port  int
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.queue:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *pipeListener) Close() error { l.once.Do(func() { close(l.done) }); return nil }
func (l *pipeListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: l.port}
}
func (l *pipeListener) connect(ctx context.Context) (net.Conn, error) {
	a, b := net.Pipe()
	select {
	case l.queue <- tcpPipe{b}:
		return a, nil
	case <-l.done:
		a.Close()
		b.Close()
		return nil, net.ErrClosed
	case <-ctx.Done():
		a.Close()
		b.Close()
		return nil, ctx.Err()
	}
}

type tcpPipe struct{ net.Conn }

func (c tcpPipe) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 43000}
}
func (c tcpPipe) LocalAddr() net.Addr { return &net.TCPAddr{IP: net.ParseIP("10.0.0.2"), Port: 43001} }

func pipeController(t *testing.T) (*DirectController, *pipeListener, *atomic.Int32, *recordingEventSink) {
	t.Helper()
	sink := &recordingEventSink{}
	c := newControllerForAddress(t, "10.0.0.10:3306", 20000, sink, &recordingExposure{})
	l := &pipeListener{queue: make(chan net.Conn), done: make(chan struct{}), port: 20000}
	c.listen = func(context.Context, string, string) (net.Listener, error) { return l, nil }
	count := &atomic.Int32{}
	c.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "10.0.0.10:3306" {
			t.Errorf("unexpected target: %s", address)
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		count.Add(1)
		a, b := net.Pipe()
		go func() { defer b.Close(); _, _ = io.Copy(b, b) }()
		return tcpPipe{a}, nil
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := c.Shutdown(ctx); err != nil {
			t.Error(err)
		}
	})
	return c, l, count, sink
}
