package sessionproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
)

type singleHTTPListener struct {
	conn   net.Conn
	once   sync.Once
	closed chan struct{}
	stop   sync.Once
}

func (l *singleHTTPListener) Accept() (net.Conn, error) {
	var conn net.Conn
	l.once.Do(func() { conn = &httpCloseConn{Conn: l.conn, close: l.Close} })
	if conn != nil {
		return conn, nil
	}
	<-l.closed
	return nil, net.ErrClosed
}
func (l *singleHTTPListener) Close() error   { l.stop.Do(func() { close(l.closed) }); return nil }
func (l *singleHTTPListener) Addr() net.Addr { return l.conn.LocalAddr() }

type httpCloseConn struct {
	net.Conn
	close func() error
}

func (c *httpCloseConn) Close() error { c.close(); return c.Conn.Close() }

// HTTP/2 frontend streams share one fixed HTTP/1.1 asset connection. Transport
// may never redial: a new socket requires its own acknowledged connection proof.
func serveHTTP(client, backend net.Conn, r *recorder) error {
	var used atomic.Bool
	transport := &http.Transport{MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1, MaxResponseHeaderBytes: 64 << 10, ResponseHeaderTimeout: time.Minute, ExpectContinueTimeout: time.Second,
		DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
			if used.Swap(true) {
				return nil, ErrProtocol
			}
			return backend, nil
		},
	}
	defer transport.CloseIdleConnections()
	var failureMu sync.Mutex
	var failure error
	fail := func(e error) {
		failureMu.Lock()
		if failure == nil {
			failure = e
		}
		failureMu.Unlock()
		client.Close()
		backend.Close()
	}
	targetHost := net.JoinHostPort(r.binding.TargetHost, fmt.Sprint(r.binding.TargetPort))
	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodConnect || req.Header.Get("Upgrade") != "" {
			http.Error(w, "unsupported audited HTTP protocol", http.StatusNotImplemented)
			return
		}
		if len(req.Method) > 32 {
			fail(ErrProtocol)
			return
		}
		for _, ch := range req.Method {
			if ch < 'A' || ch > 'Z' {
				fail(ErrProtocol)
				return
			}
		}
		// Headers and bodies are relayed but cannot prove the asset's identity.
		path := clean(req.URL.EscapedPath(), 3000)
		if path == "" {
			path = "/"
		}
		op, e := r.begin("unverified", strings.ToLower(req.Method), req.Method+" "+path, "", map[string]any{"http_version": req.Proto})
		if e != nil {
			fail(e)
			return
		}
		out := req.Clone(req.Context())
		out.URL = &url.URL{Scheme: "https", Host: targetHost, Path: req.URL.Path, RawPath: req.URL.RawPath, RawQuery: req.URL.RawQuery}
		out.Host = targetHost
		out.RequestURI = ""
		stripHTTPHopHeaders(out.Header)
		resp, e := transport.RoundTrip(out)
		if e != nil {
			fail(e)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode == 101 {
			if e = op.end("rejected"); e != nil {
				fail(e)
				return
			}
			http.Error(w, "unsupported audited HTTP upgrade", http.StatusNotImplemented)
			return
		}
		stripHTTPHopHeaders(resp.Header)
		for key, values := range resp.Header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		for key := range resp.Trailer {
			w.Header().Add("Trailer", key)
		}
		w.WriteHeader(resp.StatusCode)
		if _, e = io.Copy(httpStreamWriter{writer: w}, resp.Body); e != nil {
			fail(e)
			return
		}
		for key, values := range resp.Trailer {
			w.Header()[key] = values
		}
		if e = op.end(fmt.Sprintf("http_%d", resp.StatusCode)); e != nil {
			fail(e)
		}
	})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 30 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 64 << 10, ErrorLog: log.New(io.Discard, "", 0), BaseContext: func(net.Listener) context.Context { return r.ctx }}
	if c, ok := client.(*tls.Conn); ok && c.ConnectionState().NegotiatedProtocol == "h2" {
		h2 := &http2.Server{MaxConcurrentStreams: 16, MaxReadFrameSize: 1 << 20, IdleTimeout: time.Minute}
		h2.ServeConn(client, &http2.ServeConnOpts{Context: r.ctx, BaseConfig: server, Handler: handler})
	} else {
		listener := &singleHTTPListener{conn: client, closed: make(chan struct{})}
		err := server.Serve(listener)
		if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
			fail(err)
		}
	}
	failureMu.Lock()
	defer failureMu.Unlock()
	return failure
}

type httpStreamWriter struct{ writer http.ResponseWriter }

func (w httpStreamWriter) Write(p []byte) (int, error) {
	n, err := w.writer.Write(p)
	if err == nil {
		err = http.NewResponseController(w.writer).Flush()
	}
	return n, err
}

func stripHTTPHopHeaders(h http.Header) {
	for _, value := range h.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			h.Del(strings.TrimSpace(name))
		}
	}
	for _, name := range []string{"Connection", "Proxy-Connection", "Proxy-Authenticate", "Proxy-Authorization", "Keep-Alive", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
		h.Del(name)
	}
}
