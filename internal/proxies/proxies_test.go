package proxies

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/canonical/aproxy/internal/version"
)

const (
	testTimeout      = 10 * time.Second
	connectEstablish = "HTTP/1.1 200 Connection established\r\n\r\n"
)

var (
	errDialFailed = errors.New("dial failed")
	errBoom       = errors.New("boom")
)

type testAddr string

func (a testAddr) Network() string { return "tcp" }
func (a testAddr) String() string  { return string(a) }

type failingDialer struct {
	err error
}

func (d failingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return nil, d.err
}

type recordingConn struct {
	net.Conn
	closes int
}

func (c *recordingConn) Close() error {
	c.closes++
	return c.Conn.Close()
}

type recordingDialer struct {
	conn *recordingConn
}

func (d *recordingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.conn, nil
}

type fixedDialer struct {
	conn net.Conn
}

func (d *fixedDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.conn, nil
}

type deadlineRecorder struct {
	readDeadlines  int
	writeDeadlines int
	deadlines      int
	lastDeadline   time.Time
}

func (c *deadlineRecorder) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	b[0] = 'x'
	return 1, nil
}

func (c *deadlineRecorder) Write(b []byte) (int, error) { return len(b), nil }
func (c *deadlineRecorder) Close() error                { return nil }
func (c *deadlineRecorder) LocalAddr() net.Addr         { return testAddr("local") }
func (c *deadlineRecorder) RemoteAddr() net.Addr        { return testAddr("remote") }

func (c *deadlineRecorder) SetDeadline(t time.Time) error {
	c.deadlines++
	c.lastDeadline = t
	return nil
}

func (c *deadlineRecorder) SetReadDeadline(t time.Time) error {
	c.readDeadlines++
	return nil
}

func (c *deadlineRecorder) SetWriteDeadline(t time.Time) error {
	c.writeDeadlines++
	return nil
}

type writeErrConn struct {
	deadlineRecorder
}

func (c *writeErrConn) Write(b []byte) (int, error) { return 0, errBoom }

type errWriter struct {
	err error
}

func (w errWriter) Write(p []byte) (int, error) { return 0, w.err }

type shortWriter struct {
	limit   int
	written []byte
}

func (w *shortWriter) Write(p []byte) (int, error) {
	n := len(p)
	if w.limit > 0 && n > w.limit {
		n = w.limit
	}
	w.written = append(w.written, p[:n]...)
	return n, nil
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

type stubProxy struct {
	addr     string
	mu       sync.Mutex
	received bytes.Buffer
	done     chan struct{}
}

func (s *stubProxy) request() string {
	<-s.done
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.received.String()
}

func (s *stubProxy) requestLine() string {
	line, _, _ := strings.Cut(s.request(), "\r\n")
	return line
}

func (s *stubProxy) header(name string) []string {
	head, _, _ := strings.Cut(s.request(), "\r\n\r\n")
	var values []string
	for _, line := range strings.Split(head, "\r\n")[1:] {
		key, value, found := strings.Cut(line, ": ")
		if found && strings.EqualFold(key, name) {
			values = append(values, value)
		}
	}
	return values
}

func newStubProxy(t *testing.T, response string, trailing []byte) *stubProxy {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })
	s := &stubProxy{addr: listener.Addr().String(), done: make(chan struct{})}
	go func() {
		defer close(s.done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if response != "" {
			_, _ = conn.Write([]byte(response))
		}
		if len(trailing) > 0 {
			_, _ = conn.Write(trailing)
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				s.mu.Lock()
				s.received.Write(buf[:n])
				s.mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	return s
}

func newSilentProxy(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				time.Sleep(5 * time.Second)
			}()
		}
	}()
	return listener.Addr().String()
}

func tcpPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	client, err = net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	select {
	case server = <-accepted:
	case <-time.After(testTimeout):
		t.Fatalf("accept timed out")
	}
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	return client, server
}

func clientRequest(t *testing.T, raw string) net.Conn {
	t.Helper()
	client, server := net.Pipe()
	go func() {
		defer client.Close()
		_, _ = client.Write([]byte(raw))
	}()
	t.Cleanup(func() { server.Close() })
	return server
}

func proxyHTTP(t *testing.T, p *HTTPProxy, dest string, raw string) *stubProxy {
	t.Helper()
	s := newStubProxy(t, "", nil)
	p.proxyAddr = s.addr
	if p.dialer == nil {
		p.dialer = &net.Dialer{}
	}
	pc, err := p.ProxyHTTP(context.Background(), testAddr(dest), clientRequest(t, raw))
	if err != nil {
		t.Fatalf("ProxyHTTP: %v", err)
	}
	pc.Close()
	return s
}

func TestNewProxyFromURLScheme(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		wantAddr string
		wantTLS  bool
	}{
		{"http default port", "http://proxy.example", "proxy.example:80", false},
		{"http explicit port", "http://proxy.example:3128", "proxy.example:3128", false},
		{"https default port", "https://proxy.example", "proxy.example:443", true},
		{"https explicit port", "https://proxy.example:8443", "proxy.example:8443", true},
		{"ip address", "http://192.0.2.1:3128", "192.0.2.1:3128", false},
		{"ipv6 address", "http://[2001:db8::1]:3128", "[2001:db8::1]:3128", false},
		{"ipv6 default port", "http://[2001:db8::1]", "[2001:db8::1]:80", false},
		{"with path", "http://proxy.example:3128/ignored", "proxy.example:3128", false},
		{"with credentials", "http://user:pass@proxy.example", "proxy.example:80", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := NewProxyFromURL(tc.url, Options{})
			if err != nil {
				t.Fatalf("NewProxyFromURL: %v", err)
			}
			hp, ok := p.(*HTTPProxy)
			if !ok {
				t.Fatalf("got %T, want *HTTPProxy", p)
			}
			if hp.proxyAddr != tc.wantAddr {
				t.Errorf("proxyAddr = %q, want %q", hp.proxyAddr, tc.wantAddr)
			}
			_, isTLS := hp.dialer.(*tls.Dialer)
			if isTLS != tc.wantTLS {
				t.Errorf("tls dialer = %v, want %v", isTLS, tc.wantTLS)
			}
		})
	}
}

func TestNewProxyFromURLCredentials(t *testing.T) {
	tests := []struct {
		name         string
		url          string
		wantUser     string
		wantPassword string
	}{
		{"no credentials", "http://proxy.example", "", ""},
		{"user and password", "http://user:pass@proxy.example", "user", "pass"},
		{"user only", "http://user@proxy.example", "user", ""},
		{"empty password", "http://user:@proxy.example", "user", ""},
		{"percent encoded", "http://us%40er:p%3Ass@proxy.example", "us@er", "p:ss"},
		{"password with colon", "http://user:pa:ss@proxy.example", "user", "pa:ss"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := NewProxyFromURL(tc.url, Options{})
			if err != nil {
				t.Fatalf("NewProxyFromURL: %v", err)
			}
			hp := p.(*HTTPProxy)
			if hp.username != tc.wantUser {
				t.Errorf("username = %q, want %q", hp.username, tc.wantUser)
			}
			if hp.password != tc.wantPassword {
				t.Errorf("password = %q, want %q", hp.password, tc.wantPassword)
			}
		})
	}
}

func TestNewProxyFromURLInvalid(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{"empty", ""},
		{"no host http", "http://"},
		{"no host https", "https://"},
		{"port only", "http://:3128"},
		{"unsupported scheme", "socks5://proxy.example:1080"},
		{"ftp scheme", "ftp://proxy.example"},
		{"no scheme", "proxy.example:3128"},
		{"scheme relative", "//proxy.example:3128"},
		{"control character", "http://proxy.example\x7f"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := NewProxyFromURL(tc.url, Options{})
			if err == nil {
				t.Fatalf("NewProxyFromURL(%q) = %v, want error", tc.url, p)
			}
			if p != nil {
				t.Errorf("got proxy %v alongside error", p)
			}
		})
	}
}

func TestNewProxyFromURLOptions(t *testing.T) {
	t.Run("timeout copied", func(t *testing.T) {
		for _, scheme := range []string{"http", "https"} {
			p, err := NewProxyFromURL(scheme+"://proxy.example", Options{Timeout: 7 * time.Second})
			if err != nil {
				t.Fatalf("NewProxyFromURL: %v", err)
			}
			if got := p.(*HTTPProxy).timeout; got != 7*time.Second {
				t.Errorf("%s timeout = %v, want 7s", scheme, got)
			}
		}
	})

	t.Run("custom dialer used", func(t *testing.T) {
		dialer := &net.Dialer{Timeout: 3 * time.Second}
		p, err := NewProxyFromURL("http://proxy.example", Options{Dialer: dialer})
		if err != nil {
			t.Fatalf("NewProxyFromURL: %v", err)
		}
		if p.(*HTTPProxy).dialer != dialer {
			t.Errorf("dialer not propagated")
		}
	})

	t.Run("custom dialer wrapped for https", func(t *testing.T) {
		dialer := &net.Dialer{Timeout: 3 * time.Second}
		p, err := NewProxyFromURL("https://proxy.example", Options{Dialer: dialer})
		if err != nil {
			t.Fatalf("NewProxyFromURL: %v", err)
		}
		tlsDialer, ok := p.(*HTTPProxy).dialer.(*tls.Dialer)
		if !ok {
			t.Fatalf("dialer = %T, want *tls.Dialer", p.(*HTTPProxy).dialer)
		}
		if tlsDialer.NetDialer != dialer {
			t.Errorf("net dialer not propagated")
		}
	})

	t.Run("default dialer when unset", func(t *testing.T) {
		p, err := NewProxyFromURL("http://proxy.example", Options{})
		if err != nil {
			t.Fatalf("NewProxyFromURL: %v", err)
		}
		if p.(*HTTPProxy).dialer == nil {
			t.Errorf("dialer is nil")
		}
	})
}

func TestProxyAuthorization(t *testing.T) {
	tests := []struct {
		name     string
		username string
		password string
		want     string
	}{
		{"no credentials", "", "", ""},
		{"password without user", "", "pass", ""},
		{"user and password", "user", "pass", "Basic dXNlcjpwYXNz"},
		{"user without password", "user", "", "Basic dXNlcjo="},
		{"password with colon", "user", "pa:ss", "Basic dXNlcjpwYTpzcw=="},
		{"non ascii", "üser", "pass", "Basic w7xzZXI6cGFzcw=="},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &HTTPProxy{username: tc.username, password: tc.password}
			if got := p.proxyAuthorization(); got != tc.want {
				t.Errorf("proxyAuthorization() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestProxyConnectRequest(t *testing.T) {
	s := newStubProxy(t, connectEstablish, nil)
	p := &HTTPProxy{proxyAddr: s.addr, dialer: &net.Dialer{}, username: "user", password: "pass"}
	conn, err := p.Proxy(context.Background(), testAddr("example.com:443"))
	if err != nil {
		t.Fatalf("Proxy: %v", err)
	}
	conn.Close()

	if got, want := s.requestLine(), "CONNECT example.com:443 HTTP/1.1"; got != want {
		t.Errorf("request line = %q, want %q", got, want)
	}
	if got, want := s.header("Host"), []string{"example.com:443"}; !equalStrings(got, want) {
		t.Errorf("Host = %v, want %v", got, want)
	}
	if got, want := s.header("User-Agent"), []string{"aproxy/" + version.Version}; !equalStrings(got, want) {
		t.Errorf("User-Agent = %v, want %v", got, want)
	}
	if got, want := s.header("Proxy-Authorization"), []string{"Basic dXNlcjpwYXNz"}; !equalStrings(got, want) {
		t.Errorf("Proxy-Authorization = %v, want %v", got, want)
	}
	if got := s.header("Authorization"); len(got) != 0 {
		t.Errorf("Authorization = %v, want none", got)
	}
}

func TestProxyConnectNoCredentials(t *testing.T) {
	s := newStubProxy(t, connectEstablish, nil)
	p := &HTTPProxy{proxyAddr: s.addr, dialer: &net.Dialer{}}
	conn, err := p.Proxy(context.Background(), testAddr("example.com:443"))
	if err != nil {
		t.Fatalf("Proxy: %v", err)
	}
	conn.Close()
	if got := s.header("Proxy-Authorization"); len(got) != 0 {
		t.Errorf("Proxy-Authorization = %v, want none", got)
	}
}

func TestProxyConnectHostForms(t *testing.T) {
	tests := []string{
		"example.com:443",
		"192.0.2.1:443",
		"[2001:db8::1]:443",
		"example.com:8080",
	}
	for _, dest := range tests {
		t.Run(dest, func(t *testing.T) {
			s := newStubProxy(t, connectEstablish, nil)
			p := &HTTPProxy{proxyAddr: s.addr, dialer: &net.Dialer{}}
			conn, err := p.Proxy(context.Background(), testAddr(dest))
			if err != nil {
				t.Fatalf("Proxy: %v", err)
			}
			conn.Close()
			if got, want := s.requestLine(), "CONNECT "+dest+" HTTP/1.1"; got != want {
				t.Errorf("request line = %q, want %q", got, want)
			}
		})
	}
}

func TestProxyPrereadReplay(t *testing.T) {
	tests := []struct {
		name     string
		trailing []byte
	}{
		{"no trailing data", nil},
		{"short", []byte("hello")},
		{"binary", []byte{0x16, 0x03, 0x01, 0x00, 0x00, 0xff}},
		{"spans buffer", bytes.Repeat([]byte("abcdefgh"), 2048)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newStubProxy(t, connectEstablish, tc.trailing)
			p := &HTTPProxy{proxyAddr: s.addr, dialer: &net.Dialer{}}
			conn, err := p.Proxy(context.Background(), testAddr("example.com:443"))
			if err != nil {
				t.Fatalf("Proxy: %v", err)
			}
			defer conn.Close()
			if len(tc.trailing) == 0 {
				return
			}
			if err := conn.SetReadDeadline(time.Now().Add(testTimeout)); err != nil {
				t.Fatalf("set deadline: %v", err)
			}
			got := make([]byte, len(tc.trailing))
			if _, err := io.ReadFull(conn, got); err != nil {
				t.Fatalf("read tunnel: %v", err)
			}
			if !bytes.Equal(got, tc.trailing) {
				t.Errorf("tunnel data mismatch: got %d bytes, want %d", len(got), len(tc.trailing))
			}
		})
	}
}

func TestProxyResponseAccepted(t *testing.T) {
	tests := []struct {
		name     string
		response string
	}{
		{"connection established", connectEstablish},
		{"plain ok", "HTTP/1.1 200 OK\r\n\r\n"},
		{"http 1.0", "HTTP/1.0 200 Connection established\r\n\r\n"},
		{"zero content length", "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"},
		{"extra headers", "HTTP/1.1 200 OK\r\nVia: 1.1 proxy\r\nX-Trace: abc\r\n\r\n"},
		{"no reason phrase", "HTTP/1.1 200 \r\n\r\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newStubProxy(t, tc.response, nil)
			p := &HTTPProxy{proxyAddr: s.addr, dialer: &net.Dialer{}}
			conn, err := p.Proxy(context.Background(), testAddr("example.com:443"))
			if err != nil {
				t.Fatalf("Proxy: %v", err)
			}
			conn.Close()
		})
	}
}

func TestProxyResponseRejected(t *testing.T) {
	tests := []struct {
		name     string
		response string
		wantErr  string
	}{
		{"forbidden", "HTTP/1.1 403 Forbidden\r\n\r\n", "returned 403"},
		{"auth required", "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"x\"\r\n\r\n", "returned 407"},
		{"bad gateway", "HTTP/1.1 502 Bad Gateway\r\n\r\n", "returned 502"},
		{"moved", "HTTP/1.1 301 Moved\r\nLocation: http://x\r\n\r\n", "returned 301"},
		{"continue", "HTTP/1.1 100 Continue\r\n\r\n", "returned 100"},
		{"with content length", "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n", "content length 5"},
		{"malformed status line", "NOT HTTP AT ALL\r\n\r\n", "failed to read CONNECT response"},
		{"bad status code", "HTTP/1.1 abc OK\r\n\r\n", "failed to read CONNECT response"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newStubProxy(t, tc.response, nil)
			p := &HTTPProxy{proxyAddr: s.addr, dialer: &net.Dialer{}}
			conn, err := p.Proxy(context.Background(), testAddr("example.com:443"))
			if err == nil {
				conn.Close()
				t.Fatalf("Proxy succeeded, want error")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %v, want it to contain %q", err, tc.wantErr)
			}
			if conn != nil {
				t.Errorf("got non-nil conn alongside error")
			}
		})
	}
}

func TestProxyTruncatedResponse(t *testing.T) {
	tests := []struct {
		name     string
		response string
	}{
		{"empty", ""},
		{"status line only", "HTTP/1.1 200 OK\r\n"},
		{"partial status line", "HTTP/1.1 20"},
		{"headers not terminated", "HTTP/1.1 200 OK\r\nVia: 1.1 proxy\r\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer listener.Close()
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				if tc.response != "" {
					_, _ = conn.Write([]byte(tc.response))
				}
				conn.Close()
			}()
			p := &HTTPProxy{proxyAddr: listener.Addr().String(), dialer: &net.Dialer{}}
			conn, err := p.Proxy(context.Background(), testAddr("example.com:443"))
			if err == nil {
				conn.Close()
				t.Fatalf("Proxy succeeded, want error")
			}
			if !strings.Contains(err.Error(), "failed to read CONNECT response header") {
				t.Errorf("error = %v, want a header read failure", err)
			}
		})
	}
}

func TestProxyDialFailure(t *testing.T) {
	p := &HTTPProxy{proxyAddr: "proxy.example:3128", dialer: failingDialer{err: errDialFailed}}
	conn, err := p.Proxy(context.Background(), testAddr("example.com:443"))
	if err == nil {
		conn.Close()
		t.Fatalf("Proxy succeeded, want error")
	}
	if !errors.Is(err, errDialFailed) {
		t.Errorf("error = %v, want it to wrap errDialFailed", err)
	}
	if !strings.Contains(err.Error(), "proxy.example:3128") {
		t.Errorf("error = %v, want it to name the proxy address", err)
	}
}

func TestProxyClosesConnOnError(t *testing.T) {
	client, server := tcpPair(t)
	go func() {
		_, _ = server.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
	}()
	rec := &recordingConn{Conn: client}
	p := &HTTPProxy{proxyAddr: "unused", dialer: &recordingDialer{conn: rec}}
	if _, err := p.Proxy(context.Background(), testAddr("example.com:443")); err == nil {
		t.Fatalf("Proxy succeeded, want error")
	}
	if rec.closes != 1 {
		t.Errorf("closes = %d, want 1", rec.closes)
	}
}

func TestProxyKeepsConnOnSuccess(t *testing.T) {
	client, server := tcpPair(t)
	go func() {
		_, _ = server.Write([]byte(connectEstablish))
	}()
	rec := &recordingConn{Conn: client}
	p := &HTTPProxy{proxyAddr: "unused", dialer: &recordingDialer{conn: rec}}
	conn, err := p.Proxy(context.Background(), testAddr("example.com:443"))
	if err != nil {
		t.Fatalf("Proxy: %v", err)
	}
	if rec.closes != 0 {
		t.Errorf("closes = %d, want 0", rec.closes)
	}
	conn.Close()
}

func TestProxyTimeoutEnforced(t *testing.T) {
	p := &HTTPProxy{proxyAddr: newSilentProxy(t), dialer: &net.Dialer{}, timeout: 200 * time.Millisecond}
	start := time.Now()
	conn, err := p.Proxy(context.Background(), testAddr("example.com:443"))
	elapsed := time.Since(start)
	if err == nil {
		conn.Close()
		t.Fatalf("Proxy succeeded, want timeout")
	}
	if elapsed > 2*time.Second {
		t.Errorf("took %v, want the timeout to fire promptly", elapsed)
	}
}

func TestProxyNoTimeoutWithoutOption(t *testing.T) {
	s := newStubProxy(t, connectEstablish, []byte("x"))
	p := &HTTPProxy{proxyAddr: s.addr, dialer: &net.Dialer{}}
	conn, err := p.Proxy(context.Background(), testAddr("example.com:443"))
	if err != nil {
		t.Fatalf("Proxy: %v", err)
	}
	defer conn.Close()
	if err := conn.SetReadDeadline(time.Now().Add(testTimeout)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read tunnel: %v", err)
	}
}

func TestProxyClearsDeadlineOnReturnedConn(t *testing.T) {
	timeout := 200 * time.Millisecond
	s := newStubProxy(t, connectEstablish, nil)
	p := &HTTPProxy{proxyAddr: s.addr, dialer: &net.Dialer{}, timeout: timeout}
	conn, err := p.Proxy(context.Background(), testAddr("example.com:443"))
	if err != nil {
		t.Fatalf("Proxy: %v", err)
	}
	defer conn.Close()
	time.Sleep(2 * timeout)
	if _, err := conn.Write([]byte("tunnelled")); err != nil {
		t.Errorf("write after the timeout window: %v", err)
	}
}

func TestProxyContextCancelled(t *testing.T) {
	tests := []struct {
		name    string
		ctx     func() (context.Context, context.CancelFunc)
		wantErr error
	}{
		{
			name: "cancel",
			ctx: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				time.AfterFunc(150*time.Millisecond, cancel)
				return ctx, func() {}
			},
			wantErr: context.Canceled,
		},
		{
			name: "deadline",
			ctx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 150*time.Millisecond)
			},
			wantErr: context.DeadlineExceeded,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := tc.ctx()
			defer cancel()
			p := &HTTPProxy{proxyAddr: newSilentProxy(t), dialer: &net.Dialer{}}
			start := time.Now()
			conn, err := p.Proxy(ctx, testAddr("example.com:443"))
			elapsed := time.Since(start)
			if err == nil {
				conn.Close()
				t.Fatalf("Proxy succeeded, want error")
			}
			if elapsed > 2*time.Second {
				t.Errorf("took %v, want the context to interrupt promptly", elapsed)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("error = %v, want it to wrap %v", err, tc.wantErr)
			}
			var netErr net.Error
			if !errors.As(err, &netErr) {
				t.Errorf("error = %v, want the underlying net.Error preserved", err)
			}
			if conn != nil {
				t.Errorf("got non-nil conn alongside error")
			}
		})
	}
}

func TestProxyContextCancelAfterReturn(t *testing.T) {
	trailing := []byte("tunnel-payload")
	s := newStubProxy(t, connectEstablish, trailing)
	ctx, cancel := context.WithCancel(context.Background())
	p := &HTTPProxy{proxyAddr: s.addr, dialer: &net.Dialer{}, timeout: time.Second}
	conn, err := p.Proxy(ctx, testAddr("example.com:443"))
	if err != nil {
		t.Fatalf("Proxy: %v", err)
	}
	defer conn.Close()
	cancel()
	time.Sleep(50 * time.Millisecond)
	if err := conn.SetReadDeadline(time.Now().Add(testTimeout)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	got := make([]byte, len(trailing))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read after cancel: %v", err)
	}
	if !bytes.Equal(got, trailing) {
		t.Errorf("tunnel data = %q, want %q", got, trailing)
	}
}

func TestProxyHTTPRequestLine(t *testing.T) {
	tests := []struct {
		name string
		dest string
		raw  string
		want string
	}{
		{
			name: "host header wins",
			dest: "192.0.2.1:80",
			raw:  "GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n",
			want: "GET http://example.com/path HTTP/1.1",
		},
		{
			name: "addr used without host header",
			dest: "example.com:8080",
			raw:  "GET /path HTTP/1.0\r\n\r\n",
			want: "GET http://example.com:8080/path HTTP/1.0",
		},
		{
			name: "query preserved",
			dest: "example.com:80",
			raw:  "GET /path?a=1&b=2 HTTP/1.1\r\nHost: example.com\r\n\r\n",
			want: "GET http://example.com/path?a=1&b=2 HTTP/1.1",
		},
		{
			name: "root path",
			dest: "example.com:80",
			raw:  "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			want: "GET http://example.com/ HTTP/1.1",
		},
		{
			name: "absolute form request target",
			dest: "example.com:80",
			raw:  "GET http://other.example/path HTTP/1.1\r\nHost: ignored.example\r\n\r\n",
			want: "GET http://other.example/path HTTP/1.1",
		},
		{
			name: "post method",
			dest: "example.com:80",
			raw:  "POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n",
			want: "POST http://example.com/submit HTTP/1.1",
		},
		{
			name: "encoded path preserved",
			dest: "example.com:80",
			raw:  "GET /a%20b HTTP/1.1\r\nHost: example.com\r\n\r\n",
			want: "GET http://example.com/a%20b HTTP/1.1",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := proxyHTTP(t, &HTTPProxy{}, tc.dest, tc.raw)
			if got := s.requestLine(); got != tc.want {
				t.Errorf("request line = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestProxyHTTPPreservesVersion(t *testing.T) {
	for _, proto := range []string{"HTTP/1.0", "HTTP/1.1"} {
		t.Run(proto, func(t *testing.T) {
			raw := "GET /path " + proto + "\r\nHost: example.com\r\n\r\n"
			s := proxyHTTP(t, &HTTPProxy{}, "example.com:80", raw)
			if got := s.requestLine(); !strings.HasSuffix(got, proto) {
				t.Errorf("request line = %q, want it to end with %q", got, proto)
			}
		})
	}
}

func TestProxyHTTPRejects(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr string
	}{
		{"connect", "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n", "CONNECT method is not supported"},
		{"asterisk options", "OPTIONS * HTTP/1.1\r\nHost: example.com\r\n\r\n", "asterisk-form"},
		{"asterisk get", "GET * HTTP/1.1\r\nHost: example.com\r\n\r\n", "asterisk-form"},
		{"post http 0.9", "POST /x HTTP/0.9\r\nHost: example.com\r\n\r\n", "non-GET HTTP/0.9"},
		{"head http 0.9", "HEAD /x HTTP/0.9\r\nHost: example.com\r\n\r\n", "non-GET HTTP/0.9"},
		{"malformed version", "GET /x HTTP1.1\r\nHost: example.com\r\n\r\n", "failed to read incoming http request header"},
		{"missing version", "GET /x\r\nHost: example.com\r\n\r\n", "failed to read incoming http request header"},
		{"empty request", "", "failed to read incoming http request header"},
		{"garbage", "\x00\x01\x02\r\n\r\n", "failed to read incoming http request header"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newStubProxy(t, "", nil)
			p := &HTTPProxy{proxyAddr: s.addr, dialer: &net.Dialer{}}
			conn, err := p.ProxyHTTP(context.Background(), testAddr("example.com:80"), clientRequest(t, tc.raw))
			if err == nil {
				conn.Close()
				t.Fatalf("ProxyHTTP succeeded, want error")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %v, want it to contain %q", err, tc.wantErr)
			}
			if conn != nil {
				t.Errorf("got non-nil conn alongside error")
			}
		})
	}
}

func TestProxyHTTPConnectionHeader(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{"keep alive", "GET /x HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\n\r\n"},
		{"proxy connection", "GET /x HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: keep-alive\r\n\r\n"},
		{"both", "GET /x HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\nProxy-Connection: keep-alive\r\n\r\n"},
		{"absent", "GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n"},
		{"already close", "GET /x HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"},
		{"mixed case", "GET /x HTTP/1.1\r\nHost: example.com\r\nCONNECTION: Keep-Alive\r\nPROXY-CONNECTION: Keep-Alive\r\n\r\n"},
		{"multi value", "GET /x HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive, Upgrade\r\n\r\n"},
		{"repeated", "GET /x HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\nConnection: TE\r\n\r\n"},
		{"http 1.0", "GET /x HTTP/1.0\r\nHost: example.com\r\nConnection: keep-alive\r\n\r\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := proxyHTTP(t, &HTTPProxy{}, "example.com:80", tc.raw)
			if got, want := s.header("Connection"), []string{"close"}; !equalStrings(got, want) {
				t.Errorf("Connection = %v, want %v", got, want)
			}
			if got := s.header("Proxy-Connection"); len(got) != 0 {
				t.Errorf("Proxy-Connection = %v, want none", got)
			}
			if strings.Contains(strings.ToLower(s.request()), "keep-alive") {
				t.Errorf("keep-alive leaked upstream:\n%s", s.request())
			}
		})
	}
}

func TestProxyHTTPProxyAuthorization(t *testing.T) {
	tests := []struct {
		name     string
		username string
		password string
		raw      string
		want     []string
	}{
		{
			name: "absent when unconfigured",
			raw:  "GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n",
			want: nil,
		},
		{
			name:     "set when configured",
			username: "user",
			password: "pass",
			raw:      "GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n",
			want:     []string{"Basic dXNlcjpwYXNz"},
		},
		{
			name:     "replaces client value",
			username: "user",
			password: "pass",
			raw:      "GET /x HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic ZXZpbDpldmls\r\n\r\n",
			want:     []string{"Basic dXNlcjpwYXNz"},
		},
		{
			name: "strips client value when unconfigured",
			raw:  "GET /x HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic ZXZpbDpldmls\r\n\r\n",
			want: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &HTTPProxy{username: tc.username, password: tc.password}
			s := proxyHTTP(t, p, "example.com:80", tc.raw)
			if got := s.header("Proxy-Authorization"); !equalStrings(got, tc.want) {
				t.Errorf("Proxy-Authorization = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestProxyHTTPUserAgent(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{
			name: "client value preserved",
			raw:  "GET /x HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.0\r\n\r\n",
			want: []string{"curl/8.0"},
		},
		{
			name: "absent stays absent",
			raw:  "GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n",
			want: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := proxyHTTP(t, &HTTPProxy{}, "example.com:80", tc.raw)
			if got := s.header("User-Agent"); !equalStrings(got, tc.want) {
				t.Errorf("User-Agent = %v, want %v", got, tc.want)
			}
			if strings.Contains(s.request(), "Go-http-client") {
				t.Errorf("Go default user agent leaked:\n%s", s.request())
			}
		})
	}
}

func TestProxyHTTPForwardsBody(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "content length",
			raw:  "POST /x HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nHELLO",
			want: "HELLO",
		},
		{
			name: "large body",
			raw:  "POST /x HTTP/1.1\r\nHost: example.com\r\nContent-Length: 10000\r\n\r\n" + strings.Repeat("B", 10000),
			want: strings.Repeat("B", 10000),
		},
		{
			name: "empty body",
			raw:  "POST /x HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n",
			want: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := proxyHTTP(t, &HTTPProxy{}, "example.com:80", tc.raw)
			_, body, found := strings.Cut(s.request(), "\r\n\r\n")
			if !found {
				t.Fatalf("no header terminator in:\n%s", s.request())
			}
			if body != tc.want {
				t.Errorf("body length = %d, want %d", len(body), len(tc.want))
			}
		})
	}
}

func TestProxyHTTPChunkedBody(t *testing.T) {
	raw := "POST /x HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHELLO\r\n0\r\n\r\n"
	s := proxyHTTP(t, &HTTPProxy{}, "example.com:80", raw)
	if !strings.Contains(s.request(), "HELLO") {
		t.Errorf("body not forwarded:\n%s", s.request())
	}
}

func TestProxyHTTPLongRequestLine(t *testing.T) {
	path := "/" + strings.Repeat("a", 8000)
	raw := "GET " + path + " HTTP/1.0\r\nHost: example.com\r\n\r\n"
	s := proxyHTTP(t, &HTTPProxy{}, "example.com:80", raw)
	want := "GET http://example.com" + path + " HTTP/1.0"
	if got := s.requestLine(); got != want {
		t.Errorf("request line length = %d, want %d", len(got), len(want))
	}
}

func TestProxyHTTP09(t *testing.T) {
	s := proxyHTTP(t, &HTTPProxy{}, "example.com:8080", "GET /x HTTP/0.9\r\nHost: example.com\r\n\r\n")
	if got, want := s.request(), "GET http://example.com/x HTTP/0.9\r\n\r\n"; got != want {
		t.Errorf("request = %q, want %q", got, want)
	}
}

func TestProxyHTTP09NoHostHeader(t *testing.T) {
	s := proxyHTTP(t, &HTTPProxy{}, "example.com:8080", "GET /x HTTP/0.9\r\n\r\n")
	if got, want := s.request(), "GET http://example.com:8080/x HTTP/0.9\r\n\r\n"; got != want {
		t.Errorf("request = %q, want %q", got, want)
	}
}

func TestProxyHTTPDialFailure(t *testing.T) {
	p := &HTTPProxy{proxyAddr: "proxy.example:3128", dialer: failingDialer{err: errDialFailed}}
	conn, err := p.ProxyHTTP(context.Background(), testAddr("example.com:80"), clientRequest(t, "GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	if err == nil {
		conn.Close()
		t.Fatalf("ProxyHTTP succeeded, want error")
	}
	if !errors.Is(err, errDialFailed) {
		t.Errorf("error = %v, want it to wrap errDialFailed", err)
	}
}

func TestProxyHTTPClosesConnOnError(t *testing.T) {
	client, _ := tcpPair(t)
	rec := &recordingConn{Conn: client}
	p := &HTTPProxy{proxyAddr: "unused", dialer: &recordingDialer{conn: rec}}
	_, err := p.ProxyHTTP(context.Background(), testAddr("example.com:443"),
		clientRequest(t, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"))
	if err == nil {
		t.Fatalf("ProxyHTTP succeeded, want error")
	}
	if rec.closes != 1 {
		t.Errorf("closes = %d, want 1", rec.closes)
	}
}

func TestProxyHTTPClearsDeadlines(t *testing.T) {
	timeout := 200 * time.Millisecond
	upstream := newStubProxy(t, "", nil)
	client, server := tcpPair(t)
	go func() {
		_, _ = client.Write([]byte("GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	}()
	p := &HTTPProxy{proxyAddr: upstream.addr, dialer: &net.Dialer{}, timeout: timeout}
	pc, err := p.ProxyHTTP(context.Background(), testAddr("example.com:80"), server)
	if err != nil {
		t.Fatalf("ProxyHTTP: %v", err)
	}
	defer pc.Close()
	time.Sleep(2 * timeout)

	if _, err := pc.Write([]byte("more")); err != nil {
		t.Errorf("write to upstream after the timeout window: %v", err)
	}
	go func() {
		_, _ = client.Write([]byte("trailing"))
	}()
	if err := server.SetReadDeadline(time.Now().Add(testTimeout)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	buf := make([]byte, len("trailing"))
	if _, err := io.ReadFull(server, buf); err != nil {
		t.Errorf("read from client after the timeout window: %v", err)
	}
}

func TestProxyHTTPTimeoutEnforced(t *testing.T) {
	upstream := newStubProxy(t, "", nil)
	client, server := tcpPair(t)
	go func() {
		_, _ = client.Write([]byte("GET /x HTTP/1.1\r\nHost: example.com\r\n"))
	}()
	p := &HTTPProxy{proxyAddr: upstream.addr, dialer: &net.Dialer{}, timeout: 200 * time.Millisecond}
	start := time.Now()
	conn, err := p.ProxyHTTP(context.Background(), testAddr("example.com:80"), server)
	elapsed := time.Since(start)
	if err == nil {
		conn.Close()
		t.Fatalf("ProxyHTTP succeeded, want timeout")
	}
	if elapsed > 2*time.Second {
		t.Errorf("took %v, want the timeout to fire promptly", elapsed)
	}
}

func TestProxyHTTPContextCancelled(t *testing.T) {
	upstream := newStubProxy(t, "", nil)
	client, server := tcpPair(t)
	go func() {
		_, _ = client.Write([]byte("GET /x HTTP/1.1\r\nHost: example.com\r\n"))
	}()
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(150*time.Millisecond, cancel)
	defer cancel()
	p := &HTTPProxy{proxyAddr: upstream.addr, dialer: &net.Dialer{}}
	start := time.Now()
	conn, err := p.ProxyHTTP(ctx, testAddr("example.com:80"), server)
	elapsed := time.Since(start)
	if err == nil {
		conn.Close()
		t.Fatalf("ProxyHTTP succeeded, want error")
	}
	if elapsed > 2*time.Second {
		t.Errorf("took %v, want the context to interrupt promptly", elapsed)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want it to wrap context.Canceled", err)
	}
	if conn != nil {
		t.Errorf("got non-nil conn alongside error")
	}
}

func TestProxyHTTPContextCancelAfterReturn(t *testing.T) {
	upstream := newStubProxy(t, "", nil)
	ctx, cancel := context.WithCancel(context.Background())
	p := &HTTPProxy{proxyAddr: upstream.addr, dialer: &net.Dialer{}}
	pc, err := p.ProxyHTTP(ctx, testAddr("example.com:80"), clientRequest(t, "GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	if err != nil {
		t.Fatalf("ProxyHTTP: %v", err)
	}
	defer pc.Close()
	cancel()
	time.Sleep(50 * time.Millisecond)
	if _, err := pc.Write([]byte("more")); err != nil {
		t.Errorf("write after cancel: %v", err)
	}
}

func TestFixedVersionWriterReplacesVersion(t *testing.T) {
	tests := []struct {
		name    string
		version string
		input   string
		want    string
	}{
		{
			name:    "downgrade to 1.0",
			version: "HTTP/1.0",
			input:   "GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n",
			want:    "GET /x HTTP/1.0\r\nHost: example.com\r\n\r\n",
		},
		{
			name:    "same version",
			version: "HTTP/1.1",
			input:   "GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n",
			want:    "GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		{
			name:    "absolute form target",
			version: "HTTP/1.0",
			input:   "GET http://example.com/x HTTP/1.1\r\nHost: example.com\r\n\r\n",
			want:    "GET http://example.com/x HTTP/1.0\r\nHost: example.com\r\n\r\n",
		},
		{
			name:    "with body",
			version: "HTTP/1.0",
			input:   "POST /x HTTP/1.1\r\nContent-Length: 4\r\n\r\nBODY",
			want:    "POST /x HTTP/1.0\r\nContent-Length: 4\r\n\r\nBODY",
		},
		{
			name:    "request line only",
			version: "HTTP/1.0",
			input:   "GET /x HTTP/1.1\r\n\r\n",
			want:    "GET /x HTTP/1.0\r\n\r\n",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var sink bytes.Buffer
			w := &fixedVersionWriter{Writer: &sink, version: tc.version}
			n, err := w.Write([]byte(tc.input))
			if err != nil {
				t.Fatalf("Write: %v", err)
			}
			if n != len(tc.input) {
				t.Errorf("n = %d, want %d", n, len(tc.input))
			}
			if sink.String() != tc.want {
				t.Errorf("output = %q, want %q", sink.String(), tc.want)
			}
		})
	}
}

func TestFixedVersionWriterChunked(t *testing.T) {
	input := "GET /" + strings.Repeat("a", 9000) + " HTTP/1.1\r\nHost: example.com\r\n\r\nBODY"
	want := "GET /" + strings.Repeat("a", 9000) + " HTTP/1.0\r\nHost: example.com\r\n\r\nBODY"
	for _, chunk := range []int{1, 7, 4096, 8192} {
		t.Run(fmt.Sprintf("chunk %d", chunk), func(t *testing.T) {
			var sink bytes.Buffer
			w := &fixedVersionWriter{Writer: &sink, version: "HTTP/1.0"}
			for offset := 0; offset < len(input); offset += chunk {
				end := min(offset+chunk, len(input))
				part := input[offset:end]
				n, err := w.Write([]byte(part))
				if err != nil {
					t.Fatalf("Write: %v", err)
				}
				if n != len(part) {
					t.Fatalf("n = %d, want %d", n, len(part))
				}
			}
			if sink.String() != want {
				t.Errorf("output length = %d, want %d", sink.Len(), len(want))
			}
		})
	}
}

func TestFixedVersionWriterIllFormed(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"no spaces", "NOSPACES\r\n\r\n"},
		{"one space", "GET /x\r\n\r\n"},
		{"empty line", "\r\n\r\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Write panicked: %v", r)
				}
			}()
			var sink bytes.Buffer
			w := &fixedVersionWriter{Writer: &sink, version: "HTTP/1.0"}
			n, err := w.Write([]byte(tc.input))
			if err == nil {
				t.Fatalf("Write succeeded, want error")
			}
			if n != 0 {
				t.Errorf("n = %d, want 0", n)
			}
		})
	}
}

func TestFixedVersionWriterExtraSpaces(t *testing.T) {
	var sink bytes.Buffer
	w := &fixedVersionWriter{Writer: &sink, version: "HTTP/1.0"}
	if _, err := w.Write([]byte("GET /x HTTP/1.1 extra\r\n\r\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got, want := sink.String(), "GET /x HTTP/1.0\r\n\r\n"; got != want {
		t.Errorf("output = %q, want %q", got, want)
	}
}

func TestFixedVersionWriterNeverExceedsInput(t *testing.T) {
	var sink shortWriter
	sink.limit = 10
	w := &fixedVersionWriter{Writer: &sink, version: "HTTP/1.0"}
	input := []byte("GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n")
	n, err := w.Write(input)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n > len(input) {
		t.Errorf("n = %d, want at most %d", n, len(input))
	}
	if n < 0 {
		t.Errorf("n = %d, want non-negative", n)
	}
}

func TestFixedVersionWriterPassthroughAfterReplace(t *testing.T) {
	var sink bytes.Buffer
	w := &fixedVersionWriter{Writer: &sink, version: "HTTP/1.0"}
	if _, err := w.Write([]byte("GET /x HTTP/1.1\r\n\r\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !w.replaced {
		t.Fatalf("replaced = false after a complete request line")
	}
	if _, err := w.Write([]byte("GET /y HTTP/1.1\r\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got, want := sink.String(), "GET /x HTTP/1.0\r\n\r\nGET /y HTTP/1.1\r\n"; got != want {
		t.Errorf("output = %q, want %q", got, want)
	}
}

func TestFixedVersionWriterPropagatesError(t *testing.T) {
	w := &fixedVersionWriter{Writer: errWriter{err: errBoom}, version: "HTTP/1.0"}
	if _, err := w.Write([]byte("GET /x HTTP/1.1\r\n\r\n")); !errors.Is(err, errBoom) {
		t.Errorf("error = %v, want errBoom", err)
	}
}

func TestFixedVersionWriterBuffersPartialLine(t *testing.T) {
	var sink bytes.Buffer
	w := &fixedVersionWriter{Writer: &sink, version: "HTTP/1.0"}
	n, err := w.Write([]byte("GET /x HTTP/1.1"))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len("GET /x HTTP/1.1") {
		t.Errorf("n = %d, want %d", n, len("GET /x HTTP/1.1"))
	}
	if sink.Len() != 0 {
		t.Errorf("wrote %q before the request line was complete", sink.String())
	}
}

func TestParseRequestLine(t *testing.T) {
	tests := []struct {
		name   string
		line   string
		method string
		target string
		proto  string
		wantOK bool
	}{
		{"standard", "GET /x HTTP/1.1", "GET", "/x", "HTTP/1.1", true},
		{"absolute form", "GET http://a/b HTTP/1.0", "GET", "http://a/b", "HTTP/1.0", true},
		{"asterisk", "OPTIONS * HTTP/1.1", "OPTIONS", "*", "HTTP/1.1", true},
		{"trailing content", "GET /x HTTP/1.1 extra", "GET", "/x", "HTTP/1.1 extra", true},
		{"no spaces", "GET", "", "", "", false},
		{"one space", "GET /x", "", "", "", false},
		{"empty", "", "", "", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := &fixedVersionWriter{}
			method, target, proto, ok := w.parseRequestLine(tc.line)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if method != tc.method || target != tc.target || proto != tc.proto {
				t.Errorf("got (%q, %q, %q), want (%q, %q, %q)", method, target, proto, tc.method, tc.target, tc.proto)
			}
		})
	}
}

func TestTimeoutWrapperSetsDeadlines(t *testing.T) {
	conn := &deadlineRecorder{}
	w := &timeoutWrapper{conn: conn, timeout: time.Second}
	if _, err := w.Read(make([]byte, 1)); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if _, err := w.Write([]byte("x")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if conn.readDeadlines != 1 {
		t.Errorf("read deadlines = %d, want 1", conn.readDeadlines)
	}
	if conn.writeDeadlines != 1 {
		t.Errorf("write deadlines = %d, want 1", conn.writeDeadlines)
	}
}

func TestTimeoutWrapperZeroTimeout(t *testing.T) {
	conn := &deadlineRecorder{}
	w := &timeoutWrapper{conn: conn}
	if _, err := w.Read(make([]byte, 1)); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if _, err := w.Write([]byte("x")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if conn.readDeadlines != 0 || conn.writeDeadlines != 0 {
		t.Errorf("deadlines set with a zero timeout: read=%d write=%d", conn.readDeadlines, conn.writeDeadlines)
	}
}

func TestTimeoutWrapperResetsPerOperation(t *testing.T) {
	conn := &deadlineRecorder{}
	w := &timeoutWrapper{conn: conn, timeout: time.Second}
	for range 3 {
		if _, err := w.Read(make([]byte, 1)); err != nil {
			t.Fatalf("Read: %v", err)
		}
	}
	if conn.readDeadlines != 3 {
		t.Errorf("read deadlines = %d, want 3", conn.readDeadlines)
	}
}

func TestInterruptOnCancelBackgroundContext(t *testing.T) {
	client, _ := tcpPair(t)
	stop := interruptOnCancel(context.Background(), client)
	if stop() {
		t.Errorf("stop reported fired for a context that cannot be cancelled")
	}
	if err := client.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	start := time.Now()
	_, _ = client.Read(make([]byte, 1))
	if elapsed := time.Since(start); elapsed < 100*time.Millisecond {
		t.Errorf("read returned after %v, want the caller deadline honoured", elapsed)
	}
}

func TestInterruptOnCancelUnblocksRead(t *testing.T) {
	client, _ := tcpPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := interruptOnCancel(ctx, client)
	defer stop()
	time.AfterFunc(100*time.Millisecond, cancel)
	start := time.Now()
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatalf("Read succeeded, want an interrupt")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("read took %v, want the cancel to interrupt promptly", elapsed)
	}
}

func TestInterruptOnCancelStopClearsDeadlines(t *testing.T) {
	first, _ := tcpPair(t)
	second, _ := tcpPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	stop := interruptOnCancel(ctx, first, second)
	cancel()
	if !stop() {
		t.Fatalf("stop reported not fired after cancel")
	}
	for i, conn := range []net.Conn{first, second} {
		if err := conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
			t.Fatalf("set deadline: %v", err)
		}
		start := time.Now()
		_, _ = conn.Read(make([]byte, 1))
		if elapsed := time.Since(start); elapsed < 100*time.Millisecond {
			t.Errorf("conn %d returned after %v, want the expired deadline cleared", i, elapsed)
		}
	}
}

func TestInterruptOnCancelStopBeforeCancel(t *testing.T) {
	client, _ := tcpPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	stop := interruptOnCancel(ctx, client)
	if err := client.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if stop() {
		t.Fatalf("stop reported fired before cancel")
	}
	cancel()
	time.Sleep(50 * time.Millisecond)
	start := time.Now()
	_, _ = client.Read(make([]byte, 1))
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("read took %v, want the caller deadline still in force", elapsed)
	}
}

func TestSetDeadlineHelpers(t *testing.T) {
	t.Run("zero timeout is a no-op", func(t *testing.T) {
		conn := &deadlineRecorder{}
		p := &HTTPProxy{}
		p.setReadDeadline(conn)
		p.setWriteDeadline(conn)
		p.clearDeadline(conn)
		if conn.readDeadlines != 0 || conn.writeDeadlines != 0 || conn.deadlines != 0 {
			t.Errorf("helpers touched the connection with a zero timeout")
		}
	})

	t.Run("non zero timeout sets deadlines", func(t *testing.T) {
		conn := &deadlineRecorder{}
		p := &HTTPProxy{timeout: time.Second}
		p.setReadDeadline(conn)
		p.setWriteDeadline(conn)
		p.clearDeadline(conn)
		if conn.readDeadlines != 1 || conn.writeDeadlines != 1 || conn.deadlines != 1 {
			t.Errorf("read=%d write=%d both=%d, want 1 each", conn.readDeadlines, conn.writeDeadlines, conn.deadlines)
		}
		if !conn.lastDeadline.IsZero() {
			t.Errorf("clearDeadline set %v, want the zero time", conn.lastDeadline)
		}
	})
}

func TestHTTPProxyImplementsProxy(t *testing.T) {
	var _ Proxy = (*HTTPProxy)(nil)
}

func TestProxyResponseReadable(t *testing.T) {
	response := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"
	upstream := newStubProxy(t, response, nil)
	p := &HTTPProxy{proxyAddr: upstream.addr, dialer: &net.Dialer{}}
	pc, err := p.ProxyHTTP(context.Background(), testAddr("example.com:80"),
		clientRequest(t, "GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	if err != nil {
		t.Fatalf("ProxyHTTP: %v", err)
	}
	defer pc.Close()
	if err := pc.SetReadDeadline(time.Now().Add(testTimeout)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(pc), nil)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if string(body) != "hi" {
		t.Errorf("body = %q, want %q", body, "hi")
	}
}

func TestProxyUpstreamWriteError(t *testing.T) {
	p := &HTTPProxy{proxyAddr: "proxy.example:3128", dialer: &fixedDialer{conn: &writeErrConn{}}}
	_, err := p.Proxy(context.Background(), testAddr("example.com:443"))
	if err == nil {
		t.Fatal("Proxy: expected error")
	}
	if !strings.Contains(err.Error(), "failed to send CONNECT request") {
		t.Errorf("error = %v, want failed to send CONNECT request", err)
	}
	if !errors.Is(err, errBoom) {
		t.Errorf("error does not wrap errBoom: %v", err)
	}
}

func TestProxyHTTPUpstreamWriteError(t *testing.T) {
	for _, tt := range []struct {
		name string
		raw  string
		want string
	}{
		{"http 1.1", "GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n", "failed to write http request"},
		{"http 0.9", "GET /x HTTP/0.9\r\n\r\n", "failed to write HTTP/0.9 proxy request"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := &HTTPProxy{proxyAddr: "proxy.example:3128", dialer: &fixedDialer{conn: &writeErrConn{}}}
			_, err := p.ProxyHTTP(context.Background(), testAddr("example.com:80"), clientRequest(t, tt.raw))
			if err == nil {
				t.Fatal("ProxyHTTP: expected error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want %v", err, tt.want)
			}
			if !errors.Is(err, errBoom) {
				t.Errorf("error does not wrap errBoom: %v", err)
			}
		})
	}
}
