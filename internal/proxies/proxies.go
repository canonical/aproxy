// Package proxies provides implementation of a variety of proxy protocols.
package proxies

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/canonical/aproxy/internal/network"
	"github.com/canonical/aproxy/internal/version"
)

// Proxy represents a network proxy, for example an HTTP proxy or a SOCKS proxy.
type Proxy interface {
	// Proxy proxies a general TCP connection. The addr parameter is the remote address, which can be
	// an IP address:port or a hostname:port. Proxy returns a network connection proxied to that remote.
	// Cancelling ctx aborts the setup and makes Proxy return an error wrapping ctx.Err().
	Proxy(ctx context.Context, addr net.Addr) (net.Conn, error)
	// ProxyHTTP proxies an HTTP request. The addr parameter is the remote server address, which can
	// be an IP address:port or a hostname:port. ProxyHTTP returns a network connection from which a single
	// HTTP response can be read.
	// ProxyHTTP can only proxy one HTTP request/response pair, connection reuse is not supported.
	// Cancelling ctx aborts the setup and makes ProxyHTTP return an error wrapping ctx.Err().
	ProxyHTTP(ctx context.Context, addr net.Addr, req net.Conn) (resp net.Conn, err error)
}

type contextDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type HTTPProxy struct {
	proxyAddr string
	dialer    contextDialer
	timeout   time.Duration
	username  string
	password  string
}

func (p *HTTPProxy) setReadDeadline(conn net.Conn) {
	if p.timeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(p.timeout))
	}
}

func (p *HTTPProxy) setWriteDeadline(conn net.Conn) {
	if p.timeout > 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(p.timeout))
	}
}

func (p *HTTPProxy) clearDeadline(conn net.Conn) {
	if p.timeout > 0 {
		_ = conn.SetDeadline(time.Time{})
	}
}

// interruptOnCancel unblocks any read or write in flight on the given connections once ctx is done,
// by setting a deadline that has already passed. Neither net.Conn nor the operations on it are
// context aware, so an expired deadline is the only way to abort a blocked read or write.
//
// The returned stop function undoes the arrangement and reports whether ctx fired before it was
// called. If ctx did fire, stop waits for the interrupt to complete and then clears the deadlines
// again, so the connections are left usable for a caller that succeeded anyway. It must be called
// exactly once.
func interruptOnCancel(ctx context.Context, conns ...net.Conn) (stop func() (fired bool)) {
	if ctx.Done() == nil {
		return func() bool { return false }
	}
	done := make(chan struct{})
	stopAfterFunc := context.AfterFunc(ctx, func() {
		defer close(done)
		for _, conn := range conns {
			_ = conn.SetDeadline(time.Now())
		}
	})
	return func() bool {
		if stopAfterFunc() {
			return false
		}
		<-done
		for _, conn := range conns {
			_ = conn.SetDeadline(time.Time{})
		}
		return true
	}
}

func (p *HTTPProxy) proxyAuthorization() string {
	if p.username == "" {
		return ""
	}
	credentials := p.username + ":" + p.password
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(credentials))
}

// Proxy proxies a TCP connection using the HTTP CONNECT method.
func (p *HTTPProxy) Proxy(ctx context.Context, addr net.Addr) (_ net.Conn, err error) {
	pc, err := p.dialer.DialContext(ctx, "tcp", p.proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial upstream http proxy address %s: %w", p.proxyAddr, err)
	}
	defer func() {
		if err != nil {
			_ = pc.Close()
		}
	}()
	stop := interruptOnCancel(ctx, pc)
	defer func() {
		if stop() && err != nil {
			err = fmt.Errorf("maybe caused by %w: %w", ctx.Err(), err)
		}
	}()
	req := http.Request{
		Method: "CONNECT",
		URL: &url.URL{
			Host: addr.String(),
		},
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header: map[string][]string{
			"User-Agent": {fmt.Sprintf("aproxy/%s", version.Version)},
		},
		Host: addr.String(),
	}
	if auth := p.proxyAuthorization(); auth != "" {
		req.Header.Set("Proxy-Authorization", auth)
	}
	p.setWriteDeadline(pc)
	err = req.Write(pc)
	if err != nil {
		return nil, fmt.Errorf("failed to send CONNECT request to upstream http proxy: %w", err)
	}
	// A preread connection is needed here because the bufio.Reader required by http.ReadResponse may
	// read beyond the CONNECT response and into the tunneled data. Preread lets us replay those
	// extra bytes, so the returned connection starts exactly after the CONNECT response.
	rc := network.New(pc)
	b := bufio.NewReader(&io.LimitedReader{R: rc, N: 64 * 1024})
	var header []byte
	for {
		var line []byte
		p.setReadDeadline(rc)
		line, err = b.ReadBytes('\n')
		if err != nil {
			return nil, fmt.Errorf("failed to read CONNECT response header from upstream http proxy: %w", err)
		}
		header = append(header, line...)
		if len(line) == 2 && line[0] == '\r' && line[1] == '\n' {
			break
		}
	}
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(header)), &req)
	if err != nil {
		return nil, fmt.Errorf("failed to read CONNECT response from upstream http proxy: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("upstream http proxy returned %d response for CONNECT request", resp.StatusCode)
	}
	if resp.ContentLength > 0 {
		return nil, fmt.Errorf("upstream http proxy returned content length %d in CONNECT response", resp.ContentLength)
	}
	rc.EndPreread()
	_, _ = io.ReadFull(rc, header)
	p.clearDeadline(rc)
	return rc, nil
}

type timeoutWrapper struct {
	conn    net.Conn
	timeout time.Duration
}

func (w *timeoutWrapper) Read(p []byte) (n int, err error) {
	if w.timeout > 0 {
		_ = w.conn.SetReadDeadline(time.Now().Add(w.timeout))
	}
	return w.conn.Read(p)
}

func (w *timeoutWrapper) Write(p []byte) (n int, err error) {
	if w.timeout > 0 {
		_ = w.conn.SetWriteDeadline(time.Now().Add(w.timeout))
	}
	return w.conn.Write(p)
}

type fixedVersionWriter struct {
	io.Writer
	version  string
	line     []byte
	replaced bool
}

func (w *fixedVersionWriter) parseRequestLine(line string) (method, requestURI, proto string, ok bool) {
	method, rest, ok1 := strings.Cut(line, " ")
	requestURI, proto, ok2 := strings.Cut(rest, " ")
	if !ok1 || !ok2 {
		return "", "", "", false
	}
	return method, requestURI, proto, true
}

func (w *fixedVersionWriter) Write(p []byte) (n int, err error) {
	if w.replaced {
		return w.Writer.Write(p)
	}
	w.line = append(w.line, p...)
	reqLine, rest, found := bytes.Cut(w.line, []byte("\r\n"))
	if !found {
		return len(p), nil
	}

	method, uri, _, ok := w.parseRequestLine(string(reqLine))
	if !ok {
		return 0, errors.New("ill-formed request line")
	}
	w.line = []byte(fmt.Sprintf("%s %s %s\r\n", method, uri, w.version))
	w.line = append(w.line, rest...)
	w.replaced = true
	n, err = w.Writer.Write(w.line)
	return max(0, len(p)-(len(w.line)-n)), err
}

// ProxyHTTP proxies a single HTTP request using the plain HTTP proxy method and returns a network
// connection from which a single HTTP response can be read.
// The addr parameter is only used for the request target when the incoming request has no Host header,
// a Host header supplied by the client takes precedence over addr.
// The CONNECT method and the asterisk-form request target are not supported here.
func (p *HTTPProxy) ProxyHTTP(ctx context.Context, addr net.Addr, conn net.Conn) (_ net.Conn, err error) {
	pc, err := p.dialer.DialContext(ctx, "tcp", p.proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial upstream http proxy address %s: %w", p.proxyAddr, err)
	}
	defer func() {
		if err != nil {
			_ = pc.Close()
		}
	}()
	stop := interruptOnCancel(ctx, conn, pc)
	defer func() {
		if stop() && err != nil {
			err = fmt.Errorf("maybe caused by %w: %w", ctx.Err(), err)
		}
	}()
	req, err := http.ReadRequest(bufio.NewReader(&timeoutWrapper{conn: conn, timeout: p.timeout}))
	if err != nil {
		return nil, fmt.Errorf("failed to read incoming http request header: %w", err)
	}
	if req.Method == http.MethodConnect {
		return nil, fmt.Errorf("CONNECT method is not supported")
	}
	if req.URL.Path == "*" {
		return nil, fmt.Errorf("asterisk-form request target is not supported")
	}
	if req.UserAgent() == "" {
		req.Header.Set("User-Agent", "")
	}
	req.Header.Del("Proxy-Authorization")
	if auth := p.proxyAuthorization(); auth != "" {
		req.Header.Set("Proxy-Authorization", auth)
	}
	req.Header.Del("Proxy-Connection")
	req.Header.Set("Connection", "close")
	// The request target sent upstream comes from req.Host when the client supplied a Host header,
	// and falls back to req.URL.Host otherwise.
	req.URL.Host = addr.String()
	req.URL.Scheme = "http"
	if req.Proto == "HTTP/0.9" {
		buf := bytes.NewBuffer(nil)
		_ = req.WriteProxy(buf)
		line, _, _ := bytes.Cut(buf.Bytes(), []byte("\r\n"))
		if !bytes.HasPrefix(line, []byte("GET ")) {
			return nil, fmt.Errorf("non-GET HTTP/0.9 request is not supported")
		}
		// Go always writes the request line with HTTP/1.1.
		line = bytes.TrimSuffix(line, []byte("HTTP/1.1"))
		// An HTTP/0.9 request has only a request line, no headers and no body.
		line = append(line, []byte("HTTP/0.9\r\n\r\n")...)
		p.setWriteDeadline(pc)
		_, err = pc.Write(line)
		if err != nil {
			return nil, fmt.Errorf("failed to write HTTP/0.9 proxy request to upstream http proxy: %w", err)
		}
		p.clearDeadline(pc)
		return pc, nil
	}

	// Whatever the request protocol is, Go always writes the request line with a minimum version of
	// HTTP/1.1. That breaks HTTP/1.0-only clients such as GPG (HKP), so fixedVersionWriter rewrites
	// the protocol version back to the one the client used.
	err = req.WriteProxy(
		&fixedVersionWriter{
			Writer:  &timeoutWrapper{conn: pc, timeout: p.timeout},
			version: req.Proto,
		})
	if err != nil {
		return nil, fmt.Errorf("failed to write http request to upstream http proxy: %w", err)
	}
	p.clearDeadline(pc)
	return pc, nil
}

// Options represents the options for creating a proxy.
type Options struct {
	// Dialer is used to dial connections to the proxy server.
	Dialer *net.Dialer
	// Timeout is the read and write timeout applied to both the incoming connection and the proxy
	// connection. Zero means no limit.
	Timeout time.Duration
}

// NewProxyFromURL creates a new Proxy instance from a proxy URL.
// Currently supported schemes: http://, https://.
func NewProxyFromURL(proxyUrl string, option Options) (Proxy, error) {
	u, err := url.Parse(proxyUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to parse proxy URL: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("no hostname in proxy URL")
	}
	port := u.Port()
	username := u.User.Username()
	password, _ := u.User.Password()
	dialer := &net.Dialer{}
	if option.Dialer != nil {
		dialer = option.Dialer
	}
	if u.Scheme == "http" {
		if port == "" {
			port = "80"
		}
		return &HTTPProxy{
			proxyAddr: net.JoinHostPort(host, port),
			dialer:    dialer,
			username:  username,
			password:  password,
			timeout:   option.Timeout,
		}, nil
	}
	if u.Scheme == "https" {
		if port == "" {
			port = "443"
		}
		return &HTTPProxy{
			proxyAddr: net.JoinHostPort(host, port),
			dialer:    &tls.Dialer{NetDialer: dialer},
			username:  username,
			password:  password,
			timeout:   option.Timeout,
		}, nil
	}
	return nil, fmt.Errorf("unsupported proxy type: %s", proxyUrl)
}
