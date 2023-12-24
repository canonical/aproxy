package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"syscall"
)

type Forwarder struct {
	fwmark     uint32
	httpProxy  string
	httpsProxy string
}

// dialTCP dials the TCP connection to the remote address "HOST:PORT"
// dialTCP sets the fwmark of the underlying socket if the fwmark argument is not 0.
func (f *Forwarder) dialTCP(addr string) (net.Conn, error) {
	var fwmarkErr error
	dialer := &net.Dialer{
		Control: func(_, _ string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				if f.fwmark > 0 {
					err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(f.fwmark))
					if err != nil {
						fwmarkErr = fmt.Errorf("failed to set mark on socket: %w", err)
					}
				}
			})
		},
	}
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to '%v': %w", addr, err)
	}
	if fwmarkErr != nil {
		return nil, fmt.Errorf("failed to set mark on socket: %w", fwmarkErr)
	}
	return conn, nil
}

// proxyConnect dials the TCP connection and finishes the HTTP CONNECT handshake with the proxy.
// The dst argument is used during the handshake as the destination.
func (f *Forwarder) proxyConnect(dst string) (net.Conn, error) {
	conn, err := f.dialTCP(f.httpsProxy)
	if err != nil {
		return nil, err
	}
	request := http.Request{
		Method: "CONNECT",
		URL: &url.URL{
			Host: dst,
		},
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header: map[string][]string{
			"User-Agent": {fmt.Sprintf("aproxy/%s", version)},
		},
		Host: dst,
	}
	err = request.Write(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to send connect request to http proxy: %w", err)
	}
	response, err := http.ReadResponse(bufio.NewReaderSize(conn, 0), &request)
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("proxy return %d response for connect request", response.StatusCode)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to receive http connect response from proxy: %w", err)
	}
	return conn, nil
}

// relayTCP relays data between the incoming TCP connection and the outgoing connection.
func (f *Forwarder) relayTCP(ctx context.Context, in io.ReadWriter, out io.ReadWriteCloser) {
	var closed atomic.Bool
	go func() {
		_, err := io.Copy(out, in)
		if err != nil && !closed.Load() {
			logger.ErrorContext(ctx, "failed to relay network traffic to outgoing connection", "error", err)
		}
		closed.Store(true)
		_ = out.Close()
	}()
	_, err := io.Copy(in, out)
	if err != nil && !closed.Load() {
		logger.ErrorContext(ctx, "failed to relay network traffic to incoming connection", "error", err)
	}
	closed.Store(true)
}

// relayHTTP relays a single HTTP request and response between a local connection and a proxy.
// It modifies the Connection header to "close" in both the request and response.
func (f *Forwarder) relayHTTP(ctx context.Context, conn io.ReadWriter, proxyConn io.ReadWriteCloser) {
	defer proxyConn.Close()
	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		logger.ErrorContext(ctx, "failed to read HTTP request from connection", "error", err)
		return
	}
	req.URL.Host = req.Host
	req.URL.Scheme = "http"
	req.Header.Set("Connection", "close")
	if err := req.WriteProxy(proxyConn); err != nil {
		logger.ErrorContext(ctx, "failed to send HTTP request to proxy", "error", err)
		return
	}
	resp, err := http.ReadResponse(bufio.NewReader(proxyConn), req)
	if err != nil {
		logger.ErrorContext(ctx, "failed to read HTTP response from proxy", "error", err)
		return
	}
	resp.Header.Set("Connection", "close")
	if err := resp.Write(conn); err != nil {
		logger.ErrorContext(ctx, "failed to send HTTP response to connection", "error", err)
		return
	}
}

// passthrough forwards the connection to the original destination.
func (f *Forwarder) passthrough(ctx context.Context, conn *ConsignedConn) {
	out, err := f.dialTCP(conn.OriginalDst.String())
	if err != nil {
		logger.ErrorContext(ctx, "failed to dial original src address for passthrough connection", "error", err)
		return
	}
	logger.InfoContext(ctx, "passthrough connection")
	f.relayTCP(ctx, conn, out)
}

// proxyHTTP forwards the connection to an upstream HTTP proxy.
func (f *Forwarder) proxyHTTP(ctx context.Context, conn *ConsignedConn) {
	out, err := f.dialTCP(f.httpProxy)
	if err != nil {
		logger.ErrorContext(ctx, "failed to dial http proxy", "error", err)
		return
	}
	logger.InfoContext(ctx, "relay HTTP connection to proxy", "http_proxy", f.httpProxy)
	f.relayHTTP(ctx, conn, out)
}

// proxyHTTPS forwards the connection to an upstream HTTPS proxy.
func (f *Forwarder) proxyHTTPS(ctx context.Context, conn *ConsignedConn) {
	out, err := f.proxyConnect(conn.Host)
	if err != nil {
		logger.ErrorContext(ctx, "failed to connect to https proxy", "error", err)
		return
	}
	logger.InfoContext(ctx, "relay TLS connection to proxy", "https_proxy", f.httpsProxy)
	f.relayTCP(ctx, conn, out)
}

// ForwardHTTP forwards the given HTTP connection to upstream http proxy or passthrough to original destination
// base on the configuration. It's the duty of the caller to close the input connection.
func (f *Forwarder) ForwardHTTP(ctx context.Context, conn *ConsignedConn) {
	if f.httpProxy == "" {
		f.passthrough(ctx, conn)
	} else {
		f.proxyHTTP(ctx, conn)
	}
}

// ForwardHTTPS forwards the given HTTPS/TLS connection to upstream https proxy or passthrough to original destination
// base on the configuration. It's the duty of the caller to close the input connection.
func (f *Forwarder) ForwardHTTPS(ctx context.Context, conn *ConsignedConn) {
	if f.httpsProxy == "" {
		f.passthrough(ctx, conn)
	} else {
		f.proxyHTTPS(ctx, conn)
	}
}
