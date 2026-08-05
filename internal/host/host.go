// Package host provides helper functions to extract hostname information from connections.
package host

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

type connWrapper struct {
	r       io.Reader
	connErr error
}

func (c *connWrapper) Read(b []byte) (n int, err error) {
	n, err = c.r.Read(b)
	if err != nil {
		c.connErr = err
	}
	return n, err
}

func (c *connWrapper) Write(b []byte) (n int, err error) { return len(b), nil }

func (c *connWrapper) LocalAddr() net.Addr { return &net.TCPAddr{} }

func (c *connWrapper) RemoteAddr() net.Addr { return &net.TCPAddr{} }

func (c *connWrapper) SetDeadline(t time.Time) error { return nil }

func (c *connWrapper) SetReadDeadline(t time.Time) error { return nil }

func (c *connWrapper) SetWriteDeadline(t time.Time) error { return nil }

func (c *connWrapper) Close() error { return nil }

// ExtractHTTPHost attempts to extract hostname information from an incoming HTTP connection.
// If the extraction failed because the connection is not HTTP, or the HTTP
// request is malformed, or the HTTP request doesn't contain a host header, it
// will return "", nil.
// This function only returns an error when the error arises from the
// underlying IO (includes io.EOF).
func ExtractHTTPHost(r io.Reader) (string, error) {
	c := connWrapper{r: r}
	req, err := http.ReadRequest(bufio.NewReader(&c))
	if c.connErr != nil {
		return "", c.connErr
	}
	if err != nil {
		return "", nil
	}
	return (&url.URL{Host: req.Host}).Hostname(), nil
}

// ExtractSNI attempts to extract the SNI from the TLS ClientHello message of an
// incoming TLS connection.
// If the extraction failed because the connection is not TLS, or the TLS
// handshake is malformed, it will return "", nil.
// This function only returns an error when the error arises from the
// underlying IO (includes io.EOF).
func ExtractSNI(r io.Reader) (string, error) {
	var sni string
	c := connWrapper{r: r}
	tlsConn := tls.Server(&c, &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			sni = hello.ServerName
			return nil, context.Canceled
		},
	})
	_ = tlsConn.Handshake()
	_ = tlsConn.Close()
	if c.connErr != nil {
		return "", c.connErr
	}
	if sni != "" {
		return sni, nil
	}
	return "", c.connErr
}
