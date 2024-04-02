package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/crypto/cryptobyte"
)

// Stream represents the incoming connections to aproxy.
type Stream interface {
	Host() string
	Src() *net.TCPAddr
	Dst() *net.TCPAddr
	OriginalDst() *net.TCPAddr
	io.ReadWriteCloser
}

type ConnInfo struct {
	src         *net.TCPAddr
	dst         *net.TCPAddr
	originalDst *net.TCPAddr
}

func (i *ConnInfo) Src() *net.TCPAddr {
	return i.src
}

func (i *ConnInfo) Dst() *net.TCPAddr {
	return i.dst
}

func (i *ConnInfo) OriginalDst() *net.TCPAddr {
	return i.originalDst
}

// GetConnInfo retrieve information from the TCP connection.
func GetConnInfo(conn *net.TCPConn) (info *ConnInfo, err error) {
	originalDst, err := GetSocketIPv4OriginalDst(conn)
	var errno syscall.Errno
	// errno 92: connection didn't go through NAT on this machine
	if err != nil && !errors.As(err, &errno) && errno != 92 {
		return nil, fmt.Errorf("getsockopt SO_ORIGINAL_DST failed: %s", err)
	}
	return &ConnInfo{
		src:         conn.RemoteAddr().(*net.TCPAddr),
		dst:         conn.LocalAddr().(*net.TCPAddr),
		originalDst: originalDst,
	}, nil
}

// PrereadConn is a wrapper around net.Conn that supports pre-reading from the underlying connection.
// Any Read before the EndPreread can be undone and read again by calling the EndPreread function.
type PrereadConn struct {
	ended bool
	buf   []byte
	mu    sync.Mutex
	conn  net.Conn
}

// EndPreread ends the pre-reading phase. Any Read before will be undone and data in the stream can be read again.
// EndPreread can be only called once.
func (c *PrereadConn) EndPreread() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ended {
		panic("call EndPreread after preread has ended or hasn't started")
	}
	c.ended = true
}

// Read reads from the underlying connection. Read during the pre-reading phase can be undone by EndPreread.
func (c *PrereadConn) Read(p []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ended {
		n = copy(p, c.buf)
		bufLen := len(c.buf)
		c.buf = c.buf[n:]
		if n == len(p) || (bufLen > 0 && bufLen == n) {
			return n, nil
		}
		rn, err := c.conn.Read(p[n:])
		return rn + n, err
	} else {
		n, err = c.conn.Read(p)
		c.buf = append(c.buf, p[:n]...)
		return n, err
	}
}

// Write writes data to the underlying connection.
func (c *PrereadConn) Write(p []byte) (n int, err error) {
	return c.conn.Write(p)
}

// Close closes the underlying connection.
func (c *PrereadConn) Close() error {
	return c.conn.Close()
}

// NewPrereadConn wraps the network connection and return a *PrereadConn.
// It's recommended to not touch the original connection after wrapped.
func NewPrereadConn(conn net.Conn) *PrereadConn {
	return &PrereadConn{conn: conn}
}

// addPort adds the port from connection info to host if host doesn't have one
func addPort(host string, info *ConnInfo) (string, error) {
	_, _, err := net.SplitHostPort(host)
	if err != nil {
		if strings.Contains(err.Error(), "missing port in address") {
			if info.OriginalDst() != nil {
				return net.JoinHostPort(host, strconv.Itoa(info.OriginalDst().Port)), nil
			}

			return net.JoinHostPort(host, strconv.Itoa(info.Dst().Port)), nil
		}
		return "", err
	}
	return host, nil
}

type HttpStream struct {
	*PrereadConn
	host string
	*ConnInfo
}

func (s *HttpStream) Host() string {
	return s.host
}

func NewHttpStream(conn net.Conn, info *ConnInfo) (s *HttpStream, err error) {
	preread := NewPrereadConn(conn)
	defer func() {
		if err != nil {
			err = fmt.Errorf("failed to preread HTTP request: %w", err)
		}
	}()
	defer preread.EndPreread()
	req, err := http.ReadRequest(bufio.NewReader(preread))
	if err != nil {
		return nil, err
	}
	host := req.Host
	if host != "" {
		host, err = addPort(host, info)
		if err != nil {
			return nil, fmt.Errorf("failed to parse HTTP Host %#v: %w", host, err)
		}
	}
	return &HttpStream{PrereadConn: preread, host: host, ConnInfo: info}, nil
}

// PrereadSNI pre-reads the Server Name Indication (SNI) from a TLS connection.
func PrereadSNI(conn *PrereadConn) (_ string, err error) {
	defer conn.EndPreread()
	defer func() {
		if err != nil {
			err = fmt.Errorf("failed to preread TLS client hello: %w", err)
		}
	}()
	typeVersionLen := make([]byte, 5)
	n, err := conn.Read(typeVersionLen)
	if n != 5 {
		return "", errors.New("too short")
	}
	if err != nil {
		return "", err
	}
	if typeVersionLen[0] != 22 {
		return "", errors.New("not a TCP handshake")
	}
	msgLen := binary.BigEndian.Uint16(typeVersionLen[3:])
	buf := make([]byte, msgLen+5)
	n, err = conn.Read(buf[5:])
	if n != int(msgLen) {
		return "", errors.New("too short")
	}
	if err != nil {
		return "", err
	}
	copy(buf[:5], typeVersionLen)
	return extractSNI(buf)
}

func extractSNI(data []byte) (string, error) {
	s := cryptobyte.String(data)
	var (
		version   uint16
		random    []byte
		sessionId []byte
	)

	if !s.Skip(9) ||
		!s.ReadUint16(&version) || !s.ReadBytes(&random, 32) ||
		!s.ReadUint8LengthPrefixed((*cryptobyte.String)(&sessionId)) {
		return "", fmt.Errorf("failed to parse TLS client hello version, random or session id")
	}

	var cipherSuitesData cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&cipherSuitesData) {
		return "", fmt.Errorf("failed to parse TLS client hello cipher suites")
	}

	var cipherSuites []uint16
	for !cipherSuitesData.Empty() {
		var suite uint16
		if !cipherSuitesData.ReadUint16(&suite) {
			return "", fmt.Errorf("failed to parse TLS client hello cipher suites")
		}
		cipherSuites = append(cipherSuites, suite)
	}

	var compressionMethods []byte
	if !s.ReadUint8LengthPrefixed((*cryptobyte.String)(&compressionMethods)) {
		return "", fmt.Errorf("failed to parse TLS client hello compression methods")
	}

	if s.Empty() {
		// ClientHello is optionally followed by extension data
		return "", fmt.Errorf("no extension data in TLS client hello")
	}

	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return "", fmt.Errorf("failed to parse TLS client hello extensions")
	}

	finalServerName := ""
	for !extensions.Empty() {
		var extension uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extension) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			return "", fmt.Errorf("failed to parse TLS client hello extension")
		}
		if extension != 0 {
			continue
		}
		var nameList cryptobyte.String
		if !extData.ReadUint16LengthPrefixed(&nameList) || nameList.Empty() {
			return "", fmt.Errorf("failed to parse server name extension")
		}

		for !nameList.Empty() {
			var nameType uint8
			var serverName cryptobyte.String
			if !nameList.ReadUint8(&nameType) ||
				!nameList.ReadUint16LengthPrefixed(&serverName) ||
				serverName.Empty() {
				return "", fmt.Errorf("failed to parse server name indication extension")
			}
			if nameType != 0 {
				continue
			}
			if len(finalServerName) != 0 {
				return "", fmt.Errorf("multiple names of the same name_type are prohibited in server name extension")
			}
			finalServerName = string(serverName)
			if strings.HasSuffix(finalServerName, ".") {
				return "", fmt.Errorf("SNI name ends with a trailing dot")
			}
		}
	}
	return finalServerName, nil
}

type TlsStream struct {
	*PrereadConn
	host string
	*ConnInfo
}

func (s *TlsStream) Host() string {
	return s.host
}

func NewTlsStream(conn net.Conn, info *ConnInfo) (*TlsStream, error) {
	preread := NewPrereadConn(conn)
	sni, err := PrereadSNI(preread)
	if err != nil {
		return nil, err
	}
	if sni != "" {
		sni, err = addPort(sni, info)
		if err != nil {
			return nil, fmt.Errorf("failed to parse SNI %#v as host: %w", sni, err)
		}
	}
	return &TlsStream{
		PrereadConn: preread,
		host:        sni,
		ConnInfo:    info,
	}, nil
}
