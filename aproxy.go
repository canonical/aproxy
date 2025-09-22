package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/cryptobyte"
)

var version = "0.2.4"

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

// NewPrereadConn wraps the network connection and return a *PrereadConn.
// It's recommended to not touch the original connection after wrapped.
func NewPrereadConn(conn net.Conn) *PrereadConn {
	return &PrereadConn{conn: conn}
}

// PrereadSNI pre-reads the Server Name Indication (SNI) from a TLS connection.
func PrereadSNI(conn *PrereadConn) (_ string, err error) {
	defer conn.EndPreread()
	defer func() {
		if err != nil {
			err = fmt.Errorf("failed to preread TLS client hello: %w", err)
		}
	}()
	recordHeader := make([]byte, 5)
	n, err := io.ReadFull(conn, recordHeader)
	if err != nil {
		return "", fmt.Errorf("failed to read TLS record layer header: %w", err)
	}
	if n != 5 {
		return "", fmt.Errorf("failed to read TLS record layer header: too short, less than 5 bytes (%d)", n)
	}
	if recordHeader[0] != 22 {
		return "", errors.New("not a TCP handshake")
	}
	msgLen := binary.BigEndian.Uint16(recordHeader[3:])
	buf := make([]byte, msgLen+5)
	n, err = io.ReadFull(conn, buf[5:])
	if n != int(msgLen) {
		return "", fmt.Errorf("client hello too short (%d < %d), err: %w", n, msgLen, err)
	}
	copy(buf[:5], recordHeader)
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

// PrereadHttpHost pre-reads the HTTP Host header from an HTTP connection.
func PrereadHttpHost(conn *PrereadConn) (_ string, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("failed to preread HTTP request: %w", err)
		}
	}()

	defer conn.EndPreread()
	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		return "", err
	}
	host := req.Host
	if host == "" {
		return "", errors.New("http request doesn't have host")
	}
	return host, nil
}

// DialProxy dials the TCP connection to the proxy.
func DialProxy(proxy string) (net.Conn, error) {
	proxyAddr, err := net.ResolveTCPAddr("tcp", proxy)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve proxy address: %w", err)
	}
	conn, err := net.DialTCP("tcp", nil, proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to proxy: %w", err)
	}
	return conn, nil
}

// DialProxyConnect dials the TCP connection and finishes the HTTP CONNECT handshake with the proxy.
// dst: HOST:PORT or IP:PORT
func DialProxyConnect(proxy string, dst string) (net.Conn, error) {
	conn, err := DialProxy(proxy)
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
	if err != nil {
		return nil, fmt.Errorf("failed to receive http connect response from proxy: %w", err)
	}
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("proxy return %d response for connect request", response.StatusCode)
	}
	return conn, nil
}

// GetOriginalDst get the original destination address of a TCP connection before dstnat.
func GetOriginalDst(conn *net.TCPConn) (*net.TCPAddr, error) {
	file, err := conn.File()
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			slog.Error("failed to close the duplicated TCP socket file descriptor")
		}
	}(file)
	if err != nil {
		return nil, fmt.Errorf("failed to convert connection to file: %w", err)
	}
	return GetsockoptIPv4OriginalDst(file.Fd())
}

// RelayTCP relays data between the incoming TCP connection and the proxy connection.
func RelayTCP(conn io.ReadWriter, proxyConn io.ReadWriteCloser, logger *slog.Logger) {
	var closed atomic.Bool
	go func() {
		_, err := io.Copy(proxyConn, conn)
		if err != nil && !closed.Load() {
			logger.Error("failed to relay network traffic to proxy", "error", err)
		}
		closed.Store(true)
		_ = proxyConn.Close()
	}()
	_, err := io.Copy(conn, proxyConn)
	if err != nil && !closed.Load() {
		logger.Error("failed to relay network traffic from proxy", "error", err)
	}
	closed.Store(true)
}

// RelayHTTP relays a single HTTP request and response between a local connection and a proxy.
// It modifies the Connection header to "close" in both the request and response.
func RelayHTTP(conn io.ReadWriter, proxyConn io.ReadWriteCloser, logger *slog.Logger) {
	defer proxyConn.Close()
	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		logger.Error("failed to read HTTP request from connection", "error", err)
		return
	}
	req.URL.Host = req.Host
	req.URL.Scheme = "http"
	if req.UserAgent() == "" {
		req.Header.Set("User-Agent", "")
	}
	req.Header.Set("Connection", "close")
	if req.Proto == "HTTP/1.0" {
		// no matter what the request protocol is, Go enforces a minimum version of HTTP/1.1
		// this causes problems for HTTP/1.0 only clients like GPG (HKP)
		// manually modify and send the HTTP/1.0 request to the proxy server
		buf := bytes.NewBuffer(nil)
		err := req.WriteProxy(buf)
		if err != nil {
			logger.Error("failed to serialize HTTP/1.0 request", "error", err)
			return
		}
		reqStr := buf.String()
		crlfIndex := strings.Index(reqStr, "\r\n")
		protoSpaceIndex := strings.LastIndex(reqStr[:crlfIndex], " ")
		reqStr = reqStr[:protoSpaceIndex+1] + "HTTP/1.0" + reqStr[crlfIndex:]
		_, err = proxyConn.Write([]byte(reqStr))
		if err != nil {
			logger.Error("failed to send HTTP request to proxy", "error", err)
			return
		}
	} else {
		if err := req.WriteProxy(proxyConn); err != nil {
			logger.Error("failed to send HTTP request to proxy", "error", err)
			return
		}
	}
	resp, err := http.ReadResponse(bufio.NewReader(proxyConn), req)
	if err != nil {
		logger.Error("failed to read HTTP response from proxy", "error", err)
		return
	}
	resp.Header.Set("Connection", "close")
	if err := resp.Write(conn); err != nil {
		logger.Error("failed to send HTTP response to connection", "error", err)
		return
	}
}

// HandleConn manages the incoming connections.
func HandleConn(conn net.Conn, proxy string) {
	defer conn.Close()
	logger := slog.With("src", conn.RemoteAddr())
	dst, err := GetOriginalDst(conn.(*net.TCPConn))
	if err != nil {
		slog.Error("failed to get connection original destination", "error", err)
		return
	}
	logger = logger.With("original_dst", dst)
	consigned := NewPrereadConn(conn)
	switch dst.Port {
	case 443:
		sni, err := PrereadSNI(consigned)
		if err != nil {
			logger.Error("failed to preread SNI from connection", "error", err)
			return
		} else {
			host := fmt.Sprintf("%s:%d", sni, dst.Port)
			logger = logger.With("host", host)
			proxyConn, err := DialProxyConnect(proxy, host)
			if err != nil {
				logger.Error("failed to connect to http proxy", "error", err)
				return
			}
			logger.Info("relay TLS connection to proxy")
			RelayTCP(consigned, proxyConn, logger)
		}
	case 80, 11371:
		host, err := PrereadHttpHost(consigned)
		if err != nil {
			logger.Error("failed to preread HTTP host from connection", "error", err)
			return
		}
		if !strings.Contains(host, ":") {
			host = fmt.Sprintf("%s:%d", host, dst.Port)
		}
		logger = logger.With("host", host)
		proxyConn, err := DialProxy(proxy)
		if err != nil {
			logger.Error("failed to connect to http proxy", "error", err)
			return
		}
		logger.Info("relay HTTP connection to proxy")
		RelayHTTP(consigned, proxyConn, logger)
	default:
		logger = logger.With("host", fmt.Sprintf("%s:%d", dst.IP.String(), dst.Port))
		proxyConn, err := DialProxyConnect(proxy, fmt.Sprintf("%s:%d", dst.IP.String(), dst.Port))
		if err != nil {
			logger.Error("failed to connect to tcp proxy", "error", err)
			return
		}
		logger.Info("relay TCP connection to proxy")
		RelayTCP(consigned, proxyConn, logger)
	}
}

func main() {
	proxyFlag := flag.String("proxy", "", "upstream proxy address in the 'host:port' format")
	listenFlag := flag.String("listen", ":8443", "the address and port on which the server will listen")
	flag.Parse()
	listenAddr := *listenFlag
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	listenConfig := new(net.ListenConfig)
	listener, err := listenConfig.Listen(ctx, "tcp", listenAddr)
	if err != nil {
		log.Fatalf("failed to listen on %#v", listenAddr)
	}
	slog.Info(fmt.Sprintf("start listening on %s", listenAddr))
	proxy := *proxyFlag
	if proxy == "" {
		log.Fatalf("no upstream proxy specified")
	}
	slog.Info(fmt.Sprintf("start forwarding to proxy %s", proxy))
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				slog.Error("failed to accept connection", "error", err)
				continue
			}
			go HandleConn(conn, proxy)
		}
	}()
	<-ctx.Done()
	stop()
}
