//go:build linux

package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/crypto/cryptobyte"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"
)

var version = "0.2.0"

type PrereadConn struct {
	prereadStarted bool
	prereadEnded   bool
	prereadBuf     []byte
	mu             sync.Mutex
	conn           net.Conn
}

func (c *PrereadConn) StartPreread() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.prereadStarted {
		panic("call StartPreread after preread has already started or ended")
	}
	c.prereadStarted = true
}

func (c *PrereadConn) RestorePreread() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.prereadStarted || c.prereadEnded {
		panic("call RestorePreread after preread has ended or hasn't started")
	}
	c.prereadEnded = true
}

func (c *PrereadConn) Read(p []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.prereadEnded {
		n = copy(p, c.prereadBuf)
		bufLen := len(c.prereadBuf)
		c.prereadBuf = c.prereadBuf[n:]
		if n == len(p) || (bufLen > 0 && bufLen == n) {
			return n, nil
		}
		rn, err := c.conn.Read(p[n:])
		return rn + n, err
	}
	if c.prereadStarted {
		n, err = c.conn.Read(p)
		c.prereadBuf = append(c.prereadBuf, p[:n]...)
		return n, err
	}
	return c.conn.Read(p)
}

func (c *PrereadConn) Write(p []byte) (n int, err error) {
	return c.conn.Write(p)
}

func NewPrereadConn(conn net.Conn) *PrereadConn {
	return &PrereadConn{conn: conn}
}

func PrereadSNI(conn *PrereadConn) (_ string, err error) {
	conn.StartPreread()
	defer conn.RestorePreread()
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
	var version uint16
	var random []byte
	var sessionId []byte
	var compressionMethods []byte
	var cipherSuites []uint16

	if !s.Skip(9) ||
		!s.ReadUint16(&version) || !s.ReadBytes(&random, 32) ||
		!s.ReadUint8LengthPrefixed((*cryptobyte.String)(&sessionId)) {
		return "", fmt.Errorf("failed to parse TLS client hello version, random or session id")
	}

	var cipherSuitesData cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&cipherSuitesData) {
		return "", fmt.Errorf("failed to parse TLS client hello cipher suites")
	}
	for !cipherSuitesData.Empty() {
		var suite uint16
		if !cipherSuitesData.ReadUint16(&suite) {
			return "", fmt.Errorf("failed to parse TLS client hello cipher suites")
		}
		cipherSuites = append(cipherSuites, suite)
	}

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

func PrereadHttpHost(conn *PrereadConn) (_ string, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("failed to preread HTTP request: %w", err)
		}
	}()

	conn.StartPreread()
	defer conn.RestorePreread()
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
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("proxy return %d response for connect request", response.StatusCode)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to receive http connect response from proxy: %w", err)
	}
	return conn, nil
}

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
	var sockaddr [16]byte
	size := 16
	_, _, e := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		file.Fd(),
		syscall.SOL_IP,
		80, // SO_ORIGINAL_DST
		uintptr(unsafe.Pointer(&sockaddr)),
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	if e != 0 {
		return nil, fmt.Errorf("getsockopt SO_ORIGINAL_DST failed: errno %d", e)
	}
	return &net.TCPAddr{
		IP:   sockaddr[4:8],
		Port: int(binary.BigEndian.Uint16(sockaddr[2:4])),
	}, nil
}

func RelayTcp(conn io.ReadWriter, proxyConn io.ReadWriteCloser, logger *slog.Logger) {
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

func RelayHttp(conn io.ReadWriter, proxyConn io.ReadWriteCloser, logger *slog.Logger) {
	defer func() {
		_ = proxyConn.Close()
	}()
	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		logger.Error("failed to read HTTP request from connection", "error", err)
		return
	}
	req.URL.Host = req.Host
	req.URL.Scheme = "http"
	req.Header.Set("Connection", "close")
	if err := req.WriteProxy(proxyConn); err != nil {
		logger.Error("failed to send HTTP request to proxy", "error", err)
		return
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

func HandleConn(conn net.Conn, proxy string) {
	defer func() { _ = conn.Close() }()
	logger := slog.With("src", conn.RemoteAddr())
	dst, err := GetOriginalDst(conn.(*net.TCPConn))
	if err != nil {
		slog.Error("failed to get connection original destination", "error", err)
		return
	}
	logger = logger.With("original_dst", dst)
	var host string
	var relay func(conn io.ReadWriter, proxyConn io.ReadWriteCloser, logger *slog.Logger)
	var dialProxy func(proxy string) (net.Conn, error)
	consigned := NewPrereadConn(conn)
	switch dst.Port {
	case 443:
		relay = RelayTcp
		sni, sniErr := PrereadSNI(consigned)
		if sniErr != nil {
			err = sniErr
		} else {
			host = fmt.Sprintf("%s:%d", sni, dst.Port)
			dialProxy = func(proxy string) (net.Conn, error) { return DialProxyConnect(proxy, host) }
		}
	case 80:
		relay = RelayHttp
		host, err = PrereadHttpHost(consigned)
		if !strings.Contains(host, ":") {
			host = fmt.Sprintf("%s:%d", host, dst.Port)
		}
		dialProxy = DialProxy
	default:
		logger.Error(fmt.Sprintf("unknown destination port: %d", dst.Port))
		return
	}
	if err != nil {
		logger.Error("failed to preread host from connection", "error", err)
		return
	}
	logger = logger.With("host", host)
	proxyConn, err := dialProxy(proxy)
	if err != nil {
		logger.Error("failed to connect to http proxy", "error", err)
		return
	}
	logger.Info("relay connection to http proxy")
	relay(consigned, proxyConn, logger)
}

func main() {
	proxyFlag := flag.String("proxy", "", "upstream HTTP proxy address in the 'host:port' format")
	flag.Parse()
	listenAddr := &net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: 8443}
	listener, err := net.ListenTCP("tcp", listenAddr)
	if err != nil {
		log.Fatalf("failed to listen on %s", listenAddr.String())
	}
	slog.Info("start listening on 0.0.0.0:8443")
	proxy := *proxyFlag
	if proxy == "" {
		log.Fatalf("no upstearm proxy specified")
	}
	slog.Info(fmt.Sprintf("start forwarding to proxy %s", proxy))
	for {
		conn, err := listener.Accept()
		if err != nil {
			slog.Error("failed to accept connection", "error", err)
			continue
		}
		go HandleConn(conn, proxy)
	}
}
