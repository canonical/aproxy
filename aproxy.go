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
	"sync/atomic"
	"syscall"
	"unsafe"
)

var version = "0.1.0"

type ConsignedConn interface {
	net.Conn
	Host() (string, error)
	PrepareTunnel(proxyConn net.Conn) error
}

type TlsConn struct {
	net.Conn
	DstAddr     *net.TCPAddr
	clientHello []byte
}

func (c *TlsConn) readClientHello() (_ []byte, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("failed to read TLS client hello: %w", err)
		}
	}()
	typeVersionLen := make([]byte, 5)
	n, err := c.Read(typeVersionLen)
	if n != 5 {
		return nil, errors.New("too short")
	}
	if err != nil {
		return nil, err
	}
	if typeVersionLen[0] != 22 {
		return nil, errors.New("not a TCP handshake")
	}
	msgLen := binary.BigEndian.Uint16(typeVersionLen[3:])
	buf := make([]byte, msgLen+5)
	n, err = c.Read(buf[5:])
	if n != int(msgLen) {
		return nil, errors.New("too short")
	}
	if err != nil {
		return nil, err
	}
	copy(buf[:5], typeVersionLen)
	return buf, nil
}

func (c *TlsConn) extractSNI(data []byte) (string, error) {
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

func (c *TlsConn) httpConnect(proxyConn net.Conn, dst string) error {
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
	err := request.Write(proxyConn)
	if err != nil {
		return fmt.Errorf("failed to send connect request to http proxy: %w", err)
	}
	response, err := http.ReadResponse(bufio.NewReaderSize(proxyConn, 0), &request)
	if response.StatusCode != 200 {
		return fmt.Errorf("proxy return %d response for connect request", response.StatusCode)
	}
	if err != nil {
		return fmt.Errorf("failed to receive http connect response from proxy: %w", err)
	}
	return nil
}

func (c *TlsConn) Host() (string, error) {
	if c.clientHello == nil {
		clientHello, err := c.readClientHello()
		if err != nil {
			return "", err
		}
		c.clientHello = clientHello
	}
	sni, err := c.extractSNI(c.clientHello)
	return fmt.Sprintf("%s:%d", sni, c.DstAddr.Port), err
}

func (c *TlsConn) PrepareTunnel(proxyConn net.Conn) error {
	host, err := c.Host()
	if err != nil {
		return err
	}
	if err = c.httpConnect(proxyConn, host); err != nil {
		return err
	}
	if _, err = proxyConn.Write(c.clientHello); err != nil {
		return fmt.Errorf("failed to send preread client hello to proxy: %w", err)
	}
	return nil
}

type HttpConn struct {
	net.Conn
	DstAddr *net.TCPAddr
	req     *http.Request
}

func (c *HttpConn) readHttpRequest() error {
	if c.req != nil {
		return nil
	}
	req, err := http.ReadRequest(bufio.NewReaderSize(c, 0))
	if err != nil {
		return fmt.Errorf("failed to read HTTP request: %w", err)
	}
	c.req = req
	return nil
}

func (c *HttpConn) getHost() (string, error) {
	if c.req == nil {
		err := c.readHttpRequest()
		if err != nil {
			return "", err
		}
	}
	host := c.req.Host
	if host == "" {
		return "", errors.New("http request doesn't have Host header")
	}
	return host, nil
}

func (c *HttpConn) Host() (string, error) {
	host, err := c.getHost()
	if err != nil {
		return "", err
	}
	if strings.Contains(host, ":") {
		return host, nil
	}
	return fmt.Sprintf("%s:%d", host, c.DstAddr.Port), nil
}

func (c *HttpConn) PrepareTunnel(proxyConn net.Conn) error {
	if c.req == nil {
		if err := c.readHttpRequest(); err != nil {
			return err
		}
	}
	host, err := c.getHost()
	if err != nil {
		return err
	}
	if c.DstAddr.Port != 80 {
		host = fmt.Sprintf("%s:%d", host, c.DstAddr.Port)
	}
	c.req.URL.Host = host
	c.req.URL.Scheme = "http"
	c.req.Header.Set("Connection", "close")
	if err = c.req.WriteProxy(proxyConn); err != nil {
		return fmt.Errorf("failed to send request to http proxy: %w", err)
	}
	return nil
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
		return nil, fmt.Errorf("getsocketopt SO_ORIGINAL_DST failed: errno %d", e)
	}
	return &net.TCPAddr{
		IP:   sockaddr[4:8],
		Port: int(binary.BigEndian.Uint16(sockaddr[2:4])),
	}, nil
}

func forward(conn, proxyConn net.Conn, logger *slog.Logger) {
	// TODO: have something better to close the consigned connection when tunnel is closed or vice versa
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

func handleConn(c net.Conn, proxy *net.TCPAddr) {
	defer c.Close()
	logger := slog.With("src", c.RemoteAddr())
	dst, err := GetOriginalDst(c.(*net.TCPConn))
	if err != nil {
		slog.Error("failed to get connection original destination", "error", err)
		return
	}
	logger = logger.With("original_dst", dst)
	var conn ConsignedConn
	switch dst.Port {
	case 443:
		conn = &TlsConn{Conn: c, DstAddr: dst}
	case 80:
		conn = &HttpConn{Conn: c, DstAddr: dst}
	default:
		logger.Error(fmt.Sprintf("unknown destination port: %d", dst.Port))
		return
	}
	host, err := conn.Host()
	if err != nil {
		logger.Error("failed to preread host from connection", "error", err)
	}
	logger = logger.With("host", host)
	logger.Info("forward connection to http proxy")
	tunnel, err := net.DialTCP("tcp", nil, proxy)
	if err != nil {
		logger.Error("failed to connect to proxy", "error", err)
		return
	}
	if err = conn.PrepareTunnel(tunnel); err != nil {
		logger.Error("failed to create proxy tunnel", "error", err)
	}
	forward(conn, tunnel, logger)
}

func main() {
	proxyAddr := flag.String("proxy", "", "upstream HTTP proxy address in the 'host:port' format")
	flag.Parse()
	listenAddr := &net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: 8443}
	listener, err := net.ListenTCP("tcp", listenAddr)
	if err != nil {
		log.Fatalf("failed to listen on %s", listenAddr.String())
	}
	slog.Info("start listening on 0.0.0.0:8443")
	proxy, err := net.ResolveTCPAddr("tcp", *proxyAddr)
	if err != nil {
		log.Fatalf("failed to resolve proxy address %q: %s", *proxyAddr, err)
	}
	slog.Info(fmt.Sprintf("start forwarding to proxy %s", proxy.String()))
	for {
		conn, err := listener.Accept()
		if err != nil {
			slog.Error("failed to accept connection", "error", err)
			continue
		}
		go handleConn(conn, proxy)
	}
}
