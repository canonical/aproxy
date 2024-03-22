package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/crypto/cryptobyte"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
)

var version = "0.3.0"

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

// PrereadHTTPHost pre-reads the HTTP Host header from an HTTP connection.
func PrereadHTTPHost(conn *PrereadConn) (_ string, err error) {
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

func HandleTCPConn(ctx context.Context, consigned *ConsignedConn, forwarder *Forwarder) {
	sni, err := PrereadSNI(consigned.PrereadConn)
	if err != nil {
		logger.ErrorContext(ctx, "failed to preread SNI from connection", "error", err)
		return
	}
	host := fmt.Sprintf("%s:%d", sni, consigned.OriginalDst.Port)
	consigned.Host = host
	forwarder.ForwardHTTPS(ctx, consigned)
}

func HandleHTTPConn(ctx context.Context, consigned *ConsignedConn, forwarder *Forwarder) {
	host, err := PrereadHTTPHost(consigned.PrereadConn)
	if err != nil {
		logger.ErrorContext(ctx, "failed to preread HTTP host from connection", "error", err)
		return
	}
	if !strings.Contains(host, ":") {
		host = fmt.Sprintf("%s:%d", host, consigned.OriginalDst.Port)
	}
	consigned.Host = host
	forwarder.ForwardHTTP(ctx, consigned)
}

// HandleConn manages the incoming connections.
func HandleConn(ctx context.Context, conn *net.TCPConn, forwarder *Forwarder) {
	defer conn.Close()
	dst, err := GetSocketIPv4OriginalDst(conn)
	if err != nil {
		logger.ErrorContext(ctx, "failed to get connection original destination", "error", err)
		return
	}
	consigned := NewConsignedConn(conn)
	consigned.OriginalDst = dst
	ctx = ContextWithConsignedConn(ctx, consigned)
	switch dst.Port {
	case 443:
		HandleTCPConn(ctx, consigned, forwarder)
	case 80:
		HandleHTTPConn(ctx, consigned, forwarder)
	default:
		logger.ErrorContext(ctx, fmt.Sprintf("unknown destination port: %d", dst.Port))
		return
	}
}

// parseProxyUrl parses a proxy URL to a TCP address in the format of 'host:port'.
func parseProxyUrl(proxyUrl string) (string, error) {
	u, err := url.Parse(proxyUrl)
	if err == nil && u.Scheme != "http" {
		err = fmt.Errorf("proxy protocol %s not supported", u.Scheme)
	}
	if err == nil && u.User != nil {
		err = fmt.Errorf("proxy authencation not supported")
	}
	if err == nil && u.Port() == "" {
		err = fmt.Errorf("proxy URL doesn't contain a port")
	}
	if err != nil {
		return "", fmt.Errorf("failed to parse http proxy URL '%v': %w", proxyUrl, err)
	}
	return u.Host, nil
}

func main() {
	httpProxyFlag := flag.String("http-proxy", "", "upstream HTTP proxy URL")
	httpsProxyFlag := flag.String("https-proxy", "", "upstream HTTPS proxy URL")
	listenFlag := flag.String("listen", ":8443", "the address and port on which the server will listen")
	fwmarkFlag := flag.Uint("fwmark", 0, "set firewall mark for outgoing traffic")
	flag.Parse()
	httpProxy := *httpProxyFlag
	if httpProxy != "" {
		var err error
		httpProxy, err = parseProxyUrl(*httpProxyFlag)
		if err != nil {
			log.Fatalf("failed to parse http proxy: %s", err)
		}
	}
	httpsProxy := *httpsProxyFlag
	if httpsProxy != "" {
		var err error
		httpsProxy, err = parseProxyUrl(*httpsProxyFlag)
		if err != nil {
			log.Fatalf("failed to parse https proxy: %s", err)
		}
	}
	fwmark := uint32(*fwmarkFlag)
	forwarder := &Forwarder{
		fwmark:     fwmark,
		httpProxy:  httpProxy,
		httpsProxy: httpsProxy,
	}
	listenAddr := *listenFlag
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	listenConfig := new(net.ListenConfig)
	listener, err := listenConfig.Listen(ctx, "tcp", listenAddr)
	if err != nil {
		log.Fatalf("failed to listen on %#v", listenAddr)
	}
	logger.InfoContext(ctx, fmt.Sprintf("start listening on %s", listenAddr))
	if httpProxy != "" {
		logger.InfoContext(ctx, fmt.Sprintf("start forwarding HTTP connection to proxy %s", httpProxy))
	} else {
		logger.InfoContext(ctx, "start passthrough HTTP connection")
	}
	if httpsProxy != "" {
		logger.InfoContext(ctx, fmt.Sprintf("start forwarding HTTPS connection to proxy %s", httpsProxy))
	} else {
		logger.InfoContext(ctx, "start passthrough HTTPS connection")
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
			  logger.ErrorContext(ctx, "failed to accept connection", "error", err)
				continue
			}
			go HandleConn(conn, proxy)
		}
	}()
	<-ctx.Done()
	stop()
}
