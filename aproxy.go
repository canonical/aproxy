package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
)

var version = "1.0.0"

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

// HandleTLSConn handles one incoming TCP connection
func HandleTLSConn(ctx context.Context, consigned *ConsignedConn, forwarder *Forwarder) {
	sni, err := PrereadSNI(consigned.PrereadConn)
	if err != nil {
		logger.ErrorContext(ctx, "failed to preread SNI from connection", "error", err)
		return
	}
	host := fmt.Sprintf("%s:%d", sni, consigned.OriginalDst.Port)
	consigned.Host = host
	forwarder.ForwardHTTPS(ctx, consigned)
}

// HandleHTTPConn handles one incoming HTTP connection
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
		HandleTLSConn(ctx, consigned, forwarder)
	case 80:
		HandleHTTPConn(ctx, consigned, forwarder)
	default:
		logger.ErrorContext(ctx, fmt.Sprintf("unknown destination port: %d", dst.Port))
		return
	}
}

func main() {
	httpProxyFlag := flag.String("http-proxy", "", "upstream HTTP proxy URL")
	httpsProxyFlag := flag.String("https-proxy", "", "upstream HTTPS proxy URL")
	listenFlag := flag.String("listen", ":8443", "the address and port on which the server will listen")
	fwmarkFlag := flag.Uint("fwmark", 0, "set firewall mark for outgoing traffic")
	flag.Parse()
	httpProxy := *httpProxyFlag
	httpsProxy := *httpsProxyFlag
	forwarder, err := NewForwarder(*httpProxyFlag, *httpsProxyFlag, *fwmarkFlag)
	if err != nil {
		log.Fatal(err)
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
