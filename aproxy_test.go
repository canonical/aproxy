package main

import (
	"bufio"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"sync"
	"testing"
)

func TestTlsConn(t *testing.T) {
	ccRemote, ccLocal := net.Pipe()
	tc := TlsConn{
		Conn: ccLocal,
		DstAddr: &net.TCPAddr{
			IP:   make(net.IP, 4),
			Port: 443,
		},
	}
	// data obtained from https://gitlab.com/wireshark/wireshark/-/blob/master/test/captures/tls12-aes256gcm.pcap
	clientHello, _ := hex.DecodeString("160301004f0100004b0303588e60d1d96bad5f1fcf0b8818466257d73385bdaaed0ac4bfd7228a6da059ad00000200a9010000200005000501000000000000000e000c0000096c6f63616c686f7374ff01000100")
	go ccRemote.Write(clientHello)
	host, err := tc.Host()
	if host != "localhost:443" || err != nil {
		t.Fatalf("failed to preread SNI from TLS client hello")
	}
	proxyRemote, proxyLocal := net.Pipe()
	var proxyErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		connectRequest, err := http.ReadRequest(bufio.NewReaderSize(proxyRemote, 0))
		if err != nil {
			proxyErr = err
			return
		}
		if connectRequest.Method != "CONNECT" {
			proxyErr = errors.New("proxy didn't receive HTTP CONNECT request")
			return
		}
		_, _ = proxyRemote.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		clientHelloRecv := make([]byte, len(clientHello))
		n, err := proxyRemote.Read(clientHelloRecv)
		if n != len(clientHelloRecv) || err != nil {
			proxyErr = errors.New("proxy didn't receive replayed TLS client hello")
		}
	}()
	err = tc.PrepareTunnel(proxyLocal)
	wg.Wait()
	if proxyErr != nil {
		t.Fatalf(proxyErr.Error())
	}
	if err != nil {
		t.Fatalf("failed to prepare proxy tunnel connection: %s", err)
	}
}

func TestHttpConn(t *testing.T) {
	ccRemote, ccLocal := net.Pipe()
	hc := HttpConn{
		Conn: ccLocal,
		DstAddr: &net.TCPAddr{
			IP:   make(net.IP, 4),
			Port: 80,
		},
	}
	go ccRemote.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n"))
	host, err := hc.Host()
	if host != "example.com:80" || err != nil {
		t.Fatalf("failed to preread Host header from HTTP request")
	}
	proxyRemote, proxyLocal := net.Pipe()
	var proxyErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		req, err := http.ReadRequest(bufio.NewReaderSize(proxyRemote, 0))
		if err != nil {
			proxyErr = err
			return
		}
		if req.Method != "GET" || req.URL.String() != "http://example.com/" {
			proxyErr = errors.New("proxy didn't receive correct HTTP request")
			return
		}
	}()
	if err := hc.PrepareTunnel(proxyLocal); err != nil {
		t.Fatalf("failed to prepare proxy tunnel connection: %s", err)
	}
	wg.Wait()
	if proxyErr != nil {
		t.Fatalf(proxyErr.Error())
	}
}
