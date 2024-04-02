package main

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
)

func TestVerifyProxyUrl(t *testing.T) {
	tests := []struct {
		name     string
		proxyUrl string
		wantErr  bool
	}{
		{"host and port", "http://example.com:123", false},
		{"ip and port", "http://10.30.74.14:8888", false},
		// surprisingly this is okay, at least for curl
		{"with path", "http://example.com:1234/test", false},
		{"no port", "http://example.com", true},
		{"no protocol", "example.com:1234", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyProxyUrl(tt.proxyUrl)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseProxyUrl() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestForwarderForwardHTTP(t *testing.T) {
	egressIn, egressOut := net.Pipe()
	ingressIn, ingressOut := net.Pipe()
	f := Forwarder{
		httpProxy: "http://http-proxy:1234",
		dialFunc: func(f *Forwarder, addr string) (net.Conn, error) {
			if addr != "http-proxy:1234" {
				panic(addr)
			}
			return egressIn, nil
		},
	}
	wg := sync.WaitGroup{}
	defer func() {
		_ = egressIn.Close()
		_ = egressOut.Close()
		_ = ingressIn.Close()
		_ = ingressOut.Close()
		wg.Wait()
	}()
	wg.Add(1)
	go func() {
		f.ForwardHTTP(context.Background(), &ConsignedConn{
			PrereadConn: NewPrereadConn(ingressOut),
			OriginalDst: &net.TCPAddr{},
			Host:        "example.com",
		})
		wg.Done()
	}()
	wg.Add(1)
	go func() {
		_, _ = ingressIn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.4.0\r\n\r\n"))
		wg.Done()
	}()
	buf := make([]byte, 1000)
	n, _ := egressOut.Read(buf)
	expected := "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.4.0\r\nConnection: close\r\n\r\n"
	got := string(buf[:n])
	if expected != got {
		t.Fatalf("expected HTTP request sent by aproxy %#v, got %#v", expected, got)
	}
	wg.Add(1)
	go func() {
		_, _ = egressOut.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
		wg.Done()
	}()
	expected = "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
	n, _ = io.ReadAtLeast(ingressIn, buf, len(expected))
	got = string(buf[:n])
	if expected != got {
		t.Fatalf("expected HTTP response sent by aproxy %#v, got %#v", expected, got)
	}
}

func TestForwarderForwardHTTPS(t *testing.T) {
	egressIn, egressOut := net.Pipe()
	ingressIn, ingressOut := net.Pipe()
	f := Forwarder{
		httpsProxy: "http://http-proxy:1234",
		dialFunc: func(f *Forwarder, addr string) (net.Conn, error) {
			if addr != "http-proxy:1234" {
				panic(addr)
			}
			return egressIn, nil
		},
	}
	wg := sync.WaitGroup{}
	defer func() {
		_ = egressIn.Close()
		_ = egressOut.Close()
		_ = ingressIn.Close()
		_ = ingressOut.Close()
		wg.Wait()
	}()
	wg.Add(1)
	go func() {
		f.ForwardHTTPS(context.Background(), &ConsignedConn{
			PrereadConn: NewPrereadConn(ingressOut),
			OriginalDst: &net.TCPAddr{},
			Host:        "example.com",
		})
		wg.Done()
	}()
	expected := "CONNECT example.com HTTP/1.1\r\nHost: example.com\r\nUser-Agent: aproxy/1.0.0\r\n\r\n"
	buf := make([]byte, 1000)
	n, _ := egressOut.Read(buf)
	got := string(buf[:n])
	if expected != got {
		t.Fatalf("expected HTTP CONNECT request sent by aproxy %#v, got %#v", expected, got)
	}

	wg.Add(1)
	go func() {
		_, _ = ingressIn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.4.0\r\n\r\n"))
		wg.Done()
	}()
	n, _ = egressOut.Read(buf)
	expected = "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.4.0\r\nConnection: close\r\n\r\n"
	got = string(buf[:n])
	if expected != got {
		t.Fatalf("expected HTTP request sent by aproxy %#v, got %#v", expected, got)
	}
	wg.Add(1)
	go func() {
		_, _ = egressOut.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
		wg.Done()
	}()
	expected = "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
	n, _ = io.ReadAtLeast(ingressIn, buf, len(expected))
	got = string(buf[:n])
	if expected != got {
		t.Fatalf("expected HTTP response sent by aproxy %#v, got %#v", expected, got)
	}
}
