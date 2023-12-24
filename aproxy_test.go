package main

import (
	"encoding/hex"
	"net"
	"testing"
)

func TestPrereadSNI(t *testing.T) {
	remote, local := net.Pipe()
	// data obtained from https://gitlab.com/wireshark/wireshark/-/blob/master/test/captures/tls12-aes256gcm.pcap
	clientHello, _ := hex.DecodeString("160301004f0100004b0303588e60d1d96bad5f1fcf0b8818466257d73385bdaaed0ac4bfd7228a6da059ad00000200a9010000200005000501000000000000000e000c0000096c6f63616c686f7374ff01000100")
	go remote.Write(clientHello)
	sni, err := PrereadSNI(NewPrereadConn(local))
	if err != nil {
		t.Fatalf("PrereadSNI failed: %s", err)
	}
	if sni != "localhost" {
		t.Fatalf("PrereadSNI returns incorrect SNI: expected: localhost, got %s", sni)
	}
}

func TestPrereadHttpHost(t *testing.T) {
	remote, local := net.Pipe()
	go remote.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n"))
	host, err := PrereadHTTPHost(NewPrereadConn(local))
	if err != nil {
		t.Fatalf("PrereadHTTPHost failed: %s", err)
	}
	if host != "example.com" {
		t.Fatalf("PrereadHTTPHost returns incorrect host: expected: example.com, got %s", host)
	}
}

func Test_parseProxyUrl(t *testing.T) {
	tests := []struct {
		name     string
		proxyUrl string
		want     string
		wantErr  bool
	}{
		{"host and port", "http://example.com:123", "example.com:123", false},
		{"ip and port", "http://10.30.74.14:8888", "10.30.74.14:8888", false},
		// surprisingly this is correct, at least for curl
		{"with path", "http://example.com:1234/test", "example.com:1234", false},
		{"no port", "http://example.com", "", true},
		{"no protocol", "example.com:1234", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseProxyUrl(tt.proxyUrl)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseProxyUrl() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseProxyUrl() got = %v, want %v", got, tt.want)
			}
		})
	}
}
