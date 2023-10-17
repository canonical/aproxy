package main

import (
	"encoding/hex"
	"io"
	"net"
	"testing"
)

func TestPrereadConn(t *testing.T) {
	remote, local := net.Pipe()
	go remote.Write([]byte("hello, world"))
	preread := &PrereadConn{conn: local}
	preread.StartPreread()
	buf := make([]byte, 5)
	_, err := preread.Read(buf)
	if err != nil {
		t.Fatalf("Read failed during preread: %s", err)
	}
	buf = make([]byte, 3)
	_, err = preread.Read(buf)
	if err != nil {
		t.Fatalf("Read failed during preread: %s", err)
	}
	preread.RestorePreread()
	buf2 := make([]byte, 12)
	_, err = io.ReadFull(preread, buf2)
	if err != nil {
		t.Fatalf("Read failed after preread: %s", err)
	}
	if string(buf2) != "hello, world" {
		t.Fatalf("preread altered the read state: got %s", string(buf2))
	}
}

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
	host, err := PrereadHttpHost(NewPrereadConn(local))
	if err != nil {
		t.Fatalf("PrereadHttpHost failed: %s", err)
	}
	if host != "example.com" {
		t.Fatalf("PrereadHttpHost returns incorrect host: expected: example.com, got %s", host)
	}
}
