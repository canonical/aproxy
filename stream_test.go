package main

import (
	"bytes"
	"encoding/hex"
	"io"
	"net"
	"testing"
)

func TestPrereadConn(t *testing.T) {
	remote, local := net.Pipe()
	go remote.Write([]byte("hello, world"))
	preread := &PrereadConn{conn: local}
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
	preread.EndPreread()
	buf2 := make([]byte, 12)
	_, err = io.ReadFull(preread, buf2)
	if err != nil {
		t.Fatalf("Read failed after preread: %s", err)
	}
	if string(buf2) != "hello, world" {
		t.Fatalf("preread altered the read state: got %s", string(buf2))
	}
}

func TestNewHttpStream(t *testing.T) {
	remote, local := net.Pipe()
	payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n")
	go remote.Write(payload)
	s, err := NewHttpStream(local, &ConnInfo{
		src:         &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8443},
		dst:         &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
		originalDst: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 80},
	})
	if err != nil {
		t.Fatalf("NewHttpStream failed: %s", err)
	}
	if s.Host() != "example.com:80" {
		t.Fatalf("incorrect host in HttpStream, expect: \"example.com:80\", got: %#v", s.Host())
	}
	buf := make([]byte, len(payload))
	_, err = io.ReadFull(s, buf)
	if err != nil {
		t.Fatalf("HttpStream.Read failed: %s", err)
	}
	if !bytes.Equal(payload, buf) {
		t.Fatalf("HttpStream.Read failed, expect: %#v, got: %#v", string(payload), string(buf))
	}
}

func TestNewHttpStreamNonDefaultPort(t *testing.T) {
	remote, local := net.Pipe()
	payload := []byte("GET / HTTP/1.1\r\nHost: example.com:8080\r\nContent-Length: 0\r\n\r\n")
	go remote.Write(payload)
	s, err := NewHttpStream(local, &ConnInfo{
		src:         &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8443},
		dst:         &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
		originalDst: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080},
	})
	if err != nil {
		t.Fatalf("NewHttpStream failed: %s", err)
	}
	if s.Host() != "example.com:8080" {
		t.Fatalf("incorrect host in HttpStream, expect: \"example.com:8080\", got: %#v", s.Host())
	}
}

func TestNewTlsStream(t *testing.T) {
	remote, local := net.Pipe()
	// data obtained from https://gitlab.com/wireshark/wireshark/-/blob/master/test/captures/tls12-aes256gcm.pcap
	clientHello, _ := hex.DecodeString(
		"160301004f0100004b0303588e60d1d96bad5f1fcf0b8818466257d73385bdaaed0ac4bfd7228a6da059ad00000200a901000020" +
			"0005000501000000000000000e000c0000096c6f63616c686f7374ff01000100")
	go remote.Write(clientHello)
	s, err := NewTlsStream(local, &ConnInfo{
		src:         &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8443},
		dst:         &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
		originalDst: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443},
	})
	if err != nil {
		t.Fatalf("NewTlsStream failed: %s", err)
	}
	if s.Host() != "localhost:443" {
		t.Fatalf("incorrect host in TlsStream, expect: \"localhost:443\", got: %#v", s.Host())
	}
	buf := make([]byte, len(clientHello))
	_, err = io.ReadFull(s, buf)
	if err != nil {
		t.Fatalf("TlsStream.Read failed: %s", err)
	}
	if !bytes.Equal(clientHello, buf) {
		t.Fatalf("TlsStream.Read failed, expect: %#v, got: %#v", string(clientHello), string(buf))
	}
}

func TestNewTlsStreamWithoutSNI(t *testing.T) {
	remote, local := net.Pipe()
	clientHello, _ := hex.DecodeString("160301012801000124030315a03a6cbea1ff32d0fb9af5d6d94988e212b6bcf15a3e672ed" +
		"7d31f6d946edd20f8879d969a75d1da26560c92a942f13458a0cd2a96e690c0fa628ff6357119de0062130313021301cca9cca8ccaa" +
		"c030c02cc028c024c014c00a009f006b0039ff8500c400880081009d003d003500c00084c02fc02bc027c023c013c009009e0067003" +
		"300be0045009c003c002f00ba0041c011c00700050004c012c0080016000a00ff01000079002b000908030403030302030100330026" +
		"0024001d00203754ae4e94f3a5fb69709af119b982db1322c5da9299f7ce0da661a05f06ce35000b00020100000a000a0008001d001" +
		"700180019000d00180016080606010603080505010503080404010403020102030010000e000c02683208687474702f312e31")
	go remote.Write(clientHello)
	s, err := NewTlsStream(local, &ConnInfo{
		src:         &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8443},
		dst:         &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
		originalDst: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443},
	})
	if err != nil {
		t.Fatalf("NewTlsStream failed: %s", err)
	}
	if s.Host() != "" {
		t.Fatalf("incorrect host in TlsStream, expect: \"\", got: %#v", s.Host())
	}
}

func TestNewTlsStreamNonDefaultPort(t *testing.T) {
	remote, local := net.Pipe()
	// data obtained from https://gitlab.com/wireshark/wireshark/-/blob/master/test/captures/tls12-aes256gcm.pcap
	clientHello, _ := hex.DecodeString(
		"160301004f0100004b0303588e60d1d96bad5f1fcf0b8818466257d73385bdaaed0ac4bfd7228a6da059ad00000200a901000020" +
			"0005000501000000000000000e000c0000096c6f63616c686f7374ff01000100")
	go remote.Write(clientHello)
	s, err := NewTlsStream(local, &ConnInfo{
		src:         &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8443},
		dst:         &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
		originalDst: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1443},
	})
	if err != nil {
		t.Fatalf("NewTlsStream failed: %s", err)
	}
	if s.Host() != "localhost:1443" {
		t.Fatalf("incorrect host in TlsStream, expect: \"localhost:1443\", got: %#v", s.Host())
	}
}
