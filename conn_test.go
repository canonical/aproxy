package main

import (
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
