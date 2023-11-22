//go:build linux

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

func GetsockoptIPv4OriginalDst(fd, level, opt int) (*net.TCPAddr, error) {
	var sockaddr [16]byte
	size := 16
	_, _, e := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(level),
		uintptr(opt),
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
