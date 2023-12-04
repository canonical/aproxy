//go:build linux

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

// GetSocketIPv4OriginalDst get the original destination address of a TCP connection before dstnat.
func GetSocketIPv4OriginalDst(conn *net.TCPConn) (*net.TCPAddr, error) {
	file, err := conn.File()
	defer file.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to get file decriptor of given TCP connection: %w", err)
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
		return nil, fmt.Errorf("getsockopt SO_ORIGINAL_DST failed: errno %d", e)
	}
	return &net.TCPAddr{
		IP:   sockaddr[4:8],
		Port: int(binary.BigEndian.Uint16(sockaddr[2:4])),
	}, nil
}
