package main

import (
	"net"
)

// ConsignedConn wraps the PrereadConn and provides some slots to attach information related to the connection.
type ConsignedConn struct {
	*PrereadConn
	OriginalDst *net.TCPAddr
	Host        string
}

// NewConsignedConn creates a new *ConsignedConn from the connection.
func NewConsignedConn(conn net.Conn) *ConsignedConn {
	return &ConsignedConn{
		PrereadConn: NewPrereadConn(conn),
		OriginalDst: nil,
		Host:        "",
	}
}
