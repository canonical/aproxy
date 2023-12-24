package main

import (
	"net"
	"sync"
)

// PrereadConn is a wrapper around net.Conn that supports pre-reading from the underlying connection.
// Any Read before the EndPreread can be undone and read again by calling the EndPreread function.
type PrereadConn struct {
	ended bool
	buf   []byte
	mu    sync.Mutex
	conn  net.Conn
}

// EndPreread ends the pre-reading phase. Any Read before will be undone and data in the stream can be read again.
// EndPreread can be only called once.
func (c *PrereadConn) EndPreread() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ended {
		panic("call EndPreread after preread has ended or hasn't started")
	}
	c.ended = true
}

// Read reads from the underlying connection. Read during the pre-reading phase can be undone by EndPreread.
func (c *PrereadConn) Read(p []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ended {
		n = copy(p, c.buf)
		bufLen := len(c.buf)
		c.buf = c.buf[n:]
		if n == len(p) || (bufLen > 0 && bufLen == n) {
			return n, nil
		}
		rn, err := c.conn.Read(p[n:])
		return rn + n, err
	} else {
		n, err = c.conn.Read(p)
		c.buf = append(c.buf, p[:n]...)
		return n, err
	}
}

// Write writes data to the underlying connection.
func (c *PrereadConn) Write(p []byte) (n int, err error) {
	return c.conn.Write(p)
}

// NewPrereadConn wraps the network connection and return a *PrereadConn.
// It's recommended to not touch the original connection after wrapped.
func NewPrereadConn(conn net.Conn) *PrereadConn {
	return &PrereadConn{conn: conn}
}

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
