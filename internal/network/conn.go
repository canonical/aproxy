// Package network provides a TCP connection wrapper that adds preread functionality.
// During the preread phase, the read operations are recorded and can be reverted
// using the Rewind function and the same data can be read again from the beginning.
package network

import (
	"errors"
	"io"
	"math"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
)

const defaultPrereadLimit = 64 * 1024

var ErrPrereadLimitExceeded = errors.New("exceed preread limit")

type ConnMetrics interface {
	ObserveWrite(n int, err error)
	ObserveRead(n int, err error)
}

type Conn struct {
	net.Conn

	prereadLimit  int
	prereadEnd    atomic.Bool
	prereadCursor int
	prereadBuf    []byte

	metrics ConnMetrics

	mu sync.Mutex

	// Connection attributes which can be set by the user
	// The conn package doesn't use these attributes
	Source              net.Addr
	Destination         net.Addr
	OriginalDestination net.Addr
	Host                string
}

func (c *Conn) read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if c.metrics != nil {
		c.metrics.ObserveRead(n, err)
	}
	return n, err
}

// Read reads from the connection.
// During preread phase, data read from the underlying TCP connection are recorded
// and can be read again as if it hasn't been read before using the Rewind function.
// A zero-length read during the preread phase just returns without touching the
// underlying TCP connection.
// Conn starts with preread enabled and the preread phase can be ended with the
// EndPreread method.
func (c *Conn) Read(b []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	prereadEnd := c.prereadEnd.Load()
	limit := c.prereadLimit - c.prereadCursor
	if prereadEnd {
		limit = math.MaxInt
	}
	rb := b[:min(limit, len(b))]
	if len(rb) == 0 && len(b) != 0 {
		return 0, ErrPrereadLimitExceeded
	}
	reuse := min(len(rb), max(len(c.prereadBuf)-c.prereadCursor, 0))
	copy(rb, c.prereadBuf[c.prereadCursor:c.prereadCursor+reuse])
	c.prereadCursor += reuse
	if reuse > 0 || (len(b) == 0 && !prereadEnd) {
		return reuse, nil
	}
	n, err = c.read(rb)
	if !prereadEnd {
		c.prereadBuf = append(c.prereadBuf, rb[:n]...)
		c.prereadCursor += n
	} else {
		if c.prereadCursor >= len(c.prereadBuf) {
			c.prereadCursor = 0
			c.prereadBuf = nil
		}
	}
	return n + reuse, err
}

// ReadFrom is not supported.
func (c *Conn) ReadFrom(r io.Reader) (n int64, err error) {
	panic("not supported")
}

func (c *Conn) write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)
	if c.metrics != nil {
		c.metrics.ObserveWrite(n, err)
	}
	return n, err
}

// Write writes to the connection.
// Write is not allowed during the preread phase.
func (c *Conn) Write(b []byte) (n int, err error) {
	if !c.prereadEnd.Load() {
		panic("write while in preread")
	}
	return c.write(b)
}

// WriteTo is not supported.
func (c *Conn) WriteTo(w io.Writer) (n int64, err error) {
	panic("not supported")
}

// Rewind undoes the reads performed so far, and allows the connection to be
// read from the beginning again.
// Rewind will panic if called after the preread phase.
func (c *Conn) Rewind() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.prereadEnd.Load() {
		panic("attempt to rewind while preread ended")
	}
	c.prereadCursor = 0
}

// EndPreread ends the preread phase and rewinds the connection.
// EndPreread can only be called once.
func (c *Conn) EndPreread() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.prereadEnd.Load() {
		return
	}
	c.prereadEnd.Store(true)
	c.prereadCursor = 0
}

type Option func(*Conn)

// WithPrereadLimit sets a limit on how many bytes can be read during the preread phase.
// A Read operation exceeding the preread limit will cause an ErrPrereadLimitExceeded error.
func WithPrereadLimit(n int) Option {
	if n <= 0 {
		panic("invalid preread limit")
	}
	return func(c *Conn) {
		c.prereadLimit = n
	}
}

// WithMetrics reports socket activity to observability.
func WithMetrics(m ConnMetrics) Option {
	if m == nil {
		panic("nil metrics")
	}
	if v := reflect.ValueOf(m); v.Kind() == reflect.Pointer && v.IsNil() {
		panic("nil metrics")
	}
	return func(c *Conn) {
		c.metrics = m
	}
}

// New wraps the input TCP connection and returns a connection started in the
// preread phase.
func New(c net.Conn, options ...Option) *Conn {
	conn := &Conn{
		Conn:         c,
		prereadLimit: defaultPrereadLimit,
	}
	for _, option := range options {
		option(conn)
	}
	return conn
}
