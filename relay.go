package main

import (
	"errors"
	"io"
	"net"
	"time"
)

type tcpForwarder struct {
	Fwmark       uint32
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

func (f *tcpForwarder) copyBuffer(dst net.Conn, src net.Conn) (written int64, err error) {
	buf := make([]byte, 32*1024)
	for {
		err = src.SetReadDeadline(time.Now().Add(f.ReadTimeout))
		if err != nil {
			break
		}
		nr, er := src.Read(buf)
		if nr > 0 {
			err = src.SetWriteDeadline(time.Now().Add(f.ReadTimeout))
			if err != nil {
				break
			}
			nw, ew := dst.Write(buf[0:nr])
			if nw < 0 || nr < nw {
				nw = 0
				if ew == nil {
					ew = errors.New("invalid write result")
				}
			}
			written += int64(nw)
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return written, err
}
