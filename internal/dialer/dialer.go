//go:build linux

// Package dialer provides a customized dialer for aproxy.
package dialer

import (
	"fmt"
	"net"
	"syscall"
)

// Options customizes the dialer returned by New.
// The zero value is the default dialer setting.
type Options struct {
	// Fwmark sets the fwmark on all outgoing packets dialed by the dialer, so
	// they can be matched by netfilter rules.
	// This includes the DNS resolution connections during the dialing process.
	Fwmark uint32
}

// New creates a new customized network dialer based on the option.
// The option is optional, at most one should be given and the rest are ignored.
func New(option ...Options) *net.Dialer {
	if len(option) == 0 {
		option = append(option, Options{})
	}
	o := option[0]
	d := &net.Dialer{}
	if o.Fwmark != 0 {
		mark := o.Fwmark
		d.Control = func(network, address string, c syscall.RawConn) error {
			var sockErr error
			err := c.Control(func(fd uintptr) {
				sockErr = syscall.SetsockoptInt(
					int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(mark),
				)
			})
			if err != nil {
				return fmt.Errorf("raw control: %w", err)
			}
			if sockErr != nil {
				return fmt.Errorf("failed to set SO_MARK %d: %w", mark, sockErr)
			}
			return nil
		}
		d.Resolver = &net.Resolver{
			PreferGo: true,
			Dial:     d.DialContext,
		}
	}
	return d
}
