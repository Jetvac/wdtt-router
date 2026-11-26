//go:build !linux

package link

import (
	"context"
	"errors"
	"net"
)

// Run is the tunnel service; it runs on Linux servers only.
func Run(context.Context, string, string) error {
	return errors.New("the chain tunnel runs on Linux only")
}

// MarkedDialer: marks exist on Linux only; elsewhere a plain dialer.
func MarkedDialer(int) func(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext
}
