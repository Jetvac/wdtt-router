package wdtt

import (
	"context"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// listenUDP opens n sockets on the same port with SO_REUSEPORT. The kernel
// hashes each remote address to one socket, so every client connection is
// served by one read loop and the load spreads over CPU cores.
func listenUDP(ctx context.Context, addr string, n int) ([]*net.UDPConn, error) {
	lc := net.ListenConfig{Control: func(_, _ string, rc syscall.RawConn) error {
		var serr error
		err := rc.Control(func(fd uintptr) {
			serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
		})
		if err != nil {
			return err
		}
		return serr
	}}
	var out []*net.UDPConn
	for i := 0; i < n; i++ {
		pc, err := lc.ListenPacket(ctx, "udp", addr)
		if err != nil {
			for _, c := range out {
				c.Close()
			}
			return nil, err
		}
		out = append(out, pc.(*net.UDPConn))
	}
	return out, nil
}
