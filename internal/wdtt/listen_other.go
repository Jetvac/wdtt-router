//go:build !linux

package wdtt

import (
	"context"
	"net"
)

func listenUDP(ctx context.Context, addr string, _ int) ([]*net.UDPConn, error) {
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}
	return []*net.UDPConn{pc.(*net.UDPConn)}, nil
}
