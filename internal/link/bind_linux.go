package link

import (
	"errors"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// setDontFragment has the kernel refuse datagrams over the interface's
// MTU (EMSGSIZE) instead of fragmenting them: the link cuts messages into
// parts itself and never sends IP fragments into Cloudflare.
func setDontFragment(c *net.UDPConn) {
	rc, err := c.SyscallConn()
	if err != nil {
		return
	}
	_ = rc.Control(func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO)
	})
}

func isMsgSize(err error) bool { return errors.Is(err, syscall.EMSGSIZE) }
