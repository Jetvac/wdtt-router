//go:build !linux

package link

import "net"

func setDontFragment(*net.UDPConn) {}

func isMsgSize(error) bool { return false }
