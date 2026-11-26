package link

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"time"
)

// dnsQuery builds a query for name's A record.
func dnsQuery(id uint16, name string) []byte {
	q := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(q, id)
	q[2] = 1 // recursion desired
	q[5] = 1 // one question
	for _, l := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	return append(q, 0, 0, 1, 0, 1) // root, type A, class IN
}

// dnsAnswered checks a response to query id: a response, no error.
func dnsAnswered(b []byte, id uint16) bool {
	return len(b) >= 12 && binary.BigEndian.Uint16(b) == id && b[2]&0x80 != 0 && b[3]&0x0f == 0
}

// DNSCheck asks server (ip:53) for name through a socket made by dial
// (which routes it through the tunnel) and returns the round trip.
func DNSCheck(ctx context.Context, dial func(ctx context.Context, network, addr string) (net.Conn, error), server, name string) (time.Duration, error) {
	c, err := dial(ctx, "udp4", server)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	if d, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(d)
	}
	var idb [2]byte
	_, _ = rand.Read(idb[:])
	id := binary.BigEndian.Uint16(idb[:])
	start := time.Now()
	if _, err := c.Write(dnsQuery(id, name)); err != nil {
		return 0, err
	}
	buf := make([]byte, 1500)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return 0, err
		}
		if dnsAnswered(buf[:n], id) {
			return time.Since(start), nil
		}
		if n >= 2 && binary.BigEndian.Uint16(buf) == id {
			return 0, errors.New("DNS error response")
		}
	}
}
