package agent

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Jetvac/wdtt-router/internal/spec"
)

// socksDial opens a TCP connection through the entry's local SOCKS inbound.
func socksDial(ctx context.Context, e *spec.EntrySpec, cmd byte, host string, port int) (net.Conn, *net.UDPAddr, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(e.SocksPort)))
	if err != nil {
		return nil, nil, err
	}
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	fail := func(err error) (net.Conn, *net.UDPAddr, error) { c.Close(); return nil, nil, err }
	if _, err := c.Write([]byte{5, 1, 2}); err != nil {
		return fail(err)
	}
	buf := make([]byte, 262)
	if _, err := io.ReadFull(c, buf[:2]); err != nil || buf[1] != 2 {
		return fail(errors.New("SOCKS authentication method rejected"))
	}
	auth := []byte{1, byte(len(e.SocksUser))}
	auth = append(auth, e.SocksUser...)
	auth = append(auth, byte(len(e.SocksPass)))
	auth = append(auth, e.SocksPass...)
	if _, err := c.Write(auth); err != nil {
		return fail(err)
	}
	if _, err := io.ReadFull(c, buf[:2]); err != nil || buf[1] != 0 {
		return fail(errors.New("SOCKS authentication failed"))
	}
	req := []byte{5, cmd, 0, 3, byte(len(host))}
	req = append(req, host...)
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := c.Write(req); err != nil {
		return fail(err)
	}
	if _, err := io.ReadFull(c, buf[:4]); err != nil {
		return fail(err)
	}
	if buf[1] != 0 {
		return fail(fmt.Errorf("chain refused the connection (SOCKS code %d)", buf[1]))
	}
	var ip net.IP
	switch buf[3] {
	case 1:
		if _, err := io.ReadFull(c, buf[:4]); err != nil {
			return fail(err)
		}
		ip = net.IP(append([]byte{}, buf[:4]...))
	case 4:
		if _, err := io.ReadFull(c, buf[:16]); err != nil {
			return fail(err)
		}
		ip = net.IP(append([]byte{}, buf[:16]...))
	case 3:
		if _, err := io.ReadFull(c, buf[:1]); err != nil {
			return fail(err)
		}
		if _, err := io.ReadFull(c, buf[:buf[0]]); err != nil {
			return fail(err)
		}
		ip = net.IPv4(127, 0, 0, 1)
	}
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return fail(err)
	}
	bound := &net.UDPAddr{IP: ip, Port: int(binary.BigEndian.Uint16(buf[:2]))}
	if bound.IP.IsUnspecified() {
		bound.IP = net.IPv4(127, 0, 0, 1)
	}
	return c, bound, nil
}

// Probe checks the whole chain from the entry: a TCP request to Cloudflare's
// trace endpoint (reports the public IP seen on the Internet) and a UDP DNS
// query to 1.1.1.1 carried through the chain.
func Probe(ctx context.Context) spec.ProbeResult {
	r := spec.ProbeResult{}
	s, _, err := loadSaved()
	if err != nil || s.Entry == nil {
		r.Error = "this server is not the configured entry"
		return r
	}
	if len(s.Entry.Chain) == 0 {
		r.Error = "the chain has no downstream servers"
		return r
	}
	start := time.Now()
	raw, _, err := socksDial(ctx, s.Entry, 1, "one.one.one.one", 443)
	if err != nil {
		r.Error = "TCP through chain: " + err.Error()
		if errors.Is(err, syscall.ECONNREFUSED) {
			addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(s.Entry.SocksPort))
			r.Error += ". " + xrayDiagnosis(ctx, addr)
		}
		return r
	}
	c := tls.Client(raw, &tls.Config{ServerName: "one.one.one.one", MinVersion: tls.VersionTLS12})
	if err := c.HandshakeContext(ctx); err != nil {
		raw.Close()
		r.Error = "TLS through chain: " + err.Error()
		return r
	}
	_, _ = c.Write([]byte("GET /cdn-cgi/trace HTTP/1.1\r\nHost: one.one.one.one\r\nConnection: close\r\nUser-Agent: wdtt-router\r\n\r\n"))
	body, _ := io.ReadAll(io.LimitReader(c, 8192))
	c.Close()
	r.TCPms = time.Since(start).Milliseconds()
	sc := bufio.NewScanner(strings.NewReader(string(body)))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "ip="); ok {
			r.ExitIP = v
		}
		if v, ok := strings.CutPrefix(sc.Text(), "colo="); ok {
			r.Colo = v
		}
	}
	if r.ExitIP == "" {
		r.Error = "TCP through chain: unexpected response"
		return r
	}
	r.UDPms, err = probeUDP(ctx, s.Entry)
	if err != nil {
		r.Error = "UDP through chain: " + err.Error()
		return r
	}
	r.UDPOK = true
	r.OK = true
	return r
}

func probeUDP(ctx context.Context, e *spec.EntrySpec) (int64, error) {
	ctrl, relay, err := socksDial(ctx, e, 3, "0.0.0.0", 0)
	if err != nil {
		return 0, err
	}
	defer ctrl.Close()
	u, err := net.DialUDP("udp", nil, relay)
	if err != nil {
		return 0, err
	}
	defer u.Close()
	// DNS query: A record for one.one.one.one, ID 0x5754.
	q := []byte{0x57, 0x54, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split("one.one.one.one", ".") {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	q = append(q, 0, 0, 1, 0, 1)
	pkt := append([]byte{0, 0, 0, 1, 1, 1, 1, 1, 0, 53}, q...)
	buf := make([]byte, 1500)
	for attempt := 0; attempt < 3; attempt++ {
		start := time.Now() // time only the attempt that succeeds
		if _, err := u.Write(pkt); err != nil {
			return 0, err
		}
		_ = u.SetReadDeadline(time.Now().Add(4 * time.Second))
		n, err := u.Read(buf)
		if err != nil {
			continue
		}
		if n > 12 && buf[10] == 0x57 && buf[11] == 0x54 {
			return time.Since(start).Milliseconds(), nil
		}
	}
	return 0, errors.New("no DNS answer over UDP")
}
