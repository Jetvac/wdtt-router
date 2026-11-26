package agent

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Jetvac/wdtt-router/internal/link"
	"github.com/Jetvac/wdtt-router/internal/spec"
)

const (
	speedHost  = "speed.cloudflare.com"
	speedBytes = 10_000_000
)

// probeLink runs the chain check through the tunnel: the entry's own
// connections carry LinkMark and follow the tunnel's route.
func probeLink(ctx context.Context, speed bool) *spec.LinkProbe {
	p := &spec.LinkProbe{}
	dial := link.MarkedDialer(LinkMark)
	dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	rtt, err := link.DNSCheck(dctx, dial, "1.1.1.1:53", "one.one.one.one")
	cancel()
	if err != nil {
		p.Error = "DNS через туннель: " + err.Error()
		return p
	}
	p.DNSms = rtt.Milliseconds()
	start := time.Now()
	tctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	raw, err := dial(tctx, "tcp", "1.1.1.1:443")
	if err != nil {
		p.Error = "TCP через туннель: " + err.Error()
		return p
	}
	body, err := httpsGet(tctx, raw, "one.one.one.one", "/cdn-cgi/trace", 8192)
	if err != nil {
		p.Error = "HTTPS через туннель: " + err.Error()
		return p
	}
	p.TCPms = time.Since(start).Milliseconds()
	for _, l := range strings.Split(string(body), "\n") {
		if v, ok := strings.CutPrefix(l, "ip="); ok {
			p.ExitIP = strings.TrimSpace(v)
		}
	}
	if p.ExitIP == "" {
		p.Error = "через туннель: неожиданный ответ"
		return p
	}
	p.OK = true
	if speed {
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dial(ctx, "udp4", "1.1.1.1:53")
		}}
		sctx, cancel := context.WithTimeout(ctx, 40*time.Second)
		defer cancel()
		ips, err := r.LookupIPAddr(sctx, speedHost)
		if err == nil && len(ips) > 0 {
			var c net.Conn
			if c, err = dial(sctx, "tcp", net.JoinHostPort(ips[0].IP.String(), "443")); err == nil {
				p.SpeedMbps, err = download(sctx, c)
			}
		}
		if err != nil {
			p.Error = "скорость через туннель: " + err.Error()
		}
	}
	return p
}

// speedXray downloads through the Xray chain.
func speedXray(ctx context.Context, e *spec.EntrySpec) (float64, error) {
	sctx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	c, _, err := socksDial(sctx, e, 1, speedHost, 443)
	if err != nil {
		return 0, err
	}
	return download(sctx, c)
}

// download fetches speedBytes from Cloudflare's speed test over raw (TLS
// on top) and returns the rate in Mbit/s.
func download(ctx context.Context, raw net.Conn) (float64, error) {
	start := time.Now()
	body, err := httpsGet(ctx, raw, speedHost, fmt.Sprintf("/__down?bytes=%d", speedBytes), speedBytes+1)
	if err != nil {
		return 0, err
	}
	if len(body) < speedBytes/2 {
		return 0, fmt.Errorf("only %d bytes", len(body))
	}
	return float64(len(body)) * 8 / time.Since(start).Seconds() / 1e6, nil
}

// httpsGet sends one GET over raw with TLS and returns up to limit bytes of
// the body.
func httpsGet(ctx context.Context, raw net.Conn, host, path string, limit int64) ([]byte, error) {
	defer raw.Close()
	if d, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(d)
	}
	c := tls.Client(raw, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	if err := c.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: wdtt-router\r\n\r\n", path, host)
	if _, err := c.Write([]byte(req)); err != nil {
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}
