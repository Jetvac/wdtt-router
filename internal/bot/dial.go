package bot

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"
)

// In some networks the DNS answer for api.telegram.org is tampered with
// (for example, only an unreachable IPv6 address comes back). The bot
// therefore resolves it over DNS-over-HTTPS and falls back to Telegram's
// published IPv4 addresses. TLS still verifies the api.telegram.org
// certificate, so a wrong address cannot impersonate Telegram.
const telegramHost = "api.telegram.org"

var telegramFallback = []string{"149.154.167.220", "149.154.166.110", "149.154.175.50"}

var (
	dohMu      sync.Mutex
	dohAddrs   []string
	dohExpires time.Time
)

func telegramAddrs(ctx context.Context) []string {
	dohMu.Lock()
	defer dohMu.Unlock()
	if time.Now().Before(dohExpires) && len(dohAddrs) > 0 {
		return dohAddrs
	}
	addrs := resolveDoH(ctx, telegramHost)
	if len(addrs) == 0 {
		return telegramFallback
	}
	dohAddrs, dohExpires = addrs, time.Now().Add(time.Hour)
	return addrs
}

// resolveDoH asks Cloudflare's DNS-over-HTTPS (by IP, no DNS needed).
func resolveDoH(ctx context.Context, name string) []string {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://1.1.1.1/dns-query?type=A&name="+name, nil)
	req.Header.Set("Accept", "application/dns-json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var r struct {
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if json.NewDecoder(resp.Body).Decode(&r) != nil {
		return nil
	}
	var out []string
	for _, a := range r.Answer {
		if ip := net.ParseIP(a.Data); a.Type == 1 && ip != nil && ip.To4() != nil {
			out = append(out, a.Data)
		}
	}
	return out
}

var (
	goodMu sync.Mutex
	good   string // the last address that worked
)

// candidates: the address that worked last, then the resolved ones, then
// the published ones. Some networks block only some of Telegram's
// addresses, so trying several in turn finds one that works.
func candidates(ctx context.Context) []string {
	goodMu.Lock()
	first := good
	goodMu.Unlock()
	seen := map[string]bool{}
	var out []string
	for _, ip := range append(append([]string{first}, telegramAddrs(ctx)...), telegramFallback...) {
		if ip != "" && !seen[ip] {
			seen[ip] = true
			out = append(out, ip)
		}
	}
	return out
}

func dialTelegram(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	d := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	if host != telegramHost {
		return d.DialContext(ctx, network, addr)
	}
	last := errors.New("api.telegram.org is unreachable")
	for _, ip := range candidates(ctx) {
		c, err := d.DialContext(ctx, "tcp4", net.JoinHostPort(ip, port))
		if err == nil {
			goodMu.Lock()
			good = ip
			goodMu.Unlock()
			return c, nil
		}
		last = err
	}
	// Then whatever the system resolver says.
	if c, err := d.DialContext(ctx, network, addr); err == nil {
		return c, nil
	}
	return nil, last
}
