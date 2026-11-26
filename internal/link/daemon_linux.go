package link

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/Jetvac/wdtt-router/internal/spec"
)

// viaTimeout is how long the kernel keeps client UDP on the tunnel without
// the service renewing it (Thresholds.Grace).
const viaTimeout = 5 * time.Second

// Run is the tunnel service ("wdtt-router link"). SIGHUP re-reads the
// entry's mode.
func Run(ctx context.Context, cfgPath, version string) error {
	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		return err
	}
	st := &statusWriter{path: cfg.StatusFile, base: spec.LinkStatus{Role: cfg.Role, Mode: cfg.Mode, Version: version, StartedAt: time.Now().Unix()}}
	if cfg.Role == "relay" {
		return runRelay(ctx, cfg, st)
	}
	mesh := &meshMTU{iface: cfg.MeshIface}
	mesh.refresh()
	go mesh.loop(ctx)

	psk, _ := decodeKey(cfg.PSK)
	var listen netip.AddrPort
	if cfg.Role == "exit" {
		listen = netip.MustParseAddrPort(cfg.Listen)
	}
	b := NewBind(psk, listen, mesh.datagram)
	_ = exec.Command("ip", "link", "del", cfg.Iface).Run()
	t, err := tun.CreateTUN(cfg.Iface, cfg.MTU)
	if err != nil {
		return fmt.Errorf("create %s: %w", cfg.Iface, err)
	}
	logger := &device.Logger{Verbosef: device.DiscardLogf, Errorf: func(f string, a ...any) {
		msg := fmt.Sprintf(f, a...)
		// The exit knows no endpoint until the entry's first handshake.
		if strings.Contains(msg, "no known endpoint") {
			return
		}
		log.Print("wireguard: " + msg)
	}}
	dev := device.NewDevice(t, b, logger)
	defer dev.Close()
	if err := dev.IpcSet(ipcConfig(cfg)); err != nil {
		return fmt.Errorf("wireguard: %w", err)
	}
	for _, args := range [][]string{
		{"addr", "replace", cfg.Address, "dev", cfg.Iface},
		{"link", "set", cfg.Iface, "mtu", strconv.Itoa(cfg.MTU), "up"},
	} {
		if err := ipcmd(args...); err != nil {
			return err
		}
	}
	_ = os.WriteFile("/proc/sys/net/ipv6/conf/"+cfg.Iface+"/disable_ipv6", []byte("1"), 0644)
	if err := dev.Up(); err != nil {
		return err
	}
	wg := &wgWatch{dev: dev}
	log.Printf("chain tunnel (%s) up on %s, datagrams up to %d bytes", cfg.Role, cfg.Iface, b.Datagram())
	if cfg.Role == "exit" {
		return runExit(ctx, cfg, b, wg, mesh, st)
	}
	return runEntry(ctx, cfg, cfgPath, dev, b, wg, mesh, st)
}

func runExit(ctx context.Context, cfg *Config, b *Bind, wg *wgWatch, mesh *meshMTU, st *statusWriter) error {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		// Replies from the Internet come in on the public interface and go
		// out through the tunnel: both forward (firewall rules allow only
		// that, see the agent).
		_ = setForwarding(cfg.Iface)
		_ = setForwarding(cfg.PublicIface)
		s := st.base
		s.Peer = addrString(b.Peer())
		s.HandshakeAge = wg.age()
		s.MeshMTU, s.Datagram = mesh.get(), b.Datagram()
		fillTraffic(&s, b)
		st.write(s)
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

func runEntry(ctx context.Context, cfg *Config, cfgPath string, dev *device.Device, b *Bind, wg *wgWatch, mesh *meshMTU, st *statusWriter) error {
	var mode atomic.Value
	mode.Store(cfg.Mode)
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				if c, err := LoadConfig(cfgPath); err == nil && c.Role == "entry" {
					mode.Store(c.Mode)
					log.Printf("mode: %s", c.Mode)
				}
			}
		}
	}()
	ensureTable(cfg)
	h := &Health{T: DefaultThresholds}
	if viaPresent(cfg) {
		h.Inherit()
		log.Printf("client UDP was on the tunnel: keeping it while the tunnel comes up")
	}
	servers := []string{"1.1.1.1:53", "9.9.9.9:53"}
	var turn atomic.Uint32
	e := &Entry{
		Bind: b, Peer: netip.MustParseAddrPort(cfg.Peer), Health: h,
		Allowed:   func() bool { return mode.Load() == "udp" },
		Handshake: wg.last,
		Route:     func(on bool) error { return route(cfg, on) },
		E2E: func(ctx context.Context) (time.Duration, error) {
			srv := servers[turn.Add(1)%uint32(len(servers))]
			return DNSCheck(ctx, MarkedDialer(cfg.Mark), srv, "cloudflare.com")
		},
		PeerRestarted: func() {
			if err := resetPeer(dev, cfg); err != nil {
				log.Printf("new handshake: %v", err)
			}
		},
		Log: log.Printf,
	}
	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		n := 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			if n++; n%3 == 0 {
				ensureTable(cfg)
			}
			now := time.Now()
			es := e.State(now)
			s := st.base
			s.Mode, _ = mode.Load().(string)
			s.Peer = cfg.Peer
			s.HandshakeAge = wg.age()
			s.Healthy = es.Health.Problem == ""
			s.Problem = es.Health.Problem
			s.Routing = es.Routed
			s.RTT50, s.RTT95 = ms(es.RTT50), ms(es.RTT95)
			s.Loss = es.Loss
			s.MeshMTU, s.Datagram, s.Confirmed = mesh.get(), es.Datagram, es.Confirmed
			if !es.E2EAt.IsZero() {
				s.DNSAt, s.DNSError = es.E2EAt.Unix(), es.E2EErr
				if es.E2EErr == "" {
					s.DNSms = ms(es.E2ERTT)
				}
			}
			if !es.Health.SwitchAt.IsZero() {
				s.SwitchAt, s.SwitchTo, s.SwitchWhy = es.Health.SwitchAt.Unix(), es.Health.SwitchTo, es.Health.SwitchWhy
			}
			if es.Health.HoldUntil.After(now) {
				s.HeldUntil = es.Health.HoldUntil.Unix()
			}
			s.RouteErr = es.RouteErr
			fillTraffic(&s, b)
			st.write(s)
		}
	}()
	return e.Run(ctx)
}

func runRelay(ctx context.Context, cfg *Config, st *statusWriter) error {
	r := &Relay{Listen: netip.MustParseAddrPort(cfg.Listen), Next: netip.MustParseAddrPort(cfg.Peer), Log: log.Printf}
	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			s := st.base
			s.Peer = addrString(r.Prev())
			s.HandshakeAge = -1
			s.RxBytes = r.Bytes.Load()
			st.write(s)
		}
	}()
	log.Printf("chain tunnel relay: %s → %s", cfg.Listen, cfg.Peer)
	return r.Run(ctx)
}

func fillTraffic(s *spec.LinkStatus, b *Bind) {
	s.RxBytes, s.TxBytes = b.RxBytes.Load(), b.TxBytes.Load()
	s.Split, s.Joined, s.Expired = b.Split.Load(), b.Joined.Load(), b.Expired()
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

func addrString(a netip.AddrPort) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}

// route puts client UDP of the WDTT interfaces on the tunnel (on) or
// leaves it to Xray. The set's elements expire by themselves unless
// renewed, so the kernel falls back to Xray when this service stops.
func route(cfg *Config, on bool) error {
	script := fmt.Sprintf("flush set inet %s %s\n", cfg.NftTable, cfg.NftSet)
	if on {
		if err := setForwarding(cfg.Iface); err != nil {
			return err
		}
		var els []string
		for _, ifc := range cfg.WDTTIfaces {
			if _, err := net.InterfaceByName(ifc); err != nil {
				continue // that WDTT server is restarting
			}
			if setForwarding(ifc) != nil {
				continue
			}
			els = append(els, fmt.Sprintf("%q timeout %ds", ifc, int(viaTimeout.Seconds())))
		}
		if len(els) > 0 {
			script += fmt.Sprintf("add element inet %s %s { %s }\n", cfg.NftTable, cfg.NftSet, strings.Join(els, ", "))
		}
	}
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// viaPresent: the previous run left client UDP on the tunnel.
func viaPresent(cfg *Config) bool {
	out, err := exec.Command("nft", "list", "set", "inet", cfg.NftTable, cfg.NftSet).Output()
	return err == nil && strings.Contains(string(out), "elements =")
}

// ensureTable keeps the tunnel's routes in its table: the interface, and
// below it a blackhole, so nothing meant for the tunnel ever falls through
// to the main table, even while the interface is gone (the agent installs
// the blackhole too).
func ensureTable(cfg *Config) {
	p, _ := netip.ParsePrefix(cfg.Address)
	tbl := strconv.Itoa(cfg.RouteTable)
	_ = ipcmd("route", "replace", "default", "dev", cfg.Iface, "src", p.Addr().String(), "table", tbl)
	_ = ipcmd("route", "replace", "blackhole", "default", "metric", "4096", "table", tbl)
}

func setForwarding(ifc string) error {
	p := "/proc/sys/net/ipv4/conf/" + ifc + "/forwarding"
	if b, err := os.ReadFile(p); err == nil && strings.TrimSpace(string(b)) == "1" {
		return nil
	}
	return os.WriteFile(p, []byte("1"), 0644)
}

func ipcmd(args ...string) error {
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %s", strings.Join(args, " "), strings.TrimSpace(string(out)))
	}
	return nil
}

// MarkedDialer dials with SO_MARK set, so the entry's own checks follow the
// tunnel's policy route.
func MarkedDialer(mark int) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) { serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, mark) })
		if err != nil {
			return err
		}
		return serr
	}}
	return d.DialContext
}

// meshMTU follows the MTU of Cloudflare's interface.
type meshMTU struct {
	iface string
	mtu   atomic.Int32
}

func (m *meshMTU) refresh() {
	b, err := os.ReadFile("/sys/class/net/" + m.iface + "/mtu")
	if err != nil {
		if m.mtu.Load() == 0 {
			m.mtu.Store(1280)
		}
		return
	}
	if v, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && v >= 576 {
		m.mtu.Store(int32(v))
	}
}

func (m *meshMTU) loop(ctx context.Context) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.refresh()
		}
	}
}

func (m *meshMTU) get() int      { return int(m.mtu.Load()) }
func (m *meshMTU) datagram() int { return m.get() - 28 }

// wgWatch reads WireGuard's state of the one peer, at most once a second.
type wgWatch struct {
	dev *device.Device
	mu  sync.Mutex
	at  time.Time
	hs  time.Time
}

func (w *wgWatch) last() time.Time {
	w.mu.Lock()
	defer w.mu.Unlock()
	if time.Since(w.at) < time.Second {
		return w.hs
	}
	w.at = time.Now()
	s, err := w.dev.IpcGet()
	if err != nil {
		return w.hs
	}
	var sec, nsec int64
	for _, l := range strings.Split(s, "\n") {
		k, v, _ := strings.Cut(l, "=")
		switch k {
		case "last_handshake_time_sec":
			sec, _ = strconv.ParseInt(v, 10, 64)
		case "last_handshake_time_nsec":
			nsec, _ = strconv.ParseInt(v, 10, 64)
		}
	}
	w.hs = time.Time{}
	if sec != 0 || nsec != 0 {
		w.hs = time.Unix(sec, nsec)
	}
	return w.hs
}

func (w *wgWatch) age() int {
	hs := w.last()
	if hs.IsZero() {
		return -1
	}
	return int(time.Since(hs).Seconds())
}

// statusWriter publishes the service's state for the agent.
type statusWriter struct {
	path string
	base spec.LinkStatus
}

func (w *statusWriter) write(s spec.LinkStatus) {
	s.UpdatedAt = time.Now().Unix()
	b, err := json.Marshal(s)
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(w.path), 0755)
	tmp := w.path + ".tmp"
	if os.WriteFile(tmp, b, 0644) == nil {
		_ = os.Rename(tmp, w.path)
	}
}
