package link

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"math"
	mrand "math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

// mesh stands in for Cloudflare Mesh between the entry and the exit: it
// drops datagrams over its limit (a smaller MTU than the interfaces say),
// loses a share of them, goes silent on demand, and can change the port
// it sends to the exit from (as Cloudflare's proxy may).
type mesh struct {
	t     *testing.T
	in    *net.UDPConn // the entry sends here
	exit  netip.AddrPort
	limit atomic.Int32
	loss  atomic.Uint64 // math.Float64bits
	down  atomic.Bool

	mu    sync.Mutex
	up    *net.UDPConn
	entry netip.AddrPort
	gen   int
}

func newMesh(t *testing.T, exit netip.AddrPort) *mesh {
	in, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	m := &mesh{t: t, in: in, exit: exit}
	m.limit.Store(65507)
	m.rebind()
	go m.fromEntry()
	t.Cleanup(func() { in.Close(); m.mu.Lock(); m.up.Close(); m.mu.Unlock() })
	return m
}

func (m *mesh) addr() netip.AddrPort { return m.in.LocalAddr().(*net.UDPAddr).AddrPort() }

func (m *mesh) pass(n int) bool {
	if m.down.Load() || n > int(m.limit.Load()) {
		return false
	}
	return mrand.Float64() >= math.Float64frombits(m.loss.Load())
}

// rebind moves the mesh's side towards the exit to a new port.
func (m *mesh) rebind() {
	up, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		m.t.Fatal(err)
	}
	m.mu.Lock()
	old := m.up
	m.up = up
	m.gen++
	m.mu.Unlock()
	if old != nil {
		old.Close()
	}
	go func() {
		buf := make([]byte, 65536)
		for {
			n, err := up.Read(buf)
			if err != nil {
				return
			}
			m.mu.Lock()
			to := m.entry
			m.mu.Unlock()
			if to.IsValid() && m.pass(n) {
				_, _ = m.in.WriteToUDPAddrPort(buf[:n], to)
			}
		}
	}()
}

func (m *mesh) fromEntry() {
	buf := make([]byte, 65536)
	for {
		n, src, err := m.in.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		m.mu.Lock()
		m.entry = src
		up, to := m.up, m.exit
		m.mu.Unlock()
		if m.pass(n) {
			_, _ = up.WriteToUDPAddrPort(buf[:n], to)
		}
	}
}

type side struct {
	tun  *tuntest.ChannelTUN
	dev  *device.Device
	bind *Bind
	addr netip.Addr
	cfg  *Config
}

func keypair(t *testing.T) (priv, pub []byte) {
	priv = make([]byte, 32)
	_, _ = rand.Read(priv)
	priv[0] &= 248
	priv[31] = priv[31]&127 | 64
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return
}

// pair starts an entry and an exit with real WireGuard devices; the
// entry reaches the exit through a mesh. datagram is what both binds think
// the path takes.
func pair(t *testing.T, datagram int) (entry, exit *side, m *mesh) {
	psk := make([]byte, 32)
	_, _ = rand.Read(psk)
	ePriv, ePub := keypair(t)
	xPriv, xPub := keypair(t)
	b64 := base64.StdEncoding.EncodeToString
	path := func() int { return datagram }

	xcfg := &Config{Role: "exit", PrivateKey: b64(xPriv), PeerKey: b64(ePub), PSK: b64(psk), AllowedIP: "10.66.80.1/32"}
	exit = startSide(t, xcfg, netip.MustParseAddrPort("127.0.0.1:0"), path, "10.66.80.2")
	exitAddr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(exit.bind.conn.Load().LocalAddr().(*net.UDPAddr).Port))
	m = newMesh(t, exitAddr)

	ecfg := &Config{Role: "entry", PrivateKey: b64(ePriv), PeerKey: b64(xPub), PSK: b64(psk), AllowedIP: "0.0.0.0/0", Peer: m.addr().String()}
	entry = startSide(t, ecfg, netip.AddrPort{}, path, "10.66.80.1")
	return entry, exit, m
}

// startSide runs one end with WireGuard configured as the service does.
func startSide(t *testing.T, cfg *Config, listen netip.AddrPort, path func() int, addr string) *side {
	psk, _ := decodeKey(cfg.PSK)
	s := &side{tun: tuntest.NewChannelTUN(), addr: netip.MustParseAddr(addr), cfg: cfg}
	s.bind = NewBind(psk, listen, path)
	s.dev = device.NewDevice(s.tun.TUN(), s.bind, device.NewLogger(device.LogLevelSilent, ""))
	if err := s.dev.IpcSet(ipcConfig(cfg)); err != nil {
		t.Fatal(err)
	}
	if err := s.dev.Up(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.dev.Close)
	return s
}

// udpPacket builds an IPv4 UDP packet of total size n.
func udpPacket(src, dst netip.Addr, n int, seq uint32) []byte {
	p := make([]byte, n)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:], uint16(n))
	p[8], p[9] = 64, 17
	copy(p[12:16], src.AsSlice())
	copy(p[16:20], dst.AsSlice())
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(p[i:]))
	}
	for sum > 0xffff {
		sum = sum>>16 + sum&0xffff
	}
	binary.BigEndian.PutUint16(p[10:], ^uint16(sum))
	binary.BigEndian.PutUint16(p[20:], 5000)
	binary.BigEndian.PutUint16(p[22:], 6000)
	binary.BigEndian.PutUint16(p[24:], uint16(n-20))
	binary.BigEndian.PutUint32(p[28:], seq)
	for i := 32; i < n; i++ {
		p[i] = byte(i * 7)
	}
	return p
}

// send puts a packet into from's TUN and waits for it at to's.
func send(t *testing.T, from, to *side, src, dst netip.Addr, n int, seq uint32, wait time.Duration) bool {
	t.Helper()
	p := udpPacket(src, dst, n, seq)
	select {
	case from.tun.Outbound <- p:
	case <-time.After(wait):
		return false
	}
	deadline := time.After(wait)
	for {
		select {
		case got := <-to.tun.Inbound:
			if bytes.Equal(got, p) {
				return true
			}
		case <-deadline:
			return false
		}
	}
}

var internet = netip.MustParseAddr("1.1.1.1")

func TestTunnelCarriesFullSizePackets(t *testing.T) {
	// Mesh at its smallest seen MTU, 1147: 1119 bytes per datagram.
	entry, exit, m := pair(t, 1147-28)
	m.limit.Store(1147 - 28)
	for i, n := range []int{60, 1000, 1072, 1200, 1228, 1280, 1340} {
		if !send(t, entry, exit, entry.addr, internet, n, uint32(i), 5*time.Second) {
			t.Fatalf("entry → exit: %d bytes lost", n)
		}
		if !send(t, exit, entry, internet, entry.addr, n, uint32(100+i), 5*time.Second) {
			t.Fatalf("exit → entry: %d bytes lost", n)
		}
	}
	if entry.bind.Split.Load() == 0 || exit.bind.Joined.Load() == 0 {
		t.Fatal("large packets were not sent in parts")
	}
}

func TestTunnelUnderLoss(t *testing.T) {
	entry, exit, m := pair(t, 1280-28)
	// Wait for the handshake on a clean path, then lose 3 %.
	if !send(t, entry, exit, entry.addr, internet, 100, 0, 5*time.Second) {
		t.Fatal("no tunnel")
	}
	m.loss.Store(math.Float64bits(0.03))
	got := 0
	for i := 0; i < 300; i++ {
		if send(t, entry, exit, entry.addr, internet, 1300, uint32(i+1), 300*time.Millisecond) {
			got++
		}
	}
	// A 2-part packet survives with 0.97² ≈ 94 %.
	if got < 255 {
		t.Fatalf("only %d of 300 large packets arrived at 3 %% loss", got)
	}
}

func TestTunnelFollowsPortChange(t *testing.T) {
	entry, exit, m := pair(t, 1280-28)
	if !send(t, entry, exit, entry.addr, internet, 200, 1, 5*time.Second) {
		t.Fatal("no tunnel")
	}
	m.rebind() // Cloudflare's proxy now sends from another port
	// The entry's keepalive (1 s) or next packet tells the exit the new
	// address; then the exit's replies reach the entry again.
	ok := false
	for i := 0; i < 30 && !ok; i++ {
		_ = send(t, entry, exit, entry.addr, internet, 200, uint32(10+i), 200*time.Millisecond)
		ok = send(t, exit, entry, internet, entry.addr, 200, uint32(100+i), 200*time.Millisecond)
	}
	if !ok {
		t.Fatal("the exit did not follow the new port")
	}
}

func TestEntryFindsSmallerPath(t *testing.T) {
	// The interface says 1280 but the path takes 1147.
	entry, exit, m := pair(t, 1280-28)
	m.limit.Store(1147 - 28)
	e := &Entry{Bind: entry.bind, Peer: m.addr(), Health: &Health{T: DefaultThresholds},
		Allowed: func() bool { return false }, Handshake: func() time.Time { return time.Now() },
		Route: func(bool) error { return nil }, Interval: 20 * time.Millisecond, MTUWait: 100 * time.Millisecond,
		MTUEvery: 300 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)
	deadline := time.Now().Add(10 * time.Second)
	for entry.bind.Limited() == 0 || entry.bind.Datagram() > 1147-28 {
		if time.Now().After(deadline) {
			t.Fatalf("datagrams still %d bytes", entry.bind.Datagram())
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !send(t, entry, exit, entry.addr, internet, 1340, 1, 5*time.Second) {
		t.Fatal("a full-size packet did not pass after capping")
	}
	// The path gets its 1280 back: the cap goes after the next check.
	m.limit.Store(1280 - 28)
	deadline = time.Now().Add(10 * time.Second)
	for entry.bind.Limited() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("still capped at %d", entry.bind.Limited())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestEntryFallsBackAndReturns(t *testing.T) {
	entry, _, m := pair(t, 1280-28)
	th := DefaultThresholds
	th.Down, th.Up, th.Grace = 300*time.Millisecond, 600*time.Millisecond, 100*time.Millisecond
	var mu sync.Mutex
	var routes []bool
	e := &Entry{Bind: entry.bind, Peer: m.addr(), Health: &Health{T: th},
		Allowed: func() bool { return true }, Handshake: func() time.Time { return time.Now() },
		Route:    func(on bool) error { mu.Lock(); routes = append(routes, on); mu.Unlock(); return nil },
		Interval: 20 * time.Millisecond, RouteEvery: 100 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)
	waitFor := func(want bool, within time.Duration) {
		t.Helper()
		deadline := time.Now().Add(within)
		for e.Health.State().Want != want {
			if time.Now().After(deadline) {
				t.Fatalf("decision not %v after %s (problem %q)", want, within, e.Health.State().Problem)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	waitFor(true, 3*time.Second)
	// A 200 ms blip: no switch.
	m.down.Store(true)
	time.Sleep(200 * time.Millisecond)
	m.down.Store(false)
	time.Sleep(300 * time.Millisecond)
	if !e.Health.State().Want {
		t.Fatal("a short blip moved UDP off the tunnel")
	}
	// A real outage: off, then back once healthy for Up.
	m.down.Store(true)
	waitFor(false, 2*time.Second)
	m.down.Store(false)
	waitFor(true, 3*time.Second)
	mu.Lock()
	defer mu.Unlock()
	sawOff := false
	for _, r := range routes {
		sawOff = sawOff || !r
	}
	if !sawOff || !routes[len(routes)-1] {
		t.Fatalf("routing calls %v", routes)
	}
	// (Round trips on loopback may read 0 where the clock is coarse.)
	if p50, _, loss, n := e.tr.stats(time.Now()); n == 0 || p50 < 0 {
		t.Fatalf("no round trips measured: p50 %v loss %v n %d", p50, loss, n)
	}
}

func TestRelayPassesTheTunnel(t *testing.T) {
	entry, exit, m := pair(t, 1280-28)
	// Put a relay between the mesh and the exit.
	m.mu.Lock()
	r := &Relay{Next: m.exit}
	m.mu.Unlock()
	ln, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	r.Listen = ln.LocalAddr().(*net.UDPAddr).AddrPort()
	ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx)
	time.Sleep(50 * time.Millisecond)
	m.mu.Lock()
	m.exit = r.Listen
	m.mu.Unlock()
	if !send(t, entry, exit, entry.addr, internet, 1300, 1, 5*time.Second) || !send(t, exit, entry, internet, entry.addr, 1300, 2, 5*time.Second) {
		t.Fatal("no traffic through the relay")
	}
	if r.Bytes.Load() == 0 || !r.Prev().IsValid() {
		t.Fatal("the relay saw nothing")
	}
}

func TestEntryRekeysWhenExitRestarts(t *testing.T) {
	entry, exit, m := pair(t, 1280-28)
	e := &Entry{Bind: entry.bind, Peer: m.addr(), Health: &Health{T: DefaultThresholds},
		Allowed: func() bool { return false }, Handshake: func() time.Time { return time.Now() },
		Route: func(bool) error { return nil }, Interval: 50 * time.Millisecond,
		PeerRestarted: func() { _ = resetPeer(entry.dev, entry.cfg) }}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)
	if !send(t, entry, exit, entry.addr, internet, 300, 1, 5*time.Second) {
		t.Fatal("no tunnel")
	}
	time.Sleep(200 * time.Millisecond) // the entry learns the exit's run
	// The exit's service restarts on the same port: its WireGuard has no
	// keys any more. Without a new handshake the entry's packets would be
	// dropped until WireGuard itself gives up on the old keys (15 s).
	port := exit.bind.conn.Load().LocalAddr().(*net.UDPAddr).Port
	exit.dev.Close()
	exit = startSide(t, exit.cfg, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port)), func() int { return 1280 - 28 }, "10.66.80.2")
	start := time.Now()
	for i := 0; ; i++ {
		if send(t, entry, exit, entry.addr, internet, 300, uint32(10+i), 200*time.Millisecond) {
			break
		}
		if time.Since(start) > 5*time.Second {
			t.Fatal("the tunnel did not recover within 5 s of the exit's restart")
		}
	}
	t.Logf("traffic again %s after the exit's restart", time.Since(start).Round(10*time.Millisecond))
}
