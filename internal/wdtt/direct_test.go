package wdtt

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// dclient is one direct path of a TurnVK client, over plain UDP.
type dclient struct {
	t    *testing.T
	udp  *net.UDPConn
	aead cipher.AEAD
	tx   *sealer
	pub  [32]byte
}

func newDClient(t *testing.T, addr, password string, pub [32]byte) *dclient {
	t.Helper()
	ra, _ := net.ResolveUDPAddr("udp", addr)
	u, err := net.DialUDP("udp", nil, ra)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { u.Close() })
	a, _ := newAEAD(password)
	return &dclient{t: t, udp: u, aead: a, tx: newSealer(a, ptAudio), pub: pub}
}

func randKey() (k [32]byte) { _, _ = rand.Read(k[:]); return }

func helloBytes(ts time.Time, nonce [16]byte, pub [32]byte, dev, gen string) []byte {
	b := []byte{msgHello, directVersion}
	b = binary.BigEndian.AppendUint64(b, uint64(ts.UnixMilli()))
	b = append(b, nonce[:]...)
	b = append(b, pub[:]...)
	b = append(b, 0, byte(len(dev)))
	b = append(b, dev...)
	b = append(b, byte(len(gen)))
	return append(b, gen...)
}

func (c *dclient) send(msg []byte) {
	out := make([]byte, len(msg)+MaxWireOverhead)
	n := c.tx.seal(out, msg)
	if _, err := c.udp.Write(out[:n]); err != nil {
		c.t.Fatal(err)
	}
}

func (c *dclient) sendRaw(wire []byte) { _, _ = c.udp.Write(wire) }

// recv returns the next message (FEEDBACK aside), nil after the timeout.
func (c *dclient) recv(d time.Duration) []byte {
	buf := make([]byte, 4096)
	out := make([]byte, 4096)
	_ = c.udp.SetReadDeadline(time.Now().Add(d))
	for {
		n, err := c.udp.Read(buf)
		if err != nil {
			return nil
		}
		m, err := open(c.aead, buf[:n], out)
		if err == nil && m > 0 && out[0] != msgFeedback {
			return append([]byte(nil), out[:m]...)
		}
	}
}

// hello attaches the path and returns the WELCOME (nil if none came).
func (c *dclient) hello(dev string, ts time.Time) []byte {
	var nonce [16]byte
	_, _ = rand.Read(nonce[:])
	c.send(helloBytes(ts, nonce, c.pub, dev, "gen"))
	for {
		m := c.recv(2 * time.Second)
		if m == nil || (m[0] == msgWelcome && bytes.Equal(m[2:18], nonce[:])) {
			return m
		}
	}
}

func TestDirectPaths(t *testing.T) {
	cfg := Config{MainPassword: "owner-pass", DNS: "1.1.1.1, 8.8.8.8", MTU: 1300, Kind: KindTurnVK, Iface: "wdtt1", Network: "10.66.67.0/24", Keys: []Key{
		{ID: "one", Password: "one-pass", MaxDevices: 1},
	}}
	s, peers, addr, stop := startServer(t, cfg)
	defer stop()

	pub := randKey()
	c := newDClient(t, addr, "owner-pass", pub)
	w := c.hello("phone", time.Now())
	if w == nil || w[18] != welcomeOK {
		t.Fatalf("welcome %v", w)
	}
	s.mu.Lock()
	srvPub := s.st.ServerPublic
	s.mu.Unlock()
	if base64.StdEncoding.EncodeToString(w[19:51]) != srvPub {
		t.Fatal("server key in WELCOME")
	}
	if ip := netip.AddrFrom4([4]byte(w[51:55])); ip.String() != "10.66.67.2" || w[55] != 32 {
		t.Fatalf("address %s/%d", ip, w[55])
	}
	if mtu := binary.BigEndian.Uint16(w[56:58]); mtu != 1300 || w[59] != 2 {
		t.Fatalf("mtu %d dns %d", mtu, w[59])
	}
	// The server takes the client's own key and never sends a private one.
	peers.mu.Lock()
	ip, ok := peers.last[base64.StdEncoding.EncodeToString(pub[:])]
	peers.mu.Unlock()
	if !ok || ip != "10.66.67.2" {
		t.Fatalf("peers %v", peers.last)
	}
	if d := s.st.Devices["phone"]; d.Private != "" {
		t.Fatal("server kept a private key for a TurnVK device")
	}

	// A replayed HELLO gets nothing.
	var nonce [16]byte
	h := helloBytes(time.Now(), nonce, pub, "phone", "gen")
	c.send(h)
	if m := c.recv(time.Second); m == nil {
		t.Fatal("first HELLO with this nonce unanswered")
	}
	c.send(h)
	if m := c.recv(500 * time.Millisecond); m != nil {
		t.Fatalf("replayed HELLO answered: %v", m)
	}

	// A client clock far off learns the server time.
	if m := c.hello("phone", time.Now().Add(-time.Hour)); m == nil || m[18] != welcomeClock {
		t.Fatalf("clock skew: %v", m)
	}

	// Ping: pong with the same id; the reported RTT reaches the status.
	ping := []byte{msgPing, directVersion, 1, 2, 3, 4, 5, 6, 7, 8, 0, 42}
	c.send(ping)
	if m := c.recv(time.Second); m == nil || m[0] != msgPong || !bytes.Equal(m[2:10], ping[2:10]) {
		t.Fatalf("pong %v", m)
	}
	time.Sleep(50 * time.Millisecond)
	s.mu.Lock()
	st := s.statusLocked()
	s.mu.Unlock()
	var dev DeviceStatus
	for _, d := range st.Keys[MainKeyID].Devices {
		if d.ID == "phone" {
			dev = d
		}
	}
	if dev.Paths != 1 || dev.RTT != 42 {
		t.Fatalf("device status %+v", dev)
	}

	// WireGuard data reaches the WireGuard device.
	recv, _, _ := s.bind.Open(0)
	wg := append([]byte{4, 0, 0, 0}, bytes.Repeat([]byte{9}, 40)...)
	c.send(wg)
	bufs := [][]byte{make([]byte, 2048)}
	sizes := []int{0}
	eps := make([]conn.Endpoint, 1)
	got := make(chan []byte, 1)
	go func() {
		n, err := recv[0](bufs, sizes, eps)
		if err == nil && n == 1 {
			got <- bufs[0][:sizes[0]]
		}
	}()
	select {
	case b := <-got:
		if !bytes.Equal(b, wg) {
			t.Fatal("data altered")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("data not delivered")
	}

	// A second path of the same device: bulk downlink is spread over both,
	// small packets go on both at once.
	c2 := newDClient(t, addr, "owner-pass", pub)
	if w := c2.hello("phone", time.Now()); w == nil || w[18] != welcomeOK {
		t.Fatalf("second path: %v", w)
	}
	ep, err := s.bind.ParseEndpoint(c.udp.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	big := append([]byte{4, 0, 0, 0}, bytes.Repeat([]byte{7}, 1200)...)
	// Within what the two paths may send at once (pacer.go).
	for i := 0; i < 2*directChunk; i++ {
		if err := s.bind.Send([][]byte{big}, ep); err != nil {
			t.Fatal(err)
		}
	}
	count := func(c *dclient) int {
		n := 0
		for {
			m := c.recv(300 * time.Millisecond)
			if m == nil {
				return n
			}
			if m[0] == 4 {
				n++
			}
		}
	}
	n1, n2 := count(c), count(c2)
	if n1+n2 != 2*directChunk || n1 == 0 || n2 == 0 {
		t.Fatalf("downlink split %d/%d", n1, n2)
	}
	for i := 0; i < 5; i++ {
		_ = s.bind.Send([][]byte{wg}, ep)
	}
	if n1, n2 := count(c), count(c2); n1 != 5 || n2 != 5 {
		t.Fatalf("small packets %d/%d, want 5 on each path", n1, n2)
	}

	// Data on a path the server does not know gets a reset.
	c3 := newDClient(t, addr, "owner-pass", pub)
	c3.send(wg)
	if m := c3.recv(time.Second); m == nil || m[0] != msgReset {
		t.Fatalf("unknown path: %v", m)
	}

	// A new run of the app (new key, new generation) takes the device
	// over; the old run's paths are dropped at once and told so.
	next := newDClient(t, addr, "owner-pass", randKey())
	var nn [16]byte
	_, _ = rand.Read(nn[:])
	next.send(helloBytes(time.Now(), nn, next.pub, "phone", "gen2"))
	if m := next.recv(2 * time.Second); m == nil || m[18] != welcomeOK {
		t.Fatalf("new run: %v", m)
	}
	if m := c.recv(time.Second); m == nil || m[0] != msgReset {
		t.Fatalf("old run's path not reset: %v", m)
	}
	for i := 0; i < 3*directChunk; i++ {
		_ = s.bind.Send([][]byte{wg}, ep)
	}
	if n := count(c2); n != 0 {
		t.Fatalf("old run's path still gets %d packets", n)
	}

	// A HELLO from an older run of the app (older key) does not take over.
	old := newDClient(t, addr, "owner-pass", randKey())
	if m := old.hello("phone", time.Now().Add(-time.Minute)); m == nil || m[18] != welcomeStale {
		t.Fatalf("older run: %v", m)
	}

	// Device limits apply as for GETCONF.
	k1 := newDClient(t, addr, "one-pass", randKey())
	if m := k1.hello("a", time.Now()); m == nil || m[18] != welcomeOK {
		t.Fatalf("key one, first device: %v", m)
	}
	k2 := newDClient(t, addr, "one-pass", randKey())
	if m := k2.hello("b", time.Now()); m == nil || m[18] != welcomeDeviceMismatch {
		t.Fatalf("key one, second device: %v", m)
	}

	// A wrong password gets no answer at all.
	if m := newDClient(t, addr, "nope", randKey()).hello("x", time.Now()); m != nil {
		t.Fatal("wrong password answered")
	}

	// Unbinding a device resets its paths; the client finds out at once.
	s.dropDevice("a")
	if m := k1.recv(time.Second); m == nil || m[0] != msgReset {
		t.Fatalf("unbound device not told: %v", m)
	}

	// A legacy GETCONF for a device that last used its own key gets a
	// fresh server-made key pair.
	if r := connect(t, addr, "owner-pass", "phone"); !bytes.Contains([]byte(r), []byte("Address = 10.66.67.2/32")) {
		t.Fatal(r)
	}
	if d := s.st.Devices["phone"]; d.Private == "" {
		t.Fatal("GETCONF device without a private key")
	}
}

func TestStandardServerIgnoresHello(t *testing.T) {
	s, _, addr, stop := startServer(t, Config{MainPassword: "owner-pass", DNS: "1.1.1.1"})
	defer stop()
	_ = s
	c := newDClient(t, addr, "owner-pass", randKey())
	if m := c.hello("phone", time.Now()); m != nil {
		t.Fatalf("standard server answered a HELLO: %v", m)
	}
}

func TestSessionsFilePerServer(t *testing.T) {
	for status, want := range map[string]string{
		"/run/wdtt-router/wdtt-status.json":        "/run/wdtt-router/wdtt-sessions.json",
		"/run/wdtt-router/wdtt-turnvk-status.json": "/run/wdtt-router/wdtt-turnvk-sessions.json",
		"/x/status.json":                           "/x/wdtt-sessions.json",
	} {
		if got := filepath.ToSlash(sessionsFile(status)); got != want {
			t.Errorf("%s: %s, want %s", status, got, want)
		}
	}
}
