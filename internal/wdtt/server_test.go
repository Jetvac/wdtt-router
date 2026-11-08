package wdtt

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
)

func TestWrapRoundTrip(t *testing.T) {
	a, _ := newAEAD("pw")
	s := newSealer(a, ptAudio)
	buf := make([]byte, 2048)
	out := make([]byte, 2048)
	for i := 0; i < 300; i++ {
		msg := bytes.Repeat([]byte{byte(i)}, 1+i%1300)
		n := s.seal(buf, msg)
		if !looksLikeRTP(buf[:n]) || buf[0] != 0xa0 || buf[1] != ptAudio {
			t.Fatalf("bad header %x", buf[:2])
		}
		m, err := open(a, buf[:n], out)
		if err != nil || !bytes.Equal(out[:m], msg) {
			t.Fatalf("round trip %d: %v", i, err)
		}
	}
	b, _ := newAEAD("other")
	n := s.seal(buf, []byte("x"))
	if _, err := open(b, buf[:n], out); err == nil {
		t.Fatal("opened with the wrong key")
	}
}

// Key derivation must match the original client (HKDF-SHA256 with fixed
// salt and info). The expected value was computed independently (RFC 5869).
func TestDeriveKeyCompatible(t *testing.T) {
	k, _ := DeriveKey("password")
	if hex.EncodeToString(k) != "eb03366b47491332578610f3b1474739788893712b1172158c803b3ad2011fa3" {
		t.Fatalf("key %x", k)
	}
}

type fakePeers struct {
	mu   sync.Mutex
	last map[string]string
}

func (f *fakePeers) Set(p map[string]string) error {
	f.mu.Lock()
	f.last = p
	f.mu.Unlock()
	return nil
}
func (f *fakePeers) Close() error { return nil }
func (f *fakePeers) n() int       { f.mu.Lock(); defer f.mu.Unlock(); return len(f.last) }

// testClient speaks the client side of the protocol over plain UDP.
type testClient struct {
	udp  *net.UDPConn
	dtls *dtls.Conn
	pc   *wrapPC
}

func dialClient(t *testing.T, addr, password string) (*testClient, error) {
	t.Helper()
	u, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(netip.MustParseAddrPort(addr)))
	if err != nil {
		t.Fatal(err)
	}
	a, _ := newAEAD(password)
	pc := &wrapPC{u: u, a: a, s: newSealer(a, ptAudio)}
	cert, _ := selfsign.GenerateSelfSigned()
	c, err := dtls.Client(pc, u.RemoteAddr(), &dtls.Config{
		Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true,
		ExtendedMasterSecret:  dtls.RequireExtendedMasterSecret,
		CipherSuites:          []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		ConnectionIDGenerator: dtls.OnlySendCIDGenerator(),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := c.HandshakeContext(ctx); err != nil {
		u.Close()
		return nil, err
	}
	return &testClient{udp: u, dtls: c, pc: pc}, nil
}

func (c *testClient) close() { c.dtls.Close(); c.udp.Close() }

func (c *testClient) ask(t *testing.T, msg string) string {
	t.Helper()
	if _, err := c.dtls.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	_ = c.dtls.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := c.dtls.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	return string(buf[:n])
}

type wrapPC struct {
	u *net.UDPConn
	a interface {
		Open(dst, nonce, ct, ad []byte) ([]byte, error)
	}
	s        *sealer
	sawAlert atomic.Bool // a DTLS alert record arrived (its header is not encrypted)
	rbuf     [2048]byte
	wbuf     [2048 + MaxWireOverhead]byte
}

func (w *wrapPC) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := w.rbuf[:]
	for {
		n, err := w.u.Read(buf)
		if err != nil {
			return 0, nil, err
		}
		m, err := open(w.s.aead, buf[:n], p)
		if err == nil {
			if m > 0 && p[0] == 21 {
				w.sawAlert.Store(true)
			}
			return m, w.u.RemoteAddr(), nil
		}
	}
}
func (w *wrapPC) WriteTo(p []byte, _ net.Addr) (int, error) {
	n := w.s.seal(w.wbuf[:], p)
	_, err := w.u.Write(w.wbuf[:n])
	return len(p), err
}
func (w *wrapPC) Close() error                       { return w.u.Close() }
func (w *wrapPC) LocalAddr() net.Addr                { return w.u.LocalAddr() }
func (w *wrapPC) SetDeadline(t time.Time) error      { return w.u.SetDeadline(t) }
func (w *wrapPC) SetReadDeadline(t time.Time) error  { return w.u.SetReadDeadline(t) }
func (w *wrapPC) SetWriteDeadline(t time.Time) error { return w.u.SetWriteDeadline(t) }

func startServer(t *testing.T, cfg Config) (*Server, *fakePeers, string, func()) {
	t.Helper()
	dir := t.TempDir()
	cfg.DataDir = dir
	cfg.Listen = "127.0.0.1:0"
	cfg.StatusFile = filepath.Join(dir, "status.json")
	path := filepath.Join(dir, "wdtt.json")
	writeCfg(t, path, cfg)
	fp := &fakePeers{}
	s := NewServer(path, func(*bind, string) (Peers, error) { return fp, nil })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	for i := 0; i < 100 && (s.mux == nil); i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if s.mux == nil {
		t.Fatal("server did not start")
	}
	return s, fp, s.mux.Addr().String(), func() { cancel(); <-done }
}

func writeCfg(t *testing.T, path string, cfg Config) {
	b, _ := json.Marshal(cfg)
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestServerProtocol(t *testing.T) {
	cfg := Config{MainPassword: "owner-pass", DNS: "1.1.1.1", Keys: []Key{
		{ID: "k1", Password: "guest-pass"},
		{ID: "k2", Password: "old-pass", ExpiresAt: time.Now().Add(-time.Hour).Unix()},
	}}
	s, peers, addr, stop := startServer(t, cfg)
	defer stop()

	// A wrong password never gets a DTLS handshake: the datagram is dropped.
	if _, err := dialClient(t, addr, "nope"); err == nil {
		t.Fatal("handshake with unknown password succeeded")
	}
	// Expired keys are not accepted on the wire either.
	if _, err := dialClient(t, addr, "old-pass"); err == nil {
		t.Fatal("handshake with expired password succeeded")
	}

	c, err := dialClient(t, addr, "owner-pass")
	if err != nil {
		t.Fatal(err)
	}
	conf := c.ask(t, "GETCONF:9123|phone-1|owner-pass")
	for _, want := range []string{"[Interface]", "Address = 10.66.66.2/32", "DNS = 1.1.1.1", "MTU = 1280",
		"AllowedIPs = 0.0.0.0/0", "Endpoint = 127.0.0.1:9123", "PersistentKeepalive = 25"} {
		if !strings.Contains(conf, want) {
			t.Fatalf("config lacks %q:\n%s", want, conf)
		}
	}
	if peers.n() != 1 {
		t.Fatalf("peers = %d", peers.n())
	}
	c.close()
	// Same device gets the same address again (GETCONF is the first message
	// of a session; later messages are tunnel data).
	c, _ = dialClient(t, addr, "owner-pass")
	if conf2 := c.ask(t, "GETCONF:9123|phone-1|owner-pass"); conf2 != conf {
		t.Fatal("config changed for the same device")
	}
	c.close()

	// A password must match the key the session authenticated with.
	g, err := dialClient(t, addr, "guest-pass")
	if err != nil {
		t.Fatal(err)
	}
	if r := g.ask(t, "GETCONF:9000|tab-1|owner-pass"); r != "DENIED:wrong_password" {
		t.Fatal(r)
	}
	g.close()

	// Generated keys bind to the first device.
	g, _ = dialClient(t, addr, "guest-pass")
	if r := g.ask(t, "GETCONF:9000|tab-1|guest-pass"); !strings.Contains(r, "10.66.66.3/32") {
		t.Fatal(r)
	}
	g.close()
	g, _ = dialClient(t, addr, "guest-pass")
	if r := g.ask(t, "GETCONF:9000|tab-2|guest-pass"); r != "DENIED:device_mismatch" {
		t.Fatal(r)
	}
	g.close()

	// WireGuard data from a session reaches the bind.
	g, _ = dialClient(t, addr, "guest-pass")
	wgPkt := append([]byte{4, 0, 0, 0, 7, 0, 0, 0}, bytes.Repeat([]byte{9}, 100)...)
	if _, err := g.dtls.Write(wgPkt); err != nil {
		t.Fatal(err)
	}
	select {
	case in := <-s.bind.in:
		if !bytes.Equal((*in.b)[:in.n], wgPkt) || in.s.lastIdx.Load() != 7 {
			t.Fatal("wrong packet")
		}
		// And a reply written to its endpoint reaches the client.
		if err := s.bind.Send([][]byte{[]byte("reply")}, in.s.ep); err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("packet not delivered")
	}
	buf := make([]byte, 100)
	_ = g.dtls.SetReadDeadline(time.Now().Add(3 * time.Second))
	if n, err := g.dtls.Read(buf); err != nil || string(buf[:n]) != "reply" {
		t.Fatal("reply not received", err)
	}

	// Disabling the key closes its sessions and removes the device peer.
	cfg.Keys[0].Disabled = true
	writeCfg(t, s.cfgPath, withRuntime(cfg, s.cfg))
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	_ = g.dtls.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := g.dtls.Read(buf); err == nil || isTimeout(err) {
		t.Fatalf("session was not closed when its key was disabled: %v", err)
	}
	g.close()
	if peers.n() != 1 {
		t.Fatalf("peers after disable = %d", peers.n())
	}
	// Re-enabling with a new device epoch unbinds the old device.
	cfg.Keys[0].Disabled, cfg.Keys[0].DeviceEpoch = false, 1
	writeCfg(t, s.cfgPath, withRuntime(cfg, s.cfg))
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	g, err = dialClient(t, addr, "guest-pass")
	if err != nil {
		t.Fatal(err)
	}
	if r := g.ask(t, "GETCONF:9000|tab-2|guest-pass"); !strings.Contains(r, "[Interface]") {
		t.Fatal(r)
	}
	g.close()

	time.Sleep(5500 * time.Millisecond)
	st, err := ReadStatus(s.cfg.StatusFile)
	if err != nil {
		t.Fatal(err)
	}
	if st.Keys["k1"].DeviceID != "tab-2" || st.Keys["k1"].Up == 0 || st.AuthFailures == 0 {
		t.Fatalf("status: %+v", st)
	}
}

func withRuntime(c Config, rt *Config) Config {
	c.DataDir, c.Listen, c.StatusFile = rt.DataDir, rt.Listen, rt.StatusFile
	return c
}

func TestJunkGetsNoReply(t *testing.T) {
	_, _, addr, stop := startServer(t, Config{MainPassword: "x1", DNS: "1.1.1.1"})
	defer stop()
	u, _ := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(netip.MustParseAddrPort(addr)))
	defer u.Close()
	for _, p := range [][]byte{[]byte("hello"), bytes.Repeat([]byte{0x80, 111}, 40), {0x16, 0xfe, 0xfd}} {
		_, _ = u.Write(p)
	}
	_ = u.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := u.Read(make([]byte, 100)); err == nil {
		t.Fatal("server answered junk")
	}
}

func TestMigrationFromOriginal(t *testing.T) {
	dir := t.TempDir()
	priv, pub, _ := newKeyPair()
	cpriv, cpub, _ := newKeyPair()
	os.WriteFile(filepath.Join(dir, "wg-keys.dat"), []byte(priv+"\n"+pub+"\nx\ny\n"), 0600)
	old := `{"main_password":"p","passwords":{},"devices":{"dev-a":{"device_id":"dev-a","ip":"10.66.66.7","priv_key":"` + cpriv + `","pub_key":"` + cpub + `"}}}`
	os.WriteFile(filepath.Join(dir, "passwords.json"), []byte(old), 0600)
	st, migrated, err := loadState(dir)
	if err != nil || !migrated || st.ServerPrivate != priv || st.Devices["dev-a"].IP != "10.66.66.7" {
		t.Fatalf("migration: %v %v %+v", err, migrated, st)
	}
	if ip := st.freeIP(); ip != "10.66.66.2" {
		t.Fatal(ip)
	}
}

// BenchmarkDataPath measures a full round trip of a 1300-byte tunnel
// packet: client DTLS write, server unwrap and DTLS read, hand-off to the
// WireGuard bind, reply through the bind and back to the client.
func BenchmarkDataPath(b *testing.B) {
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)
	t := &testing.T{}
	s, _, addr, stop := startServer(t, Config{MainPassword: "bench-pass", DNS: "1.1.1.1"})
	defer stop()
	c, err := dialClient(t, addr, "bench-pass")
	if err != nil {
		b.Fatal(err)
	}
	defer c.close()
	pkt := append([]byte{4, 0, 0, 0, 1, 0, 0, 0}, bytes.Repeat([]byte{7}, 1292)...)
	go func() {
		for in := range s.bind.in {
			_ = s.bind.Send([][]byte{(*in.b)[:in.n]}, in.s.ep)
			bufPool.Put(in.b)
		}
	}()
	buf := make([]byte, 2048)
	b.SetBytes(int64(len(pkt)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := c.dtls.Write(pkt); err != nil {
			b.Fatal(err)
		}
		if _, err := c.dtls.Read(buf); err != nil {
			b.Fatal(err)
		}
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// A session the server no longer knows (it restarted or crashed) gets a
// plaintext close_notify as soon as the client sends anything. The DTLS
// library of the standard client (pion/dtls 3.1.2) closes the session on
// it; newer versions ignore such alerts, so this checks what is sent.
func TestStaleSessionReset(t *testing.T) {
	s, _, addr, stop := startServer(t, Config{MainPassword: "stale-pass", DNS: "1.1.1.1"})
	defer stop()
	c, err := dialClient(t, addr, "stale-pass")
	if err != nil {
		t.Fatal(err)
	}
	defer c.close()
	// Forget the session without telling the client, like a crash would.
	s.mux.mu.Lock()
	clear(s.mux.conns)
	s.mux.mu.Unlock()
	for i := 0; i < 3; i++ {
		if _, err := c.dtls.Write([]byte{0xFF}); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(300 * time.Millisecond)
	if n := s.mux.resetsSent.Load(); n != 1 {
		t.Fatalf("resets sent = %d, want 1 (rate limited per address)", n)
	}
	// A new session works right away.
	c2, err := dialClient(t, addr, "stale-pass")
	if err != nil {
		t.Fatal(err)
	}
	c2.close()
}

// Stopping the server sends every session a DTLS alert (close_notify), so
// clients reconnect as soon as it is back. The standard client reacting to
// it was verified live; here we check that the alert reaches the client.
func TestShutdownNotifiesClients(t *testing.T) {
	_, _, addr, stop := startServer(t, Config{MainPassword: "stop-pass", DNS: "1.1.1.1"})
	c, err := dialClient(t, addr, "stop-pass")
	if err != nil {
		t.Fatal(err)
	}
	defer c.close()
	if _, err := c.dtls.Write([]byte{0xFF}); err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = c.dtls.Read(make([]byte, 100)) }()
	time.Sleep(200 * time.Millisecond)
	stop()
	deadline := time.Now().Add(3 * time.Second)
	for !c.pc.sawAlert.Load() {
		if time.Now().After(deadline) {
			t.Fatal("no DTLS alert reached the client on shutdown")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
