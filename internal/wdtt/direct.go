package wdtt

// Direct paths: the TurnVK client's transport.
//
// A standard WDTT client opens a DTLS connection through every TURN
// allocation and repeats GETCONF on each; losing an allocation loses that
// connection, and a server restart breaks all of them. TurnVK clients skip
// DTLS. Every datagram still travels inside the RTP wrap (ChaCha20-Poly1305
// under the password's key, disguised as call audio or video) through VK's
// TURN servers, and inside it:
//
//	HELLO   client -> server  attach this TURN allocation ("path") to a device
//	WELCOME server -> client  the tunnel parameters, or why not
//	PING    client -> server  path liveness, carries the path's measured RTT
//	PONG    server -> client
//	RESET   server -> client  unknown path: send HELLO again
//	BYE     client -> server  the client closes this path
//	STATS   client -> server  statistics of the connection (stats.go)
//	STATSACK server -> client
//	WireGuard messages (types 1..4) as they are
//
// The connection itself is the WireGuard session, end to end between the
// client and the server: it does not depend on any path, so a path can drop
// or be added without a handshake, and the server sends a device's traffic
// over all of its live paths. The client generates its WireGuard key pair
// itself and sends only the public key, so the server never hands out a
// private key, and a client that knows the server's public key (from the
// link) cannot be fooled by anyone else holding the password.
//
// HELLO layout (after the RTP wrap is removed):
//
//	0x41 | version | unix ms (8) | nonce (16) | client public key (32) |
//	flags (1) | len | device id | len | generation | [run start, unix ms (8)]
//
// The run start (flag helloRunAt, TurnVK 0.9.5 and later) orders two runs
// of the app on one device; older servers ignore it.
//
// WELCOME:
//
//	0x42 | version | nonce (16) | status | on success: server public key (32) |
//	client IPv4 (4) | prefix bits | MTU (2) | keepalive s | n | DNS IPv4 (4 each)
//	status "clock": server unix ms (8) instead

import (
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	msgHello   = 0x41
	msgWelcome = 0x42
	msgPing    = 0x44
	msgPong    = 0x45
	msgReset   = 0x46
	msgBye     = 0x47

	directVersion = 1

	helloSkew = 10 * time.Minute // client clock may be off by this much
	// helloRunAt: HELLO flag, the run's start follows the generation.
	helloRunAt = 0x01
	// holderLive: the run holding a device counts as connected while the
	// client was heard on one of its paths this recently (the app pings
	// every path every few seconds and says BYE when it stops).
	holderLive = 30 * time.Second
	// pathIdle: a path silent this long is dropped. Clients ping every
	// path every 2 s, but a phone dozing with the screen off pauses for
	// minutes; its TURN allocation outlives that, so the path is kept and
	// the phone needs no reset and new HELLO when it wakes.
	pathIdle = 5 * time.Minute
	// pathFresh: a path heard from within this carries traffic. Clients
	// ping every 2 s, so a path that missed two pings is left out (it gets
	// traffic again as soon as it answers); with none fresh, the pacer
	// still sends on any live path.
	pathFresh   = 5 * time.Second
	pathLive    = 30 * time.Second // a path counted as live in the status
	pathStall   = 750 * time.Millisecond
	directChunk = 16 // tests: packets enough to cross paths
)

// WELCOME status codes.
const (
	welcomeOK = iota
	welcomeWrongPassword
	welcomeExpired
	welcomeDeactivated
	welcomeDeviceMismatch
	welcomeNoConf
	welcomeClock
	welcomeStale // a newer connection of the same device took over
)

func isDirect(b byte) bool {
	return b == msgHello || b == msgPing || (b >= 1 && b <= 4)
}

type directHandler interface {
	hello(sock *net.UDPConn, from netip.AddrPort, k keyEntry, pt byte, msg []byte)
	packet(p *dpath, seq uint16, msg []byte)
}

// dpath is one TURN allocation of a TurnVK client.
type dpath struct {
	m     *mux
	sock  *net.UDPConn
	raddr netip.AddrPort
	keyID string
	aead  cipher.AEAD
	tx    *sealer
	sess  atomic.Pointer[session]
	rtt   atomic.Int32 // ms, as measured by the client
	// lat: the round trip a small packet should expect, jitter included
	// (smoothed rtt + 2 mean deviations, jitter.go), ms; 0 until known.
	lat    atomic.Int32
	jit    jitter
	lastRx atomic.Int64 // unix nanoseconds
	// pending: when the server first sent on the path after it last heard
	// from it (unix ns); see usable.
	pending atomic.Int64
	pr      PathRate // pacing of what the server sends (pace.go)
	rx      RxTrack  // what the client sends; read loop only

	txMu  sync.Mutex
	txBuf [maxDatagram + MaxWireOverhead]byte
}

func (p *dpath) send(b []byte) error {
	if p.tx.sealedLen(len(b)) > len(p.txBuf) {
		return errors.New("datagram too large")
	}
	p.txMu.Lock()
	n := p.tx.seal(p.txBuf[:], b)
	now := time.Now().UnixNano()
	p.pr.OnSend(binary.BigEndian.Uint16(p.txBuf[2:4]), now)
	if p.pending.Load() <= p.lastRx.Load() {
		p.pending.Store(now)
	}
	_, err := p.sock.WriteToUDPAddrPort(p.txBuf[:n], p.raddr)
	p.txMu.Unlock()
	return err
}

// usable reports whether the path may carry traffic: heard from since
// fresh, and, for a client that reports every packet it gets (FEEDBACK),
// not silent for pathStall since the server first sent on it unanswered.
// A path VK stopped relaying thus drops out within pathStall instead of
// pathFresh; it comes back as soon as anything arrives on it (the
// client's next ping, at most 2 s later).
func (p *dpath) usable(now, fresh int64) bool {
	rx := p.lastRx.Load()
	if rx < fresh {
		return false
	}
	if pd := p.pending.Load(); pd > rx && now-pd > int64(pathStall) && p.pr.HasFeedback() {
		return false
	}
	return true
}

// sendDirectReset tells a client that the server does not know its path.
func (m *mux) sendDirectReset(s *net.UDPConn, to netip.AddrPort, k keyEntry, pt byte) {
	if !m.resetAllowed(to, time.Now()) {
		return
	}
	out := make([]byte, 128)
	n := newSealer(k.aead, pt).seal(out, []byte{msgReset, directVersion})
	_, _ = s.WriteToUDPAddrPort(out[:n], to)
	m.resetsSent.Add(1)
}

// attach returns the path for an address, creating it; replaced is the
// path the address had under another password.
func (m *mux) attach(s *net.UDPConn, from netip.AddrPort, k keyEntry, pt byte) (p, replaced *dpath) {
	m.mu.Lock()
	defer m.mu.Unlock()
	old := m.paths[from]
	if old != nil && old.keyID == k.id {
		return old, nil
	}
	if old == nil && len(m.paths)+len(m.conns) >= maxConnections {
		return nil, nil
	}
	p = &dpath{m: m, sock: s, raddr: from, keyID: k.id, aead: k.aead, tx: newSealer(k.aead, pt)}
	p.pr.Seed(m.learned.Start(from.Addr().String()))
	p.lastRx.Store(time.Now().UnixNano())
	m.paths[from] = p
	return p, old
}

func (m *mux) detach(p *dpath) {
	m.mu.Lock()
	if m.paths[p.raddr] == p {
		delete(m.paths, p.raddr)
	}
	m.mu.Unlock()
}

func (m *mux) pathList() []*dpath {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*dpath, 0, len(m.paths))
	for _, p := range m.paths {
		out = append(out, p)
	}
	return out
}

type helloMsg struct {
	ts    int64
	nonce [16]byte
	pub   [32]byte
	flags byte
	dev   string
	gen   string
	runAt int64 // when the run began (client's clock, unix ms), 0 if not sent
}

func parseHello(b []byte) (helloMsg, error) {
	var h helloMsg
	if len(b) < 60 || b[0] != msgHello || b[1] != directVersion {
		return h, errors.New("bad HELLO")
	}
	h.ts = int64(binary.BigEndian.Uint64(b[2:10]))
	copy(h.nonce[:], b[10:26])
	copy(h.pub[:], b[26:58])
	h.flags = b[58]
	rest := b[59:]
	str := func() (string, bool) {
		if len(rest) < 1 || len(rest) < 1+int(rest[0]) {
			return "", false
		}
		s := string(rest[1 : 1+int(rest[0])])
		rest = rest[1+int(rest[0]):]
		return s, true
	}
	var ok bool
	if h.dev, ok = str(); !ok {
		return h, errors.New("bad HELLO device")
	}
	if h.gen, ok = str(); !ok {
		return h, errors.New("bad HELLO generation")
	}
	if h.flags&helloRunAt != 0 && len(rest) >= 8 {
		h.runAt = int64(binary.BigEndian.Uint64(rest[:8]))
	}
	return h, nil
}

// olderRun reports whether a HELLO with a new key comes from an earlier run
// of the app than the one holding the device: by the runs' starts when both
// sent theirs, else by the HELLO's own time.
func olderRun(h helloMsg, d *deviceState) bool {
	if h.runAt > 0 && d.RunAt > 0 {
		return h.runAt < d.RunAt
	}
	return h.ts < d.KeyAt
}

// heardLately reports whether the client was heard within holderLive on
// any of the device's paths.
func (s *Server) heardLately(dev string, now time.Time) bool {
	cut := now.Add(-holderLive).UnixNano()
	s.bind.mu.Lock()
	defer s.bind.mu.Unlock()
	if ps := s.bind.devPaths[dev]; ps != nil {
		for _, x := range ps.list {
			if x.dp != nil && x.dp.lastRx.Load() >= cut {
				return true
			}
		}
	}
	return false
}

// nonceCache rejects replayed HELLOs within the accepted clock skew.
type nonceCache struct {
	mu   sync.Mutex
	seen map[[16]byte]int64
}

func (c *nonceCache) add(n [16]byte, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen == nil {
		c.seen = map[[16]byte]int64{}
	}
	if _, dup := c.seen[n]; dup {
		return false
	}
	if len(c.seen) > 200000 {
		cut := now.Add(-2 * helloSkew).UnixNano()
		for k, t := range c.seen {
			if t < cut {
				delete(c.seen, k)
			}
		}
	}
	c.seen[n] = now.UnixNano()
	return true
}

func (c *nonceCache) prune(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cut := now.Add(-2 * helloSkew).UnixNano()
	for k, t := range c.seen {
		if t < cut {
			delete(c.seen, k)
		}
	}
}

func welcome(nonce [16]byte, status byte, extra []byte) []byte {
	b := make([]byte, 0, 19+len(extra))
	b = append(b, msgWelcome, directVersion)
	b = append(b, nonce[:]...)
	b = append(b, status)
	return append(b, extra...)
}

func denyStatus(reason string) byte {
	switch reason {
	case "expired":
		return welcomeExpired
	case "deactivated":
		return welcomeDeactivated
	case "device_mismatch":
		return welcomeDeviceMismatch
	case "noconf":
		return welcomeNoConf
	}
	return welcomeWrongPassword
}

// directServer is the Server seen by the mux.
type directServer struct{ s *Server }

func (d directServer) hello(sock *net.UDPConn, from netip.AddrPort, k keyEntry, pt byte, msg []byte) {
	go d.s.hello(sock, from, k, pt, msg)
}

func (d directServer) packet(p *dpath, seq uint16, msg []byte) { d.s.pathPacket(p, seq, msg) }

func (s *Server) hello(sock *net.UDPConn, from netip.AddrPort, k keyEntry, pt byte, msg []byte) {
	h, err := parseHello(msg)
	if err != nil {
		return
	}
	reply := func(b []byte) {
		out := make([]byte, len(b)+MaxWireOverhead)
		n := newSealer(k.aead, pt).seal(out, b)
		_, _ = sock.WriteToUDPAddrPort(out[:n], from)
	}
	now := time.Now()
	if d := now.Sub(time.UnixMilli(h.ts)); d > helloSkew || d < -helloSkew {
		var t [8]byte
		binary.BigEndian.PutUint64(t[:], uint64(now.UnixMilli()))
		reply(welcome(h.nonce, welcomeClock, t[:]))
		return
	}
	if !s.nonces.add(h.nonce, now) {
		return // replayed
	}
	dev := cleanDeviceID(h.dev)
	pub := base64.StdEncoding.EncodeToString(h.pub[:])
	held := s.heardLately(dev, now)

	s.mu.Lock()
	key, ok := s.byID[k.id]
	if !ok {
		s.mu.Unlock()
		reply(welcome(h.nonce, welcomeWrongPassword, nil))
		return
	}
	if !key.active(now) {
		s.mu.Unlock()
		st := byte(welcomeExpired)
		if key.Disabled {
			st = welcomeDeactivated
		}
		reply(welcome(h.nonce, st, nil))
		return
	}
	d, deny := s.admitLocked(key, dev, now)
	if deny != "" {
		s.mu.Unlock()
		reply(welcome(h.nonce, denyStatus(deny), nil))
		return
	}
	changed := false
	if d.Public != pub {
		if held && olderRun(h, d) {
			// An earlier run of the app on this device while the later
			// one is still connected: the later keeps the address. Once
			// that one is gone the run that asks gets it, whatever the
			// clocks say (a phone stopped for good with "connected again
			// elsewhere", Nov 2026: a run refused by mistake).
			s.mu.Unlock()
			reply(welcome(h.nonce, welcomeStale, nil))
			return
		}
		d.Public, d.Private, d.KeyAt, d.RunAt = pub, "", h.ts, h.runAt
		changed = true
	}
	d.LastSeen, d.Key = now.Unix(), key.ID
	s.dirty = true
	if changed || d.New {
		d.New = false
		if err := s.syncPeersLocked(); err != nil {
			log.Printf("WireGuard peers: %v", err)
			s.mu.Unlock()
			reply(welcome(h.nonce, welcomeNoConf, nil))
			return
		}
	}
	extra := s.welcomeExtraLocked(d)
	s.mu.Unlock()

	p, replaced := s.mux.attach(sock, from, k, pt)
	if replaced != nil {
		s.closePath(replaced, false)
	}
	if p == nil {
		reply(welcome(h.nonce, welcomeNoConf, nil))
		return
	}
	p.lastRx.Store(now.UnixNano())
	if old := p.sess.Load(); old == nil || old.dev != dev || old.gen != h.gen {
		sess := &session{dp: p, keyID: key.ID, cnt: s.counter(key.ID), dev: dev, gen: h.gen, opened: now.UnixNano()}
		sess.ep = &endpoint{s: sess, addr: from}
		sess.dcnt.Store(s.devCounter(dev))
		sess.lastRx.Store(now.UnixNano())
		s.bind.add(sess)
		if old != nil {
			old.dead.Store(true)
			s.bind.remove(old)
		}
		p.sess.Store(sess)
	}
	// Paths of an earlier run of the app on this device are dead (or
	// about to be refused as stale): stop sending the device's traffic to
	// them now rather than when they time out.
	s.closeOtherRuns(dev, h.gen)
	_ = p.send(welcome(h.nonce, welcomeOK, extra))
}

func (s *Server) closeOtherRuns(dev, gen string) {
	var old []*dpath
	s.bind.mu.Lock()
	if ps := s.bind.devPaths[dev]; ps != nil {
		for _, x := range ps.list {
			if x.gen != gen {
				old = append(old, x.dp)
			}
		}
	}
	s.bind.mu.Unlock()
	for _, p := range old {
		s.closePath(p, true)
	}
}

func (s *Server) welcomeExtraLocked(d *deviceState) []byte {
	b := make([]byte, 0, 48)
	pub, _ := base64.StdEncoding.DecodeString(s.st.ServerPublic)
	b = append(b, pub...)
	ip := netip.MustParseAddr(d.IP).As4()
	b = append(b, ip[:]...)
	b = append(b, 32)
	b = binary.BigEndian.AppendUint16(b, uint16(s.cfg.MTU))
	b = append(b, 25)
	var dns []netip.Addr
	for _, f := range splitList(s.cfg.DNS) {
		if a, err := netip.ParseAddr(f); err == nil && a.Is4() {
			dns = append(dns, a)
		}
	}
	if len(dns) > 4 {
		dns = dns[:4]
	}
	b = append(b, byte(len(dns)))
	for _, a := range dns {
		x := a.As4()
		b = append(b, x[:]...)
	}
	return b
}

func (s *Server) pathPacket(p *dpath, seq uint16, msg []byte) {
	if len(msg) == 0 {
		return
	}
	now := time.Now()
	p.lastRx.Store(now.UnixNano())
	// Tell the client how its packets come through, so that it paces
	// what it sends (pace.go).
	if p.rx.Seen(seq, now.UnixNano()) {
		_ = p.send(p.rx.Feedback(directVersion, now.UnixNano()))
	}
	sess := p.sess.Load()
	switch t := msg[0]; {
	case t >= 1 && t <= 4:
		if sess == nil {
			return
		}
		sess.lastRx.Store(now.UnixNano())
		sess.cnt.up.Add(int64(len(msg)))
		if dc := sess.dcnt.Load(); dc != nil {
			dc.up.Add(int64(len(msg)))
		}
		if t == 4 && sess.dev != "" && !sess.checked.Swap(true) {
			go s.kick(sess.dev, p.raddr.String())
		}
		s.bind.deliver(sess, msg)
	case t == msgPing:
		if len(msg) >= 12 {
			r := int32(binary.BigEndian.Uint16(msg[10:12]))
			p.rtt.Store(r)
			if r > 0 {
				p.lat.Store(p.jit.add(r))
			}
		}
		if recv, lost, ok := pathReport(msg); ok {
			p.pr.Report(recv, lost, p.rtt.Load())
		}
		if sess != nil {
			sess.lastRx.Store(now.UnixNano())
		}
		if len(msg) >= 10 {
			pong := make([]byte, 10)
			pong[0], pong[1] = msgPong, directVersion
			copy(pong[2:10], msg[2:10])
			_ = p.send(pong)
		}
	case t == msgFeedback:
		p.pr.OnFeedback(msg, now.UnixNano())
	case t == msgStats:
		if ack, ok := s.stats.clientReport(sess, p.raddr, msg, now); ok {
			_ = p.send(ack)
		}
	case t == msgBye:
		s.closePath(p, false)
	case t == msgHello:
		cp := append([]byte(nil), msg...)
		go s.hello(p.sock, p.raddr, keyEntry{id: p.keyID, aead: p.aead}, p.tx.pt, cp)
	}
}

// closePath forgets a path; reset tells the client so that it attaches
// the path again (and learns why not, if it may no longer connect).
func (s *Server) closePath(p *dpath, reset bool) {
	s.mux.learned.Note(p.raddr.Addr().String(), &p.pr)
	s.mux.detach(p)
	if sess := p.sess.Load(); sess != nil {
		sess.dead.Store(true)
		s.bind.remove(sess)
	}
	if reset {
		s.mux.sendDirectReset(p.sock, p.raddr, keyEntry{id: p.keyID, aead: p.aead}, p.tx.pt)
	}
}

// expirePaths drops paths that have been silent for pathIdle.
func (s *Server) expirePaths(now time.Time) {
	cut := now.Add(-pathIdle).UnixNano()
	for _, p := range s.mux.pathList() {
		if p.lastRx.Load() < cut {
			s.closePath(p, false)
		}
	}
	s.nonces.prune(now)
}

func splitList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' })
}
