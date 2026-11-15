package wdtt

import (
	"context"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/transport/v5/deadline"
)

// keyEntry is one accepted connection password.
type keyEntry struct {
	id   string
	aead cipher.AEAD
}

// keyring is replaced as a whole on reload.
type keyring []keyEntry

func (k keyring) trial(wire, scratch []byte) (keyEntry, int, bool) {
	for _, e := range k {
		if n, err := open(e.aead, wire, scratch); err == nil {
			return e, n, true
		}
	}
	return keyEntry{}, 0, false
}

const (
	maxDatagram    = 2048
	connQueue      = 512
	acceptBacklog  = 256
	trialsPerIP    = 256 // unknown-source decrypt attempts per IP per second (VK relays are shared by many clients)
	maxConnections = 8192
)

var bufPool = sync.Pool{New: func() any { b := make([]byte, maxDatagram); return &b }}

// mux owns the public UDP sockets. Every remote address (one TURN
// allocation of a client) becomes a virtual packet connection once its first
// datagram authenticates under one of the keys; everything else is dropped
// without a reply, so the port looks closed to scanners.
type mux struct {
	// learned: the rates direct paths through each TURN relay settled at.
	learned LearnedRates

	socks  []*net.UDPConn
	keys   atomic.Pointer[keyring]
	accept chan *vconn
	done   chan struct{}
	once   sync.Once

	mu    sync.Mutex
	conns map[netip.AddrPort]*vconn
	paths map[netip.AddrPort]*dpath // direct paths (TurnVK clients)

	// direct handles direct-path messages; nil on servers for the
	// standard client, which speak DTLS only.
	direct atomic.Pointer[directHandler]

	tmu    sync.Mutex
	trials map[netip.Addr]int
	tReset time.Time
	resets map[netip.AddrPort]time.Time

	authFailed atomic.Int64
	resetsSent atomic.Int64
}

func listenMux(ctx context.Context, addr string, keys keyring) (*mux, error) {
	n := runtime.GOMAXPROCS(0)
	if n > 8 {
		n = 8
	}
	socks, err := listenUDP(ctx, addr, n)
	if err != nil {
		return nil, err
	}
	m := &mux{socks: socks, accept: make(chan *vconn, acceptBacklog), done: make(chan struct{}),
		conns: map[netip.AddrPort]*vconn{}, paths: map[netip.AddrPort]*dpath{}, trials: map[netip.Addr]int{}, resets: map[netip.AddrPort]time.Time{}}
	m.keys.Store(&keys)
	for _, s := range socks {
		_ = s.SetReadBuffer(8 << 20)
		_ = s.SetWriteBuffer(8 << 20)
		go m.readLoop(s)
	}
	return m, nil
}

func (m *mux) setKeys(k keyring) { m.keys.Store(&k) }

func (m *mux) Close() error {
	m.once.Do(func() {
		close(m.done)
		for _, s := range m.socks {
			_ = s.Close()
		}
	})
	return nil
}

func (m *mux) Addr() net.Addr { return m.socks[0].LocalAddr() }

// acceptor is what the DTLS listener sees. Closing the listener only stops
// accepting: the sockets stay open until established sessions have sent
// their close_notify.
type acceptor struct {
	m    *mux
	once sync.Once
	done chan struct{}
}

func (a *acceptor) Accept() (net.PacketConn, net.Addr, error) {
	select {
	case c := <-a.m.accept:
		return c, net.UDPAddrFromAddrPort(c.raddr), nil
	case <-a.done:
		return nil, nil, net.ErrClosed
	case <-a.m.done:
		return nil, nil, net.ErrClosed
	}
}

func (a *acceptor) Close() error   { a.once.Do(func() { close(a.done) }); return nil }
func (a *acceptor) Addr() net.Addr { return a.m.Addr() }

func (m *mux) allowTrial(ip netip.Addr) bool {
	m.tmu.Lock()
	defer m.tmu.Unlock()
	if now := time.Now(); now.Sub(m.tReset) > time.Second {
		clear(m.trials)
		m.tReset = now
	}
	m.trials[ip]++
	return m.trials[ip] <= trialsPerIP
}

func (m *mux) readLoop(s *net.UDPConn) {
	scratch := make([]byte, maxDatagram)
	for {
		bp := bufPool.Get().(*[]byte)
		n, from, err := s.ReadFromUDPAddrPort(*bp)
		if err != nil {
			bufPool.Put(bp)
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		m.mu.Lock()
		c := m.conns[from]
		p := m.paths[from]
		m.mu.Unlock()
		if c != nil {
			c.push(bp, n)
			continue
		}
		wire := (*bp)[:n]
		if p != nil {
			// A known direct path: no queue, no goroutine hop.
			if pn, err := open(p.aead, wire, scratch); err == nil {
				seq := binary.BigEndian.Uint16(wire[2:4])
				bufPool.Put(bp)
				if h := m.direct.Load(); h != nil {
					(*h).packet(p, seq, scratch[:pn])
				}
				continue
			}
			// Not under the path's key: maybe a new password on the
			// same relay address; try every key below.
		}
		if !looksLikeRTP(wire) || !m.allowTrial(from.Addr()) {
			bufPool.Put(bp)
			continue
		}
		ks := *m.keys.Load()
		k, pn, ok := ks.trial(wire, scratch)
		if !ok {
			m.authFailed.Add(1)
			bufPool.Put(bp)
			continue
		}
		if h := m.direct.Load(); h != nil && pn > 0 && isDirect(scratch[0]) {
			msg := scratch[:pn]
			if msg[0] == msgHello {
				(*h).hello(s, from, k, wire[1], append([]byte(nil), msg...))
			} else {
				// Data or a ping on a path the server does not know (it
				// restarted, or dropped the idle path): the client
				// re-attaches the path with one HELLO.
				m.sendDirectReset(s, from, k, wire[1])
			}
			bufPool.Put(bp)
			continue
		}
		// A new connection must start with a DTLS handshake record. An
		// authenticated record of an established session we do not know
		// (the server restarted, or the session was closed) gets a reset,
		// so the client reconnects at once instead of waiting for its
		// 30-minute read timeout.
		if scratch[0] != 22 {
			if scratch[0] == 23 || scratch[0] == 25 {
				m.sendReset(s, from, k, wire[1])
			}
			bufPool.Put(bp)
			continue
		}
		c = m.newConn(s, from, k, wire[1])
		if c == nil {
			bufPool.Put(bp)
			continue
		}
		c.push(bp, n)
		select {
		case m.accept <- c:
		default:
			_ = c.Close()
		}
	}
}

// sendReset answers with a plaintext DTLS close_notify alert at epoch 0.
// The client's DTLS stack accepts epoch-0 alerts without decryption and
// closes the connection; the client then opens a new session.
func (m *mux) sendReset(s *net.UDPConn, to netip.AddrPort, k keyEntry, pt byte) {
	now := time.Now()
	if !m.resetAllowed(to, now) {
		return
	}
	rec := []byte{21, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 1, 0}
	seq := uint64(1)<<40 | uint64(now.UnixNano())&0xffffffff
	for i := 0; i < 6; i++ {
		rec[5+i] = byte(seq >> (8 * (5 - i)))
	}
	out := make([]byte, 128)
	n := newSealer(k.aead, pt).seal(out, rec)
	_, _ = s.WriteToUDPAddrPort(out[:n], to)
	m.resetsSent.Add(1)
}

// resetAllowed limits resets to one per second per address.
func (m *mux) resetAllowed(to netip.AddrPort, now time.Time) bool {
	m.tmu.Lock()
	defer m.tmu.Unlock()
	if len(m.resets) > 4096 {
		clear(m.resets)
	}
	last, seen := m.resets[to]
	if seen && now.Sub(last) < time.Second {
		return false
	}
	m.resets[to] = now
	return true
}

func (m *mux) newConn(s *net.UDPConn, raddr netip.AddrPort, k keyEntry, pt byte) *vconn {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.conns) >= maxConnections {
		return nil
	}
	c := &vconn{m: m, sock: s, raddr: raddr, keyID: k.id, aead: k.aead, tx: newSealer(k.aead, pt),
		in: make(chan pkt, connQueue), closed: make(chan struct{}), rdl: deadline.New()}
	m.conns[raddr] = c
	return c
}

func (m *mux) remove(c *vconn) {
	m.mu.Lock()
	if m.conns[c.raddr] == c {
		delete(m.conns, c.raddr)
	}
	m.mu.Unlock()
}

// closeKey drops every connection that authenticated with the key.
func (m *mux) closeKey(id string) {
	m.mu.Lock()
	var list []*vconn
	for _, c := range m.conns {
		if c.keyID == id {
			list = append(list, c)
		}
	}
	m.mu.Unlock()
	for _, c := range list {
		_ = c.Close()
	}
}

type pkt struct {
	b *[]byte
	n int
}

// vconn is the unwrapped view of one remote address, used as the
// transport of one DTLS connection.
type vconn struct {
	m      *mux
	sock   *net.UDPConn
	raddr  netip.AddrPort
	keyID  string
	aead   cipher.AEAD
	tx     *sealer
	in     chan pkt
	closed chan struct{}
	once   sync.Once
	rdl    *deadline.Deadline
	txMu   sync.Mutex
	txBuf  [maxDatagram + MaxWireOverhead]byte
}

func (c *vconn) push(bp *[]byte, n int) {
	select {
	case c.in <- pkt{bp, n}:
	default: // receiver is behind: drop like a congested link would
		bufPool.Put(bp)
	}
}

func (c *vconn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		select {
		case k := <-c.in:
			n, err := open(c.aead, (*k.b)[:k.n], p)
			bufPool.Put(k.b)
			if err != nil {
				continue // forged or corrupted datagram: ignore it
			}
			return n, net.UDPAddrFromAddrPort(c.raddr), nil
		case <-c.rdl.Done():
			return 0, nil, timeoutErr{}
		case <-c.closed:
			return 0, nil, net.ErrClosed
		case <-c.m.done:
			return 0, nil, net.ErrClosed
		}
	}
}

func (c *vconn) WriteTo(p []byte, _ net.Addr) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	if c.tx.sealedLen(len(p)) > len(c.txBuf) {
		return 0, errors.New("datagram too large")
	}
	c.txMu.Lock()
	n := c.tx.seal(c.txBuf[:], p)
	_, err := c.sock.WriteToUDPAddrPort(c.txBuf[:n], c.raddr)
	c.txMu.Unlock()
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *vconn) Close() error {
	c.once.Do(func() {
		close(c.closed)
		c.m.remove(c)
		for {
			select {
			case k := <-c.in:
				bufPool.Put(k.b)
			default:
				return
			}
		}
	})
	return nil
}

func (c *vconn) LocalAddr() net.Addr                { return c.sock.LocalAddr() }
func (c *vconn) SetDeadline(t time.Time) error      { c.rdl.Set(t); return nil }
func (c *vconn) SetReadDeadline(t time.Time) error  { c.rdl.Set(t); return nil }
func (c *vconn) SetWriteDeadline(t time.Time) error { return nil }

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }
