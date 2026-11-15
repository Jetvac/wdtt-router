package wdtt

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
)

// bind connects the userspace WireGuard device straight to the DTLS
// sessions. There is no WireGuard UDP socket and no extra hop through
// localhost: a packet read from a session is handed to WireGuard, and
// WireGuard's replies are written to the session it last heard the peer on.
type bind struct {
	in chan inbound

	mu       sync.Mutex
	closed   chan struct{}
	sessions map[*session]struct{}
	// devPaths lists each device's direct paths, for spreading its
	// downlink over all of them.
	devPaths map[string]*pathSet
	pacers   map[string]*pacer
	// reorder puts what TurnVK clients send over many paths back in order
	// (reorder.go).
	reorder Reorder[inbound]
}

// pathSet is a device's live direct paths.
type pathSet struct {
	list []*session
}

type inbound struct {
	b *[]byte
	n int
	s *session
}

const bindBatch = 32

func newBind() *bind {
	b := &bind{in: make(chan inbound, 4096), closed: make(chan struct{}), sessions: map[*session]struct{}{}, devPaths: map[string]*pathSet{}, pacers: map[string]*pacer{}}
	b.reorder.Out = b.enqueue
	return b
}

func (b *bind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	select {
	case <-b.closed:
		b.closed = make(chan struct{})
	default:
	}
	closed := b.closed
	b.mu.Unlock()
	recv := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		var first inbound
		select {
		case first = <-b.in:
		case <-closed:
			return 0, net.ErrClosed
		}
		n := 0
		put := func(p inbound) {
			sizes[n] = copy(packets[n], (*p.b)[:p.n])
			eps[n] = p.s.ep
			bufPool.Put(p.b)
			n++
		}
		put(first)
		for n < len(packets) {
			select {
			case p := <-b.in:
				put(p)
			default:
				return n, nil
			}
		}
		return n, nil
	}
	return []conn.ReceiveFunc{recv}, 0, nil
}

func (b *bind) Close() error {
	b.mu.Lock()
	select {
	case <-b.closed:
	default:
		close(b.closed)
	}
	b.mu.Unlock()
	return nil
}

func (b *bind) SetMark(uint32) error { return nil }
func (b *bind) BatchSize() int       { return bindBatch }

// ParseEndpoint finds the live session with the given address; the server
// uses it to point a peer at the session a device has just opened.
func (b *bind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for x := range b.sessions {
		if x.ep.addr == ap && !x.dead.Load() {
			return x.ep, nil
		}
	}
	return nil, errors.New("no live session at " + s)
}

func (b *bind) Send(bufs [][]byte, ep conn.Endpoint) error {
	e, ok := ep.(*endpoint)
	if !ok {
		return errors.New("unknown endpoint")
	}
	s := e.s
	if s.dp != nil {
		return b.sendDirect(bufs, s)
	}
	if s.dead.Load() {
		if s = b.sibling(s); s == nil {
			return net.ErrClosed
		}
	}
	for _, p := range bufs {
		if err := s.writeData(p); err != nil {
			if s = b.sibling(s); s == nil {
				return err
			}
			_ = s.writeData(p)
		}
	}
	return nil
}

// deliver passes a WireGuard packet received on a session to the device.
func (b *bind) deliver(s *session, p []byte) {
	if len(p) >= 8 && p[0] == 4 {
		// Transport data: remember which server-side keypair the session
		// carries, so replies can fall back to a sibling session.
		s.lastIdx.Store(binary.LittleEndian.Uint32(p[4:8]))
	}
	bp := bufPool.Get().(*[]byte)
	n := copy(*bp, p)
	// A TurnVK client spreads its packets over many paths: in order again
	// before WireGuard (and the TCP behind it) sees them.
	if s.dp != nil {
		if idx, ctr, ok := WGData(p); ok {
			b.reorder.Push(idx, ctr, inbound{bp, n, s})
			return
		}
	}
	b.enqueue(inbound{bp, n, s})
}

func (b *bind) enqueue(in inbound) {
	select {
	case b.in <- in:
	default:
		bufPool.Put(in.b)
	}
}

func (b *bind) add(s *session) {
	b.mu.Lock()
	b.sessions[s] = struct{}{}
	if s.dp != nil && s.dev != "" {
		ps := b.devPaths[s.dev]
		if ps == nil {
			ps = &pathSet{}
			b.devPaths[s.dev] = ps
		}
		// Copy on write: sendDirect walks the list without the lock.
		ps.list = append(ps.list[:len(ps.list):len(ps.list)], s)
	}
	b.mu.Unlock()
}

func (b *bind) remove(s *session) {
	b.mu.Lock()
	delete(b.sessions, s)
	if ps := b.devPaths[s.dev]; ps != nil && s.dp != nil {
		next := make([]*session, 0, len(ps.list))
		for _, x := range ps.list {
			if x != s {
				next = append(next, x)
			}
		}
		ps.list = next
		if len(ps.list) == 0 {
			delete(b.devPaths, s.dev)
		}
	}
	b.mu.Unlock()
}

// sendDirect hands a device's packets to its pacer (pacer.go), which
// sends them over the device's direct paths at the rate VK lets through.
func (b *bind) sendDirect(bufs [][]byte, s *session) error {
	if s.dev == "" {
		for _, p := range bufs {
			if err := s.writeData(p); err != nil {
				return err
			}
		}
		return nil
	}
	b.mu.Lock()
	p := b.pacers[s.dev]
	if p == nil {
		p = newPacer(b, s.dev)
		b.pacers[s.dev] = p
	}
	b.mu.Unlock()
	p.enqueue(bufs)
	return nil
}

// pathStats counts each device's direct paths and averages their RTT.
func (b *bind) pathStats() (paths, rtt map[string]int) {
	paths, rtt = map[string]int{}, map[string]int{}
	b.mu.Lock()
	defer b.mu.Unlock()
	for dev, ps := range b.devPaths {
		sum, n := 0, 0
		for _, s := range ps.list {
			if r := int(s.dp.rtt.Load()); r > 0 {
				sum += r
				n++
			}
		}
		paths[dev] = len(ps.list)
		if n > 0 {
			rtt[dev] = sum / n
		}
	}
	return paths, rtt
}

// sibling picks another live session of the same client (same password
// and same WireGuard keypair) when the one WireGuard chose has gone away.
// A client keeps many parallel sessions, so a dropped TURN allocation
// does not stall the tunnel until the client sends its next packet.
func (b *bind) sibling(dead *session) *session {
	idx := dead.lastIdx.Load()
	if idx == 0 {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	var best *session
	for s := range b.sessions {
		if s == dead || s.dead.Load() || s.keyID != dead.keyID || s.lastIdx.Load() != idx {
			continue
		}
		if best == nil || s.lastRx.Load() > best.lastRx.Load() {
			best = s
		}
	}
	return best
}

// newestFor returns the address of the device's most recently opened live
// session ("" if none).
func (b *bind) newestFor(dev string) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	var best *session
	for s := range b.sessions {
		if s.dev != dev || s.dead.Load() {
			continue
		}
		if best == nil || s.opened > best.opened {
			best = s
		}
	}
	if best == nil {
		return ""
	}
	return best.ep.addr.String()
}

func (b *bind) count() (total int, byKey, byDev map[string]int) {
	byKey, byDev = map[string]int{}, map[string]int{}
	b.mu.Lock()
	defer b.mu.Unlock()
	for s := range b.sessions {
		byKey[s.keyID]++
		if s.dev != "" {
			byDev[s.dev]++
		}
	}
	return len(b.sessions), byKey, byDev
}

// endpoint identifies a session to WireGuard.
type endpoint struct {
	s    *session
	addr netip.AddrPort
}

func (e *endpoint) ClearSrc()           {}
func (e *endpoint) SrcToString() string { return "" }
func (e *endpoint) DstToString() string { return e.addr.String() }
func (e *endpoint) DstToBytes() []byte {
	b, _ := e.addr.MarshalBinary()
	return b
}
func (e *endpoint) DstIP() netip.Addr { return e.addr.Addr() }
func (e *endpoint) SrcIP() netip.Addr { return netip.Addr{} }
