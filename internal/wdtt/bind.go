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
}

type inbound struct {
	b *[]byte
	n int
	s *session
}

const bindBatch = 32

func newBind() *bind {
	return &bind{in: make(chan inbound, 4096), closed: make(chan struct{}), sessions: map[*session]struct{}{}}
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

func (b *bind) ParseEndpoint(string) (conn.Endpoint, error) {
	return nil, errors.New("endpoints are learned from sessions")
}

func (b *bind) Send(bufs [][]byte, ep conn.Endpoint) error {
	e, ok := ep.(*endpoint)
	if !ok {
		return errors.New("unknown endpoint")
	}
	s := e.s
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
	select {
	case b.in <- inbound{bp, n, s}:
	default:
		bufPool.Put(bp)
	}
}

func (b *bind) add(s *session) {
	b.mu.Lock()
	b.sessions[s] = struct{}{}
	b.mu.Unlock()
}

func (b *bind) remove(s *session) {
	b.mu.Lock()
	delete(b.sessions, s)
	b.mu.Unlock()
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

func (b *bind) count() (total int, byKey map[string]int) {
	byKey = map[string]int{}
	b.mu.Lock()
	defer b.mu.Unlock()
	for s := range b.sessions {
		byKey[s.keyID]++
	}
	return len(b.sessions), byKey
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
