package link

import (
	"net/netip"
	"sync"
	"time"
)

// Cloudflare Mesh carries packets of its interface's MTU at most: 1280 by
// default, lower (down to about 1147) when Cloudflare's client measures a
// smaller path. Clients send packets of up to 1340 bytes and QUIC needs at
// least 1228, so a WireGuard message that does not fit one datagram is cut
// into parts here and put back together on the other side. The link never
// relies on IP fragmentation inside Cloudflare.

// split cuts msg into n parts of near-equal size, none over chunk bytes.
// It returns nil when that takes more than maxParts parts.
func split(msg []byte, chunk int) [][]byte {
	if chunk <= 0 {
		return nil
	}
	n := (len(msg) + chunk - 1) / chunk
	if n < 2 {
		n = 2
	}
	if n > maxParts {
		return nil
	}
	parts := make([][]byte, 0, n)
	base, rem := len(msg)/n, len(msg)%n
	off := 0
	for i := 0; i < n; i++ {
		l := base
		if i < rem {
			l++
		}
		parts = append(parts, msg[off:off+l])
		off += l
	}
	return parts
}

const (
	reasmTimeout = 200 * time.Millisecond
	reasmMax     = 256 // messages being put together at once
)

type reasmKey struct {
	src netip.AddrPort
	id  uint16
}

type partial struct {
	count uint8
	got   uint16 // bit per part
	parts [maxParts][]byte
	size  int
	at    int64 // first part, unix ns
}

// reassembler puts messages cut by split back together. Memory is bounded:
// at most reasmMax messages wait, each at most reasmTimeout.
type reassembler struct {
	mu      sync.Mutex
	pending map[reasmKey]*partial
	adds    int
	// Expired counts messages a part of which never came.
	Expired uint64
}

// add takes one part (copied) and returns the whole message once complete.
func (r *reassembler) add(src netip.AddrPort, id uint16, idx, count int, chunk []byte, now time.Time) []byte {
	if count < 2 || count > maxParts || idx >= count || len(chunk) == 0 {
		return nil
	}
	ns := now.UnixNano()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending == nil {
		r.pending = map[reasmKey]*partial{}
	}
	if r.adds++; r.adds%64 == 0 || len(r.pending) >= reasmMax {
		r.prune(ns)
	}
	k := reasmKey{src, id}
	p := r.pending[k]
	if p != nil && (int(p.count) != count || ns-p.at > int64(reasmTimeout)) {
		// The id came round again, or a stale message: start afresh.
		r.Expired++
		delete(r.pending, k)
		p = nil
	}
	if p == nil {
		if len(r.pending) >= reasmMax {
			r.Expired++
			return nil
		}
		p = &partial{count: uint8(count), at: ns}
		r.pending[k] = p
	}
	bit := uint16(1) << idx
	if p.got&bit != 0 {
		return nil // a duplicate
	}
	p.got |= bit
	p.parts[idx] = append([]byte(nil), chunk...)
	p.size += len(chunk)
	if p.got != uint16(1)<<count-1 {
		return nil
	}
	delete(r.pending, k)
	msg := make([]byte, 0, p.size)
	for i := 0; i < count; i++ {
		msg = append(msg, p.parts[i]...)
	}
	return msg
}

func (r *reassembler) prune(ns int64) {
	for k, p := range r.pending {
		if ns-p.at > int64(reasmTimeout) {
			delete(r.pending, k)
			r.Expired++
		}
	}
}

// waiting reports how many messages wait for parts.
func (r *reassembler) waiting() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.pending)
}
