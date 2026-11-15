package wdtt

// This file is shared by the TurnVK server (wdtt-router, internal/wdtt) and
// the TurnVK client (turn-vk-client, core/engine); only the package line
// differs. Keep the two copies the same.
//
// Spread over many routes, WireGuard packets arrive out of order, and many
// TCP stacks take reordering for loss and slow down. A WireGuard data
// packet carries its receiver index and counter in the clear, so the
// receiving side puts them back in order before WireGuard sees them: a
// packet that comes early waits until the ones before it arrive, at most
// ReorderHold; then whatever is held goes on in order and the gap is
// counted as lost. Late packets and duplicates pass at once (WireGuard
// drops replays itself).

import (
	"encoding/binary"
	"sort"
	"sync"
	"time"
)

const (
	ReorderHold  = 10 * time.Millisecond
	reorderMax   = 512             // packets held per stream before giving up
	reorderJump  = 4096            // a counter this far ahead starts afresh
	reorderStale = 2 * time.Minute // streams unused this long are forgotten
)

// WGData returns the receiver index and counter of a WireGuard transport
// data packet; ok is false for other messages.
func WGData(p []byte) (idx uint32, counter uint64, ok bool) {
	if len(p) < 32 || p[0] != 4 || p[1] != 0 || p[2] != 0 || p[3] != 0 {
		return 0, 0, false
	}
	return binary.LittleEndian.Uint32(p[4:8]), binary.LittleEndian.Uint64(p[8:16]), true
}

// Reorder puts WireGuard data packets back in counter order, per receiver
// index. Out is called with each item in order, from Push or from a timer.
type Reorder[T any] struct {
	Out  func(T)
	Hold time.Duration // 0: ReorderHold

	mu      sync.Mutex
	streams map[uint32]*reorderStream[T]
	pushes  int

	Held, Late, Gaps uint64 // counters, under mu
}

type reorderStream[T any] struct {
	next  uint64 // the counter expected next
	held  map[uint64]T
	timer *time.Timer
	used  time.Time
}

// Push hands one item on, now or once the packets before it arrived.
func (r *Reorder[T]) Push(idx uint32, counter uint64, item T) {
	var out []T
	r.mu.Lock()
	if r.streams == nil {
		r.streams = map[uint32]*reorderStream[T]{}
	}
	now := time.Now()
	r.pushes++
	if r.pushes%4096 == 0 {
		for k, s := range r.streams {
			if len(s.held) == 0 && now.Sub(s.used) > reorderStale {
				delete(r.streams, k)
			}
		}
	}
	s := r.streams[idx]
	if s == nil {
		s = &reorderStream[T]{next: counter, held: map[uint64]T{}}
		r.streams[idx] = s
	}
	s.used = now
	switch {
	case counter == s.next:
		out = append(out, item)
		s.next++
		out = s.drain(out)
	case counter < s.next:
		r.Late++
		out = append(out, item) // late or a duplicate: WireGuard decides
	case counter-s.next > reorderJump || len(s.held) >= reorderMax:
		// Far ahead, or too much held: give up on the gap.
		out = s.flush(out)
		r.Gaps++
		out = append(out, item)
		s.next = counter + 1
	default:
		if _, dup := s.held[counter]; !dup {
			s.held[counter] = item
			r.Held++
		}
		if s.timer == nil {
			hold := r.Hold
			if hold <= 0 {
				hold = ReorderHold
			}
			s.timer = time.AfterFunc(hold, func() { r.expire(idx, s) })
		}
	}
	if len(s.held) == 0 && s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	r.mu.Unlock()
	for _, it := range out {
		r.Out(it)
	}
}

// expire: the gap did not fill in time; send what is held, in order.
func (r *Reorder[T]) expire(idx uint32, s *reorderStream[T]) {
	r.mu.Lock()
	if r.streams[idx] != s {
		r.mu.Unlock()
		return
	}
	s.timer = nil
	var out []T
	if len(s.held) > 0 {
		r.Gaps++
		out = s.flush(nil)
	}
	r.mu.Unlock()
	for _, it := range out {
		r.Out(it)
	}
}

// drain appends the held packets that follow on now.
func (s *reorderStream[T]) drain(out []T) []T {
	for {
		it, ok := s.held[s.next]
		if !ok {
			return out
		}
		delete(s.held, s.next)
		out = append(out, it)
		s.next++
	}
}

// flush appends everything held, in counter order, and moves past it.
func (s *reorderStream[T]) flush(out []T) []T {
	if len(s.held) == 0 {
		return out
	}
	keys := make([]uint64, 0, len(s.held))
	for k := range s.held {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	for _, k := range keys {
		out = append(out, s.held[k])
		delete(s.held, k)
	}
	s.next = keys[len(keys)-1] + 1
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	return out
}
