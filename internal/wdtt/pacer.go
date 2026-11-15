package wdtt

import (
	"encoding/binary"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// The pacer sends a device's packets over its direct paths, each path at
// the rate its PathRate allows (pace.go), so the queue forms here, where
// it can be managed:
//   - small packets (pings, TCP ACKs, DNS, games, calls) go first, and the
//     smallest go on two paths at once: whichever arrives first counts,
//     WireGuard drops the other as a replay;
//   - bulk packets that have waited longer than maxQueueDelay are dropped,
//     which tells TCP to slow down before a long queue builds.
const (
	maxQueueDelay = 60 * time.Millisecond
	maxQueueBytes = 4 << 20
	smallPacket   = 512 // smaller packets are latency-sensitive
	dupPacket     = 256 // smaller packets go on two paths
	bulkRun       = 4   // bulk packets kept on one path in a row
)

type queued struct {
	b  *[]byte
	n  int
	at int64
}

// pacer sends one device's packets over its direct paths.
type pacer struct {
	b   *bind
	dev string

	mu       sync.Mutex
	hi, lo   []queued // small and bulk packets, oldest first
	loBytes  int
	last     *session // path of the last bulk packet
	run      int
	idleFrom int64

	wake    chan struct{}
	dropped atomic.Uint64
}

func newPacer(b *bind, dev string) *pacer {
	p := &pacer{b: b, dev: dev, wake: make(chan struct{}, 1)}
	go p.loop()
	return p
}

// enqueue copies the packets in (WireGuard reuses its buffers).
func (p *pacer) enqueue(bufs [][]byte) {
	now := time.Now().UnixNano()
	p.mu.Lock()
	for _, x := range bufs {
		bp := bufPool.Get().(*[]byte)
		if len(x) > len(*bp) {
			bufPool.Put(bp)
			continue
		}
		q := queued{bp, copy(*bp, x), now}
		if len(x) < smallPacket {
			p.hi = append(p.hi, q)
		} else if p.loBytes+len(x) <= maxQueueBytes {
			p.lo = append(p.lo, q)
			p.loBytes += len(x)
		} else {
			bufPool.Put(bp)
			p.dropped.Add(1)
		}
	}
	p.mu.Unlock()
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

type sendItem struct {
	s   *session
	q   queued
	dup bool // the first copy owns the buffer
}

// loop sends whatever the paths' rates allow, then sleeps until the next
// packet can go. It ends when the device has no paths left for a while.
func (p *pacer) loop() {
	t := time.NewTimer(time.Hour)
	defer t.Stop()
	var out []sendItem
	for {
		var wait time.Duration
		out, wait = p.step(out[:0])
		for _, it := range out {
			_ = it.s.writeData((*it.q.b)[:it.q.n])
		}
		for _, it := range out {
			if !it.dup {
				bufPool.Put(it.q.b)
			}
		}
		if wait < 0 {
			return
		}
		if len(out) > 0 && wait == 0 {
			continue
		}
		if wait == 0 {
			wait = time.Hour
		}
		t.Reset(wait)
		select {
		case <-t.C:
		case <-p.wake:
		}
	}
}

const pacerIdleExit = 2 * time.Minute

// step picks the packets that can go now. wait is how long until the next
// one can (0: queue empty, wait for new packets; <0: the pacer ends).
func (p *pacer) step(out []sendItem) ([]sendItem, time.Duration) {
	now := time.Now().UnixNano()
	fresh := now - int64(pathFresh)
	p.b.mu.Lock()
	var list []*session
	if ps := p.b.devPaths[p.dev]; ps != nil {
		list = ps.list
	}
	p.b.mu.Unlock()

	p.mu.Lock()
	defer p.mu.Unlock()
	if len(list) == 0 {
		// No path (yet, or any more): hold the packets briefly.
		p.dropOld(now, true)
		if len(p.hi)+len(p.lo) == 0 {
			if p.idleFrom == 0 {
				p.idleFrom = now
			} else if now-p.idleFrom > int64(pacerIdleExit) {
				p.b.mu.Lock()
				if p.b.pacers[p.dev] == p && p.b.devPaths[p.dev] == nil {
					delete(p.b.pacers, p.dev)
					p.b.mu.Unlock()
					return out, -1
				}
				p.b.mu.Unlock()
			}
			return out, time.Second
		}
		return out, 20 * time.Millisecond
	}
	p.idleFrom = 0
	for _, s := range list {
		s.dp.pr.Refill(now)
	}
	p.dropOld(now, false)

	// Small packets first, then bulk; each on the path it arrives first on.
	for len(p.hi) > 0 {
		q := p.hi[0]
		s := p.pick(list, q.n, now, fresh, nil, false)
		if s == nil {
			break
		}
		out = append(out, sendItem{s: s, q: q})
		if q.n < dupPacket {
			if s2 := p.pick(list, q.n, now, fresh, s, false); s2 != nil {
				out = append(out, sendItem{s: s2, q: q, dup: true})
			}
		}
		p.hi = p.hi[1:]
	}
	for len(p.hi) == 0 && len(p.lo) > 0 {
		s := p.pick(list, p.lo[0].n, now, fresh, nil, true)
		if s == nil {
			break
		}
		out = append(out, sendItem{s: s, q: p.lo[0]})
		p.loBytes -= p.lo[0].n
		p.lo = p.lo[1:]
	}
	if len(p.hi) == 0 {
		p.hi = nil
	}
	if len(p.lo) == 0 {
		p.lo = nil
	}
	head := 0
	switch {
	case len(p.hi) > 0:
		head = p.hi[0].n
	case len(p.lo) > 0:
		head = p.lo[0].n
	default:
		return out, 0
	}
	// Until some path has the tokens for the next packet.
	best := time.Duration(math.MaxInt64)
	for _, s := range list {
		if s.dead.Load() || s.dp.lastRx.Load() < fresh {
			continue
		}
		pr := &s.dp.pr
		pr.Limited.Store(true)
		best = min(best, pr.Wait(float64(head+MaxWireOverhead)))
	}
	if best == time.Duration(math.MaxInt64) {
		// No fresh path: send on any live one rather than not at all.
		for _, s := range list {
			if !s.dead.Load() {
				for _, q := range p.hi {
					out = append(out, sendItem{s: s, q: q})
				}
				for _, q := range p.lo {
					out = append(out, sendItem{s: s, q: q})
				}
				p.hi, p.lo, p.loBytes = nil, nil, 0
				return out, 0
			}
		}
		return out, 20 * time.Millisecond
	}
	return out, max(best, 200*time.Microsecond)
}

// dropOld drops bulk packets that waited longer than maxQueueDelay (and,
// with no path at all, small ones that waited ten times as long).
func (p *pacer) dropOld(now int64, noPath bool) {
	cut := now - int64(maxQueueDelay)
	for len(p.lo) > 0 && p.lo[0].at < cut {
		p.loBytes -= p.lo[0].n
		bufPool.Put(p.lo[0].b)
		p.lo = p.lo[1:]
		p.dropped.Add(1)
	}
	if noPath {
		cut = now - int64(10*maxQueueDelay)
		for len(p.hi) > 0 && p.hi[0].at < cut {
			bufPool.Put(p.hi[0].b)
			p.hi = p.hi[1:]
			p.dropped.Add(1)
		}
	}
}

// pick returns the path that can send n bytes now and gets them there
// first (not skip), and books the bytes on it; nil if none has the tokens.
func (p *pacer) pick(list []*session, n int, now, fresh int64, skip *session, bulk bool) *session {
	size := float64(n + MaxWireOverhead)
	var best *session
	bestScore := 0.0
	for _, s := range list {
		pr := &s.dp.pr
		if s == skip || s.dead.Load() || s.dp.lastRx.Load() < fresh || pr.Tokens < size {
			continue
		}
		// Half the round trip, less a bonus for spare tokens (spreads load).
		score := float64(s.dp.rtt.Load())/2000 - pr.Tokens/pr.Get()
		if best == nil || score < bestScore {
			best, bestScore = s, score
		}
	}
	if best == nil {
		return nil
	}
	if bulk {
		if l := p.last; l != nil && l != best && p.run < bulkRun && !l.dead.Load() &&
			l.dp.lastRx.Load() >= fresh && l.dp.pr.Tokens >= size {
			best = l
		}
		if best == p.last {
			p.run++
		} else {
			p.last, p.run = best, 1
		}
	}
	best.dp.pr.Tokens -= size
	return best
}

// pathReport reads the loss report a client appends to its PING:
// cumulative packets received and lost on the path (4 bytes each).
func pathReport(msg []byte) (recv, lost uint32, ok bool) {
	if len(msg) < 20 {
		return 0, 0, false
	}
	return binary.BigEndian.Uint32(msg[12:16]), binary.BigEndian.Uint32(msg[16:20]), true
}
