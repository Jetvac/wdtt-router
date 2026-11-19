package wdtt

// This file is shared by the TurnVK server (wdtt-router, internal/wdtt) and
// the TurnVK client (turn-vk-client, core/session); only the package line
// differs. Keep the two copies the same.
//
// VK polices each TURN allocation: what goes over its rate in a burst is
// dropped, nearly all of it, until the allowance refills. Sent as fast as
// it comes, traffic alternates between full speed and heavy loss; TCP
// stalls, and pings wait or vanish with it. Each direction of each path
// is therefore paced (PathRate) at a rate that follows what the receiver
// reports:
//   - FEEDBACK, sent by the receiver at most every feedbackEvery while data
//     arrives: the latest RTP sequence number, how long ago it arrived, and
//     the packets received and lost so far. The sender knows when it sent
//     that packet, so each FEEDBACK is a delay sample of the data itself;
//   - every adjustEvery the rate goes down on loss or when the delay grows
//     over the path's base (VK queues before it drops), and up while the
//     path is clean, quick and the sender had more to send: by
//     growFast until the first sign of congestion, then by growSlow;
//   - a new path starts at the rate paths through the same TURN server
//     settled at lately (LearnedRates), not from scratch.
// Older clients send no FEEDBACK; the loss and round trip in their PINGs
// (every 2 s) steer the rate instead (Report).

import (
	"encoding/binary"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

const (
	msgFeedback = 0x48

	initialPathRate = 220_000   // bytes/s per path to start with (~1.75 Mbit/s)
	minPathRate     = 40_000    // bytes/s
	maxPathRate     = 2_500_000 // bytes/s
	pathBurst       = 24_000    // bytes a path may send at once after a pause

	feedbackEvery = 50 * time.Millisecond
	adjustEvery   = 100 * time.Millisecond
	baseWindow    = 10 * time.Second // the base delay is the least seen within this
	queueDelay    = 25 * time.Millisecond
	// While interactive traffic flows (Interactive): VK's queue is kept
	// shorter, at some cost to the speed of downloads beside it.
	tightQueueDelay = 10 * time.Millisecond
	tightBurst      = 8_000
	// TightBulkWait: bulk packets that waited longer are dropped then
	// (instead of the pacers' usual 60 ms).
	TightBulkWait = 25 * time.Millisecond
	tightRate     = 20 // small packets a second that make traffic interactive
	tightHold     = 5 * time.Second
	quickDelay    = 8 * time.Millisecond
	// Loss is judged over at least lossJudge packets and must exceed
	// lossCut: VK's policer drops in bursts and crosses it at once, while
	// random loss of a few percent (mobile networks) does not slow a path.
	lossJudge  = 100
	lossCut    = 0.05
	delayFloor = initialPathRate / 2
	growFast   = 1.08 // per adjustment, until the first congestion
	growSlow   = 1.02
	learnedAge = 30 * time.Minute

	// PING reports (older clients).
	queueRTT  = 30              // ms over the base round trip: VK is queueing
	quickRTT  = 15              // ms over it: no queue to speak of
	minRTTAge = 2 * time.Minute // the base is measured afresh this often
)

// PathRate paces one direction of one path. Tokens and At belong to the
// pacer that sends on the path; the rest is safe for concurrent use.
type PathRate struct {
	rate    atomic.Int64 // bytes/s; 0 until the first change: initialPathRate
	Tokens  float64
	At      int64       // unix ns of the last refill
	Limited atomic.Bool // packets waited for this path since the last adjustment
	// Tight: interactive traffic flows (the pacer sets it): a smaller
	// burst and a lower queue delay before the rate goes down.
	Tight atomic.Bool

	mu       sync.Mutex
	sentSeq  [1024]uint16
	sentAt   [1024]int64
	fbSeen   time.Time // last FEEDBACK
	base     [2]int64  // least delay in this and the previous window, ns
	baseAt   int64     // start of the current window
	delay    float64   // smoothed delay, ns
	lossRecv uint32
	lossLost uint32
	lossSeen bool
	adjusted int64
	lastLoss float64 // at the last judgement
	lastQ    float64 // queue delay at the last adjustment, ns
	settled  bool    // congestion seen: growth is growSlow from now on

	// PING reports (older clients).
	repRecv, repLost uint32
	repSeen          bool
	minRTT           int32 // ms
	minAt            int64
}

// Get is the current rate in bytes/s.
func (r *PathRate) Get() float64 {
	if v := r.rate.Load(); v > 0 {
		return float64(v)
	}
	return initialPathRate
}

func (r *PathRate) set(v float64) {
	r.rate.Store(int64(math.Max(minPathRate, math.Min(maxPathRate, v))))
}

// Refill adds the tokens earned since the last call.
func (r *PathRate) Refill(now int64) {
	if r.At == 0 {
		r.Tokens, r.At = pathBurst, now
		return
	}
	r.Tokens = math.Min(r.burst(), r.Tokens+r.Get()*float64(now-r.At)/1e9)
	r.At = now
}

// Queued estimates how long what the path sent lately takes to get
// through (s): the part of its burst it used, at its rate; zero after a
// pause. Under the pacer's lock, like Tokens.
func (r *PathRate) Queued() float64 { return math.Max(0, r.burst()-r.Tokens) / r.Get() }

// burst is how many bytes the path may send at once after a pause.
func (r *PathRate) burst() float64 {
	if r.Tight.Load() {
		return tightBurst
	}
	return pathBurst
}

// Wait is how long until the path has the tokens for size bytes.
func (r *PathRate) Wait(size float64) time.Duration {
	need := size - r.Tokens
	if need <= 0 {
		return 0
	}
	return time.Duration(need / r.Get() * 1e9)
}

// OnSend records when the packet with this RTP sequence number went out.
func (r *PathRate) OnSend(seq uint16, now int64) {
	i := seq & 1023
	r.mu.Lock()
	r.sentSeq[i], r.sentAt[i] = seq, now
	r.mu.Unlock()
}

// HasFeedback reports whether the receiver sends FEEDBACK (recently).
func (r *PathRate) HasFeedback() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return !r.fbSeen.IsZero() && time.Since(r.fbSeen) < 5*time.Second
}

// OnFeedback applies a FEEDBACK message (see Feedback).
func (r *PathRate) OnFeedback(msg []byte, now int64) {
	if len(msg) < 14 {
		return
	}
	seq := binary.BigEndian.Uint16(msg[2:4])
	hold := int64(binary.BigEndian.Uint16(msg[4:6])) * 100_000 // 0.1 ms units
	recv := binary.BigEndian.Uint32(msg[6:10])
	lost := binary.BigEndian.Uint32(msg[10:14])

	r.mu.Lock()
	defer r.mu.Unlock()
	r.fbSeen = time.Unix(0, now)
	i := seq & 1023
	if r.sentSeq[i] == seq && r.sentAt[i] > 0 {
		if d := now - r.sentAt[i] - hold; d > 0 && d < int64(5*time.Second) {
			if r.baseAt == 0 || now-r.baseAt > int64(baseWindow/2) {
				r.base[1], r.base[0], r.baseAt = r.base[0], 0, now
			}
			if r.base[0] == 0 || d < r.base[0] {
				r.base[0] = d
			}
			if r.delay == 0 {
				r.delay = float64(d)
			} else {
				r.delay += (float64(d) - r.delay) / 4
			}
		}
	}
	if now-r.adjusted < int64(adjustEvery) {
		return
	}
	r.adjusted = now

	loss := -1.0
	if !r.lossSeen {
		r.lossRecv, r.lossLost, r.lossSeen = recv, lost, true
	} else if dr, dl := recv-r.lossRecv, lost-r.lossLost; dr > 1<<30 || dl > 1<<30 {
		r.lossRecv, r.lossLost = recv, lost // counters restarted
	} else if dr+dl >= lossJudge {
		loss = float64(dl) / float64(dr+dl)
		r.lossRecv, r.lossLost = recv, lost
		r.lastLoss = loss
	}
	base := r.base[0]
	if r.base[1] > 0 && (base == 0 || r.base[1] < base) {
		base = r.base[1]
	}
	q := 0.0
	if base > 0 && r.delay > 0 {
		q = r.delay - float64(base)
	}
	r.lastQ = q
	limited := r.Limited.Swap(false)
	cur := r.Get()
	switch {
	case loss > lossCut:
		r.set(cur * 0.85)
		r.settled = true
	case q > float64(r.queueLimit()) && cur > delayFloor:
		// Delay alone never takes a path below delayFloor: jitter on
		// VK's side must not starve it; only real loss goes lower.
		r.set(math.Max(delayFloor, cur*0.92))
		r.settled = true
	case limited && q < float64(quickDelay) && loss < 0.01:
		if r.settled {
			r.set(cur * growSlow)
		} else {
			r.set(cur * growFast)
		}
	}
}

// queueLimit: VK's queue (delay over the base) above which the rate goes
// down.
func (r *PathRate) queueLimit() time.Duration {
	if r.Tight.Load() {
		return tightQueueDelay
	}
	return queueDelay
}

// Interactive notices traffic that wants a low latency (games, calls): a
// steady stream of small packets, at least tightRate a second. While it
// flows, and tightHold after, the pacer keeps queues short (Tight,
// TightBulkWait). Under the pacer's lock.
type Interactive struct {
	from  int64 // start of the current second, unix ns
	n     int   // small packets in it
	until int64 // interactive until then
	// Secs: seconds spent interactive (statistics).
	Secs atomic.Uint64
}

// Note counts small packets queued at now and tells whether the traffic
// is interactive.
func (t *Interactive) Note(now int64, small int) bool {
	t.n += small
	if now-t.from >= int64(time.Second) {
		if t.n >= tightRate && t.from != 0 {
			t.until = now + int64(tightHold)
		}
		if now < t.until {
			t.Secs.Add(1)
		}
		t.from, t.n = now, 0
	}
	return now < t.until
}

// Seed sets the rate a new path starts at.
func (r *PathRate) Seed(rate float64) {
	if rate > 0 {
		r.set(rate)
	}
}

// LearnedRates remembers the rate paths through each TURN server settled
// at, so that new paths through it start there.
type LearnedRates struct {
	mu sync.Mutex
	m  map[string]learnedRate
}

type learnedRate struct {
	rate float64
	at   time.Time
}

// Start is the rate for a new path through the TURN server key: a little
// under what paths there settled at lately, or initialPathRate.
func (l *LearnedRates) Start(key string) float64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	v, ok := l.m[key]
	if !ok || time.Since(v.at) > learnedAge {
		return initialPathRate
	}
	return math.Max(initialPathRate, v.rate*0.9)
}

// Note records the rate a path through key settled at, when it ends.
// Paths that never met congestion taught nothing and are skipped.
func (l *LearnedRates) Note(key string, r *PathRate) {
	r.mu.Lock()
	settled := r.settled
	r.mu.Unlock()
	if !settled {
		return
	}
	rate := r.Get()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.m == nil {
		l.m = map[string]learnedRate{}
	}
	if v, ok := l.m[key]; ok && time.Since(v.at) < learnedAge {
		rate = (v.rate + rate) / 2
	}
	l.m[key] = learnedRate{rate, time.Now()}
}

// State is what the controller last saw: the rate (bytes/s), the loss
// the receiver reported, and the queue delay over the path's base.
func (r *PathRate) State() (rate, loss float64, queue time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.Get(), r.lastLoss, time.Duration(r.lastQ)
}

// Report applies the loss and round trip in an older client's PING:
// cumulative packets received and lost, round trip in ms (0: unknown).
// Ignored while the client sends FEEDBACK.
func (r *PathRate) Report(recv, lost uint32, rtt int32) {
	if r.HasFeedback() {
		return
	}
	if rtt > 0 {
		now := time.Now().UnixNano()
		if r.minRTT == 0 || rtt < r.minRTT || now-r.minAt > int64(minRTTAge) {
			r.minRTT, r.minAt = rtt, now
		}
	}
	if !r.repSeen {
		r.repRecv, r.repLost, r.repSeen = recv, lost, true
		return
	}
	dr, dl := recv-r.repRecv, lost-r.repLost
	if dr > 1<<30 || dl > 1<<30 {
		r.repRecv, r.repLost = recv, lost
		return
	}
	if dr+dl < 40 {
		return
	}
	r.repRecv, r.repLost = recv, lost
	loss := float64(dl) / float64(dr+dl)
	queued := rtt > 0 && r.minRTT > 0 && rtt > r.minRTT+queueRTT
	quick := rtt == 0 || r.minRTT == 0 || rtt <= r.minRTT+quickRTT
	limited := r.Limited.Swap(false)
	cur := r.Get()
	switch {
	case loss > 0.03:
		r.set(cur * 0.8)
	case queued:
		r.set(cur * 0.9)
	case loss < 0.005 && limited && quick:
		r.set(cur * 1.08)
	}
}

// RxTrack is the receiving side of one path: it counts the sender's RTP
// sequence numbers and says when to send FEEDBACK. Used from the path's
// read loop only.
type RxTrack struct {
	Recv, Lost uint32
	seen       bool
	next       uint16
	last       uint16 // latest sequence number
	lastAt     int64
	sentAt     int64 // last FEEDBACK
}

// Seen counts one packet; true when a FEEDBACK is due.
func (t *RxTrack) Seen(seq uint16, now int64) bool {
	t.Recv++
	switch d := int16(seq - t.next); {
	case !t.seen:
		t.seen, t.next = true, seq+1
	case d == 0:
		t.next++
	case d > 0 && d < 512:
		t.Lost += uint32(d)
		t.next = seq + 1
	case d < 0 && d > -512:
		if t.Lost > 0 {
			t.Lost-- // late, counted as lost when the gap was seen
		}
		return false
	default:
		t.next = seq + 1 // a new stream
	}
	t.last, t.lastAt = seq, now
	return now-t.sentAt >= int64(feedbackEvery)
}

// Feedback builds the FEEDBACK message and notes that it went out.
//
//	type(1) version(1) seq(2) hold(2, 0.1 ms) received(4) lost(4)
func (t *RxTrack) Feedback(version byte, now int64) []byte {
	hold := (now - t.lastAt) / 100_000
	if hold > 65535 {
		hold = 65535
	}
	b := make([]byte, 14)
	b[0], b[1] = msgFeedback, version
	binary.BigEndian.PutUint16(b[2:4], t.last)
	binary.BigEndian.PutUint16(b[4:6], uint16(hold))
	binary.BigEndian.PutUint32(b[6:10], t.Recv)
	binary.BigEndian.PutUint32(b[10:14], t.Lost)
	t.sentAt = now
	return b
}
