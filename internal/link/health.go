package link

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// Thresholds of the entry's choice between the tunnel and Xray.
type Thresholds struct {
	Down       time.Duration // no answer to probes this long: leave the tunnel
	Up         time.Duration // healthy this long: come back
	Grace      time.Duration // after a start, what the previous run decided stands this long
	Handshake  time.Duration // WireGuard's last handshake older than this: broken
	HSStart    time.Duration // the first handshake may take this long
	E2EFails   int           // DNS through the tunnel failed this many times in a row
	FlapCount  int           // leaving the tunnel this many times …
	FlapWindow time.Duration // … within this window …
	FlapHold   time.Duration // … keeps UDP on Xray this long
}

// DefaultThresholds: see docs/chain-link.md.
var DefaultThresholds = Thresholds{
	Down: 3 * time.Second, Up: 30 * time.Second, Grace: 5 * time.Second,
	Handshake: 3 * time.Minute, HSStart: 15 * time.Second, E2EFails: 3,
	FlapCount: 3, FlapWindow: 15 * time.Minute, FlapHold: 15 * time.Minute,
}

// Signals are what the choice is made from.
type Signals struct {
	Now       time.Time
	Started   time.Time // this run of the service
	LastReply time.Time // last answer to a probe (zero: none yet)
	Handshake time.Time // WireGuard's last handshake (zero: none yet)
	E2EFails  int       // DNS checks through the tunnel failed in a row
	Allowed   bool      // the mode lets client traffic use the tunnel
}

// Health decides whether client UDP goes through the tunnel. The decision
// itself lives in the kernel (an nftables set element with a timeout that
// the service keeps renewing), so a service that stops simply lets it lapse.
type Health struct {
	T Thresholds

	mu        sync.Mutex
	want      bool
	inherited bool
	goodSince time.Time
	left      []time.Time // when UDP left the tunnel
	holdUntil time.Time
	problem   string
	switchAt  time.Time
	switchTo  string
	switchWhy string
}

// Inherit: the previous run of the service had UDP on the tunnel; keep it
// there through the Grace period while this run comes up.
func (h *Health) Inherit() {
	h.mu.Lock()
	h.want, h.inherited = true, true
	h.mu.Unlock()
}

// check returns "" when the tunnel is healthy, or what is wrong.
func (h *Health) check(s Signals) string {
	t := h.T
	young := s.Now.Sub(s.Started)
	switch {
	case s.LastReply.IsZero() && young < t.Grace:
		if !h.inherited {
			return "ещё нет ответа на пробы"
		}
	case s.LastReply.IsZero() || s.Now.Sub(s.LastReply) > t.Down:
		return fmt.Sprintf("нет ответа %s", s.Now.Sub(maxTime(s.LastReply, s.Started)).Round(time.Second))
	}
	if s.Handshake.IsZero() {
		if young >= t.HSStart {
			return "нет рукопожатия WireGuard"
		}
	} else if s.Now.Sub(s.Handshake) > t.Handshake {
		return "рукопожатие WireGuard устарело"
	}
	if s.E2EFails >= t.E2EFails {
		return "DNS через туннель не отвечает"
	}
	return ""
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// Step takes new signals and reports whether the decision changed.
func (h *Health) Step(s Signals) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.inherited && s.Now.Sub(s.Started) >= h.T.Grace {
		h.inherited = false
	}
	h.problem = h.check(s)
	healthy := h.problem == ""
	if !healthy {
		h.goodSince = time.Time{}
	} else if h.goodSince.IsZero() {
		h.goodSince = s.Now
	}
	switch {
	case h.want && !s.Allowed:
		h.want = false
		h.note(s.Now, "xray", "режим без туннеля")
		return true
	case h.want && !healthy:
		h.want = false
		h.left = append(h.left, s.Now)
		cut := s.Now.Add(-h.T.FlapWindow)
		for len(h.left) > 0 && h.left[0].Before(cut) {
			h.left = h.left[1:]
		}
		why := h.problem
		if len(h.left) >= h.T.FlapCount {
			h.holdUntil = s.Now.Add(h.T.FlapHold)
			h.left = nil
			why += fmt.Sprintf("; переключений слишком много, UDP остаётся на Xray до %s", h.holdUntil.Format("15:04"))
		}
		h.note(s.Now, "xray", why)
		return true
	case !h.want && s.Allowed && healthy && s.Now.Sub(h.goodSince) >= h.T.Up && !s.Now.Before(h.holdUntil):
		h.want = true
		h.note(s.Now, "link", fmt.Sprintf("туннель исправен %s", s.Now.Sub(h.goodSince).Round(time.Second)))
		return true
	}
	return false
}

func (h *Health) note(at time.Time, to, why string) {
	h.switchAt, h.switchTo, h.switchWhy = at, to, why
}

// HealthState is a snapshot for the status file.
type HealthState struct {
	Want      bool
	Problem   string
	HoldUntil time.Time
	SwitchAt  time.Time
	SwitchTo  string
	SwitchWhy string
}

func (h *Health) State() HealthState {
	h.mu.Lock()
	defer h.mu.Unlock()
	return HealthState{Want: h.want, Problem: h.problem, HoldUntil: h.holdUntil, SwitchAt: h.switchAt, SwitchTo: h.switchTo, SwitchWhy: h.switchWhy}
}

// tracker records the probes of the entry and their answers.
type tracker struct {
	mu        sync.Mutex
	seq       uint32
	recs      [256]probeRec // ring by seq
	lastReply time.Time
}

type probeRec struct {
	seq  uint32
	at   time.Time
	size int
	mtu  bool
	rtt  time.Duration // 0: no answer (yet)
	ok   bool
}

func (t *tracker) next(now time.Time, size int, mtu bool) uint32 {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.seq++
	t.recs[t.seq%uint32(len(t.recs))] = probeRec{seq: t.seq, at: now, size: size, mtu: mtu}
	return t.seq
}

// answer records a reply; it returns the probe it answers (ok false: unknown
// or stale).
func (t *tracker) answer(r Reply) (probeRec, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	p := &t.recs[r.Seq%uint32(len(t.recs))]
	if p.seq != r.Seq || p.ok || p.at.UnixNano() != r.Sent {
		return probeRec{}, false
	}
	p.ok, p.rtt = true, r.At.Sub(p.at)
	if r.At.After(t.lastReply) {
		t.lastReply = r.At
	}
	return *p, true
}

func (t *tracker) last() time.Time {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.lastReply
}

// stats over plain probes sent within the last minute (those younger than
// 2 s may still be answered and do not count as lost).
func (t *tracker) stats(now time.Time) (p50, p95 time.Duration, loss float64, n int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	var rtts []time.Duration
	sent, lost := 0, 0
	for _, p := range t.recs {
		if p.seq == 0 || p.mtu || now.Sub(p.at) > time.Minute {
			continue
		}
		if p.ok {
			rtts = append(rtts, p.rtt)
			sent++
		} else if now.Sub(p.at) > 2*time.Second {
			sent++
			lost++
		}
	}
	if sent > 0 {
		loss = float64(lost) / float64(sent)
	}
	if len(rtts) == 0 {
		return 0, 0, loss, 0
	}
	sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })
	return rtts[len(rtts)/2], rtts[min(len(rtts)-1, len(rtts)*95/100)], loss, len(rtts)
}
