package link

import (
	"strings"
	"testing"
	"time"
)

// run steps h once a second from start for d with the signals sig gives,
// and returns the decision at the end.
func run(h *Health, start time.Time, from, to time.Duration, sig func(now time.Time) Signals) bool {
	for d := from; d <= to; d += time.Second {
		h.Step(sig(start.Add(d)))
	}
	return h.State().Want
}

func healthy(start time.Time) func(time.Time) Signals {
	return func(now time.Time) Signals {
		return Signals{Now: now, Started: start, LastReply: now, Handshake: now, Allowed: true}
	}
}

func silent(start, since time.Time) func(time.Time) Signals {
	return func(now time.Time) Signals {
		return Signals{Now: now, Started: start, LastReply: since, Handshake: now, Allowed: true}
	}
}

func TestHealthComesUpAfterAWhile(t *testing.T) {
	h := &Health{T: DefaultThresholds}
	start := time.Now()
	if run(h, start, 0, 29*time.Second, healthy(start)) {
		t.Fatal("on the tunnel before Up")
	}
	if !run(h, start, 30*time.Second, 31*time.Second, healthy(start)) {
		t.Fatal("not on the tunnel after Up")
	}
	// Not allowed (mode "check"): off at once.
	h.Step(Signals{Now: start.Add(32 * time.Second), Started: start, LastReply: start.Add(32 * time.Second), Allowed: false})
	if h.State().Want {
		t.Fatal("on the tunnel in check mode")
	}
}

func TestHealthRidesOutShortGaps(t *testing.T) {
	h := &Health{T: DefaultThresholds}
	start := time.Now()
	run(h, start, 0, 40*time.Second, healthy(start))
	gap := start.Add(40 * time.Second)
	if !run(h, start, 41*time.Second, 43*time.Second, silent(start, gap)) {
		t.Fatal("left the tunnel within 3 s")
	}
	if run(h, start, 44*time.Second, 45*time.Second, silent(start, gap)) {
		t.Fatal("still on the tunnel after 4 s of silence")
	}
	if st := h.State(); st.SwitchTo != "xray" || !strings.Contains(st.SwitchWhy, "нет ответа") {
		t.Fatalf("switch %+v", st)
	}
}

func TestHealthHoldsAfterFlapping(t *testing.T) {
	h := &Health{T: DefaultThresholds}
	start := time.Now()
	at := time.Duration(0)
	for i := 0; i < 3; i++ {
		run(h, start, at, at+31*time.Second, healthy(start))
		if !h.State().Want {
			t.Fatalf("round %d: not back on the tunnel", i)
		}
		at += 32 * time.Second
		gap := start.Add(at)
		run(h, start, at, at+5*time.Second, silent(start, gap))
		at += 6 * time.Second
	}
	st := h.State()
	if st.Want || st.HoldUntil.IsZero() {
		t.Fatalf("not held after three falls: %+v", st)
	}
	if run(h, start, at, at+10*time.Minute, healthy(start)) {
		t.Fatal("back on the tunnel while held")
	}
	if !run(h, start, at+10*time.Minute, at+16*time.Minute, healthy(start)) {
		t.Fatal("not back after the hold")
	}
}

func TestHealthInheritsThroughRestart(t *testing.T) {
	h := &Health{T: DefaultThresholds}
	h.Inherit()
	start := time.Now()
	noReply := func(now time.Time) Signals { return Signals{Now: now, Started: start, Allowed: true} }
	if !run(h, start, 0, 4*time.Second, noReply) {
		t.Fatal("dropped the inherited route during the grace period")
	}
	if run(h, start, 5*time.Second, 6*time.Second, noReply) {
		t.Fatal("kept the route with no answers after the grace period")
	}
	// A restart that comes up in time keeps the route throughout.
	h = &Health{T: DefaultThresholds}
	h.Inherit()
	up := func(now time.Time) Signals {
		s := Signals{Now: now, Started: start, Allowed: true}
		if now.Sub(start) >= 2*time.Second {
			s.LastReply, s.Handshake = now, now
		}
		return s
	}
	if !run(h, start, 0, time.Minute, up) {
		t.Fatal("a quick restart dropped the route")
	}
}

func TestHealthNeedsHandshakeAndDNS(t *testing.T) {
	start := time.Now()
	h := &Health{T: DefaultThresholds}
	run(h, start, 0, 40*time.Second, healthy(start))
	stale := func(now time.Time) Signals {
		return Signals{Now: now, Started: start, LastReply: now, Handshake: now.Add(-4 * time.Minute), Allowed: true}
	}
	if run(h, start, 41*time.Second, 42*time.Second, stale) {
		t.Fatal("kept a tunnel without a fresh handshake")
	}
	h = &Health{T: DefaultThresholds}
	run(h, start, 0, 40*time.Second, healthy(start))
	dns := func(now time.Time) Signals {
		s := healthy(start)(now)
		s.E2EFails = 3
		return s
	}
	if run(h, start, 41*time.Second, 42*time.Second, dns) {
		t.Fatal("kept a tunnel whose DNS checks fail")
	}
}
