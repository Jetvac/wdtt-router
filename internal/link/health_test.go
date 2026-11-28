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

func TestHealthComesUpOnlyWithDNSAnswering(t *testing.T) {
	start := time.Now()
	with := func(fails int, unseen bool) func(time.Time) Signals {
		return func(now time.Time) Signals {
			s := healthy(start)(now)
			s.E2EFails, s.E2EUnseen = fails, unseen
			return s
		}
	}
	// Probes answered, but no DNS check has passed yet, or the last two
	// failed: client UDP stays on Xray (CI caught it going over and back
	// five seconds later).
	h := &Health{T: DefaultThresholds}
	if run(h, start, 0, 60*time.Second, with(0, true)) {
		t.Fatal("on the tunnel before DNS through it was ever checked")
	}
	if run(h, start, 61*time.Second, 120*time.Second, with(2, false)) {
		t.Fatal("on the tunnel while DNS through it fails")
	}
	if !strings.Contains(h.State().Problem, "DNS") {
		t.Fatalf("problem %q does not say why", h.State().Problem)
	}
	// DNS answers: the usual 30 s, counted from then.
	if run(h, start, 121*time.Second, 150*time.Second, with(0, false)) {
		t.Fatal("did not wait Up after DNS answered")
	}
	if !run(h, start, 151*time.Second, 152*time.Second, with(0, false)) {
		t.Fatal("not on the tunnel with everything answering")
	}
	// On the tunnel, a lost check or two do not move it off.
	if !run(h, start, 153*time.Second, 160*time.Second, with(2, false)) {
		t.Fatal("left the tunnel over two lost DNS checks")
	}
}

// Probes unanswered while Mesh carries nothing to the next server either:
// Xray rides the same Mesh, so client UDP waits in the tunnel (up to
// MeshHold) instead of moving there and back, and the outage is counted.
// With Mesh working, the tunnel itself is at fault and UDP leaves at once.
// (exit-de, 28 Nov: UDP moved to Xray and back several times an hour on
// "нет ответа 3s".)
func TestHealthWaitsOutMeshOutages(t *testing.T) {
	meshSilent := func(start, since time.Time, m MeshState) func(time.Time) Signals {
		return func(now time.Time) Signals {
			s := silent(start, since)(now)
			s.Mesh = m
			return s
		}
	}
	start := time.Now()
	on := func() *Health {
		h := &Health{T: DefaultThresholds}
		run(h, start, 0, 40*time.Second, healthy(start))
		if !h.State().Want {
			t.Fatal("not on the tunnel")
		}
		return h
	}
	gap := start.Add(40 * time.Second)

	// Mesh is down too: UDP stays through a 10 s outage, then the outage
	// is counted once the probes are answered again.
	h := on()
	if !run(h, start, 41*time.Second, 43*time.Second, meshSilent(start, gap, MeshChecking)) ||
		!run(h, start, 44*time.Second, 50*time.Second, meshSilent(start, gap, MeshDown)) {
		t.Fatal("left the tunnel during a Mesh outage")
	}
	if st := h.State(); !st.Waiting || !strings.Contains(st.Problem, "Mesh до следующего сервера тоже не отвечает") {
		t.Fatalf("state during the outage %+v", st)
	}
	back := start.Add(51 * time.Second)
	h.Step(Signals{Now: back, Started: start, LastReply: back, Handshake: back, Allowed: true})
	if st := h.State(); !st.Want || st.Waiting || st.MeshOuts != 1 || !st.MeshOutAt.Equal(gap) || st.MeshOutFor != 11*time.Second || st.SwitchTo == "xray" {
		t.Fatalf("after the outage %+v", st)
	}

	// Mesh carries a handshake: the tunnel is at fault, UDP leaves after 3 s.
	h = on()
	if run(h, start, 41*time.Second, 44*time.Second, meshSilent(start, gap, MeshUp)) {
		t.Fatal("stayed in a broken tunnel while Mesh works")
	}
	if st := h.State(); !strings.Contains(st.SwitchWhy, "хотя Mesh до следующего сервера работает") || st.MeshOuts != 0 {
		t.Fatalf("switch %+v", st)
	}

	// Mesh down for longer than MeshHold: UDP leaves anyway.
	h = on()
	if run(h, start, 41*time.Second, 41*time.Second+DefaultThresholds.MeshHold+time.Second, meshSilent(start, gap, MeshDown)) {
		t.Fatal("still waiting after MeshHold")
	}
	if st := h.State(); st.MeshOuts != 0 || st.Waiting {
		t.Fatalf("a long outage counted as waited out %+v", st)
	}
}
