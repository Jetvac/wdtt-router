package link

import (
	"context"
	"net/netip"
	"sync"
	"time"
)

// Entry runs the entry's side of the tunnel: probes, the path's datagram
// size, end-to-end checks, and the choice between the tunnel and Xray.
type Entry struct {
	Bind   *Bind
	Peer   netip.AddrPort
	Health *Health
	// Allowed: the mode lets client UDP use the tunnel (read every tick,
	// so a reloaded mode takes effect at once).
	Allowed func() bool
	// Handshake: WireGuard's last handshake with the exit.
	Handshake func() time.Time
	// Route applies the decision; called every RouteEvery while on (to
	// renew the kernel's timed entry) and once when it goes off.
	Route func(on bool) error
	// E2E sends a DNS query through the tunnel (nil: none).
	E2E func(ctx context.Context) (time.Duration, error)
	// PeerRestarted: the exit's service restarted and lost WireGuard's
	// keys; renew them now rather than after WireGuard's own 15 s.
	PeerRestarted func()
	Log           func(format string, args ...any)

	Interval   time.Duration // probes; default 500 ms
	RouteEvery time.Duration // default 1 s
	E2EEvery   time.Duration // default 15 s
	MTUEvery   time.Duration // default 10 min
	MTUWait    time.Duration // an MTU probe unanswered this long is lost; default 2 s

	tr      tracker
	started time.Time

	mu       sync.Mutex
	e2eFails int
	e2eRTT   time.Duration
	e2eAt    time.Time
	e2eErr   string
	e2eSeen  bool // a check has passed in this run
	mtu      mtuProbe
	peerRun  uint64
	routed   bool
	routeErr string
}

type mtuProbe struct {
	next      time.Time
	seq       uint32
	size      int
	at        time.Time
	raising   bool
	raiseAt   time.Time // a capped link tries the full size again then
	fails     int
	confirmed int
	path      int // the interface's datagram when last looked at
}

func (e *Entry) defaults() {
	if e.Interval == 0 {
		e.Interval = 500 * time.Millisecond
	}
	if e.RouteEvery == 0 {
		e.RouteEvery = time.Second
	}
	if e.E2EEvery == 0 {
		e.E2EEvery = 15 * time.Second
	}
	if e.MTUEvery == 0 {
		e.MTUEvery = 10 * time.Minute
	}
	if e.MTUWait == 0 {
		e.MTUWait = 2 * time.Second
	}
	if e.Log == nil {
		e.Log = func(string, ...any) {}
	}
}

// Run probes until ctx ends. It leaves the routing as it is when it
// returns: a restarted service picks it up within the kernel entry's
// lifetime (Thresholds.Grace), and a stopped one lets it lapse to Xray.
func (e *Entry) Run(ctx context.Context) error {
	e.defaults()
	e.started = time.Now()
	e.Bind.OnReply = e.reply
	tick := time.NewTicker(e.Interval)
	defer tick.Stop()
	var lastRoute time.Time
	var lastE2E time.Time
	for {
		now := time.Now()
		seq := e.tr.next(now, ProbeSize, false)
		if err := e.Bind.Probe(e.Peer, seq, now, ProbeSize); err != nil {
			e.Log("probe: %v", err)
		}
		e.mtuTick(now)
		if e.E2E != nil && now.Sub(lastE2E) >= e.E2EEvery {
			lastE2E = now
			go e.e2e(ctx)
		}
		e.mu.Lock()
		fails, unseen := e.e2eFails, e.E2E != nil && !e.e2eSeen
		e.mu.Unlock()
		changed := e.Health.Step(Signals{Now: now, Started: e.started, LastReply: e.tr.last(), Handshake: e.Handshake(),
			E2EFails: fails, E2EUnseen: unseen, Allowed: e.Allowed()})
		st := e.Health.State()
		if changed {
			e.Log("client UDP → %s: %s", map[bool]string{true: "tunnel", false: "Xray"}[st.Want], st.SwitchWhy)
		}
		if changed || (st.Want && now.Sub(lastRoute) >= e.RouteEvery) {
			lastRoute = now
			err := e.Route(st.Want)
			e.mu.Lock()
			e.routed = st.Want && err == nil
			e.routeErr = ""
			if err != nil {
				e.routeErr = err.Error()
			}
			e.mu.Unlock()
			if err != nil {
				e.Log("routing: %v", err)
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

func (e *Entry) reply(r Reply) {
	p, ok := e.tr.answer(r)
	if !ok {
		return
	}
	e.mu.Lock()
	restarted := e.peerRun != 0 && r.Run != e.peerRun
	e.peerRun = r.Run
	e.mu.Unlock()
	if restarted && e.PeerRestarted != nil {
		e.Log("the exit's service restarted: new WireGuard handshake")
		go e.PeerRestarted()
	}
	if !p.mtu {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	m := &e.mtu
	if p.seq != m.seq {
		return
	}
	if r.Size != p.size {
		return // cut on the way: not a pass
	}
	m.confirmed, m.fails, m.seq = p.size, 0, 0
	if m.raising {
		e.Bind.Limit(0)
		e.Log("datagrams of %d bytes pass again", p.size)
	}
	m.raising = false
	m.next = r.At.Add(e.MTUEvery)
}

// mtuTick checks now and then that a full-size datagram crosses the path.
// Three lost in a row while plain probes are answered: the path takes
// less than the interface says, and datagrams are capped 64 bytes lower.
// A capped link tries the full size again every MTUEvery.
func (e *Entry) mtuTick(now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	m := &e.mtu
	path := e.Bind.Datagram()
	if e.Bind.pathDatagram != nil {
		path = max(e.Bind.pathDatagram(), MinDatagram)
	}
	if m.path != path {
		// The interface changed: check at once, the full size included.
		m.path, m.next, m.raiseAt, m.fails = path, now, now, 0
	}
	if m.seq != 0 {
		if now.Sub(m.at) < e.MTUWait {
			return
		}
		// Unanswered. It counts only if plain probes got answers since.
		switch {
		case m.raising:
			m.raiseAt, m.next = now.Add(e.MTUEvery), now.Add(e.MTUEvery)
		case e.tr.last().After(m.at):
			m.fails++
			if m.fails >= 3 {
				capped := max(m.size-64, MinDatagram)
				e.Bind.Limit(capped)
				e.Log("datagrams of %d bytes do not pass: capped at %d", m.size, capped)
				m.fails = 0
				m.next, m.raiseAt = now, now.Add(e.MTUEvery)
			}
		}
		m.seq, m.raising = 0, false
	}
	if now.Before(m.next) {
		return
	}
	size := e.Bind.Datagram()
	if l := e.Bind.Limited(); l > 0 && path > l && m.fails == 0 && !now.Before(m.raiseAt) {
		size, m.raising = path, true
	}
	m.size, m.at = size, now
	m.seq = e.tr.next(now, size, true)
	m.next = now.Add(e.MTUWait)
	_ = e.Bind.Probe(e.Peer, m.seq, now, size)
}

func (e *Entry) e2e(ctx context.Context) {
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rtt, err := e.E2E(c)
	e.mu.Lock()
	defer e.mu.Unlock()
	e.e2eAt = time.Now()
	if err != nil {
		e.e2eFails++
		e.e2eErr = err.Error()
		return
	}
	e.e2eFails, e.e2eRTT, e.e2eErr, e.e2eSeen = 0, rtt, "", true
}

// EntryState is a snapshot for the status file.
type EntryState struct {
	RTT50, RTT95 time.Duration
	Loss         float64
	Answered     int
	LastReply    time.Time
	Datagram     int
	Confirmed    int
	E2ERTT       time.Duration
	E2EAt        time.Time
	E2EErr       string
	Routed       bool
	RouteErr     string
	Health       HealthState
}

func (e *Entry) State(now time.Time) EntryState {
	p50, p95, loss, n := e.tr.stats(now)
	e.mu.Lock()
	defer e.mu.Unlock()
	return EntryState{RTT50: p50, RTT95: p95, Loss: loss, Answered: n, LastReply: e.tr.last(), Datagram: e.Bind.Datagram(),
		Confirmed: e.mtu.confirmed, E2ERTT: e.e2eRTT, E2EAt: e.e2eAt, E2EErr: e.e2eErr, Routed: e.routed, RouteErr: e.routeErr, Health: e.Health.State()}
}
