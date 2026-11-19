package wdtt

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

func testPath(rtt int32, now int64) *session {
	s := &session{dp: &dpath{}}
	s.dp.rtt.Store(rtt)
	s.dp.lastRx.Store(now)
	s.dp.pr.Refill(now)
	return s
}

func TestPacerPick(t *testing.T) {
	now := time.Now().UnixNano()
	fresh := now - int64(pathFresh)
	fast, slow := testPath(50, now), testPath(90, now)
	list := []*session{slow, fast}
	p := &pacer{}

	// An idle tunnel: small packets on the path with the shorter round trip.
	for i := 0; i < 3; i++ {
		if p.pick(list, 100, now, fresh, nil, false) != fast {
			t.Fatal("small packet not on the fastest path")
		}
	}
	// Its copy goes on the other path.
	if p.pick(list, 100, now, fresh, fast, false) != slow {
		t.Fatal("copy of a small packet not on the second path")
	}

	// A burst: both paths, in runs of at most bulkRun, until the tokens
	// run out; then nothing more goes until they refill.
	count := map[*session]int{}
	sent := 0
	for {
		x := p.pick(list, 1300, now, fresh, nil, true)
		if x == nil {
			break
		}
		count[x]++
		sent++
	}
	if count[fast] == 0 || count[slow] == 0 {
		t.Fatalf("burst not spread: %d/%d", count[fast], count[slow])
	}
	if max := 2 * pathBurst / 1300; sent > max {
		t.Fatalf("%d packets in one burst, more than the tokens allow (%d)", sent, max)
	}
	// 100 ms later each path has rate/10 bytes again.
	later := now + int64(100*time.Millisecond)
	fast.dp.pr.Refill(later)
	slow.dp.pr.Refill(later)
	n := 0
	for p.pick(list, 1300, later, fresh, nil, true) != nil {
		n++
	}
	want := 2 * initialPathRate / 10 / (1300 + MaxWireOverhead)
	if n < want-1 || n > want+1 {
		t.Fatalf("%d packets after 100 ms, want about %d", n, want)
	}

	// A stale path carries nothing while a fresh one works.
	fast.dp.lastRx.Store(now - int64(time.Minute))
	later += int64(time.Second)
	fast.dp.pr.Refill(later)
	slow.dp.pr.Refill(later)
	for i := 0; i < 5; i++ {
		if p.pick(list, 1300, later, later-int64(pathFresh), nil, true) != slow {
			t.Fatal("stale path used while a fresh one works")
		}
	}
}

func TestPacerQueue(t *testing.T) {
	p := &pacer{}
	big := make([]byte, 1300)
	small := make([]byte, 60)
	p.enqueue([][]byte{big, small, big})
	if len(p.hi) != 1 || len(p.lo) != 2 {
		t.Fatalf("queues %d/%d", len(p.hi), len(p.lo))
	}
	// Bulk that waited too long is dropped; small packets are kept.
	p.dropOld(time.Now().Add(maxQueueDelay+time.Millisecond).UnixNano(), false)
	if len(p.lo) != 0 || len(p.hi) != 1 || p.loBytes != 0 || p.dropped.Load() != 2 {
		t.Fatalf("after drop: hi %d lo %d bytes %d dropped %d", len(p.hi), len(p.lo), p.loBytes, p.dropped.Load())
	}
}

func TestPathRateFollowsPingReports(t *testing.T) {
	var r PathRate
	busy := func(recv, lost uint32, rtt int32) {
		r.Limited.Store(true)
		r.Report(recv, lost, rtt)
	}
	busy(0, 0, 50)
	busy(1000, 0, 52) // clean and busy: up
	up := r.Get()
	if up <= initialPathRate {
		t.Fatalf("rate %v did not grow", up)
	}
	r.Report(2000, 0, 52) // clean, not using its rate: unchanged
	if r.Get() != up {
		t.Fatal("rate grew without demand")
	}
	busy(2900, 100, 52) // 10% loss: down
	if r.Get() >= up {
		t.Fatalf("rate %v did not drop on loss", r.Get())
	}
	before := r.Get()
	busy(2910, 105, 52) // too few packets to judge
	if r.Get() != before {
		t.Fatal("rate changed on too few packets")
	}
	for i := 0; i < 100; i++ {
		busy(r.repRecv+100, r.repLost+100, 52)
	}
	if r.Get() != minPathRate {
		t.Fatalf("rate %v, floor %d", r.Get(), minPathRate)
	}
	var q PathRate
	q.Limited.Store(true)
	q.Report(0, 0, 50)
	q.Limited.Store(true)
	q.Report(1000, 0, 51)
	base := q.Get()
	q.Limited.Store(true)
	q.Report(2000, 0, 95) // round trip grew: down
	if q.Get() >= base {
		t.Fatal("rate not lowered when the round trip grew")
	}
}

func TestFeedbackLoop(t *testing.T) {
	var tx PathRate // sender side
	var rx RxTrack  // receiver side
	now := time.Now().UnixNano()
	seq := uint16(65500) // wraps around on the way
	step := int64(2 * time.Millisecond)
	// deliver sends n packets, each arriving after delay; every packet in
	// lost (by index) never arrives. FEEDBACK goes back at once.
	deliver := func(n int, delay time.Duration, lost func(i int) bool, busy bool) {
		for i := 0; i < n; i++ {
			tx.OnSend(seq, now)
			if busy {
				tx.Limited.Store(true)
			}
			if !lost(i) && rx.Seen(seq, now+int64(delay)) {
				tx.OnFeedback(rx.Feedback(1, now+int64(delay)), now+int64(2*delay))
			}
			seq++
			now += step
		}
	}
	none := func(int) bool { return false }

	deliver(200, 25*time.Millisecond, none, true) // clean and busy: up
	up := tx.Get()
	if up <= initialPathRate {
		t.Fatalf("rate %v did not grow on a clean, busy path", up)
	}
	if rx.Lost != 0 || rx.Recv != 200 {
		t.Fatalf("receiver counted %d received, %d lost", rx.Recv, rx.Lost)
	}

	tx.Limited.Store(false)
	deliver(200, 25*time.Millisecond, none, false) // clean, not busy: unchanged
	if tx.Get() != up {
		t.Fatal("rate grew without demand")
	}

	deliver(200, 60*time.Millisecond, none, true) // delay grew by 35 ms: down
	slowed := tx.Get()
	if slowed >= up {
		t.Fatalf("rate %v not lowered when the delay grew", slowed)
	}

	tx.Limited.Store(false)
	deliver(200, 25*time.Millisecond, none, false) // the delay settles back
	before2 := tx.Get()
	deliver(500, 25*time.Millisecond, func(i int) bool { return i%50 == 0 }, false) // 2% random loss: no cut
	if tx.Get() < before2 {
		t.Fatalf("rate cut from %v to %v on 2%% random loss", before2, tx.Get())
	}
	slowed = tx.Get()
	lost0 := rx.Lost
	deliver(600, 25*time.Millisecond, func(i int) bool { return i%10 == 0 }, true) // 10% loss: down
	if tx.Get() >= slowed {
		t.Fatalf("rate %v not lowered on loss", tx.Get())
	}
	if n := rx.Lost - lost0; n < 55 || n > 65 {
		t.Fatalf("receiver counted %d lost of 600", n)
	}
	// However long the delay stays high, it alone does not starve the path.
	var d PathRate
	for i := 0; i < 100; i++ {
		d.OnSend(uint16(i), now)
		d.OnFeedback(fb(uint16(i), 0, uint32(i), 0), now+int64(25*time.Millisecond))
		now += int64(adjustEvery)
	}
	for i := 100; i < 400; i++ {
		d.OnSend(uint16(i), now)
		d.OnFeedback(fb(uint16(i), 0, uint32(i), 0), now+int64(200*time.Millisecond))
		now += int64(adjustEvery)
	}
	if d.Get() != delayFloor {
		t.Fatalf("delay took the rate to %v, floor %d", d.Get(), delayFloor)
	}
	if !tx.HasFeedback() {
		t.Fatal("feedback not noticed")
	}

	// While FEEDBACK comes, PING reports do not steer the rate.
	before := tx.Get()
	tx.Report(0, 0, 50)
	tx.Report(10000, 5000, 500)
	if tx.Get() != before {
		t.Fatal("a PING report overrode FEEDBACK")
	}
}

// fb builds a FEEDBACK message.
func fb(seq, hold uint16, recv, lost uint32) []byte {
	b := make([]byte, 14)
	b[0], b[1] = msgFeedback, 1
	binary.BigEndian.PutUint16(b[2:4], seq)
	binary.BigEndian.PutUint16(b[4:6], hold)
	binary.BigEndian.PutUint32(b[6:10], recv)
	binary.BigEndian.PutUint32(b[10:14], lost)
	return b
}

func TestFastStartAndLearnedRates(t *testing.T) {
	// A clean, busy new path grows by growFast; after congestion by growSlow.
	var r PathRate
	now := time.Now().UnixNano()
	step := func(lost uint32, delay time.Duration) {
		for i := 0; i < 100; i++ {
			seq := uint16(now / 1e6)
			r.OnSend(seq, now)
			r.Limited.Store(true)
			r.OnFeedback(fb(seq, 0, uint32(now/1e6), lost), now+int64(delay))
			now += int64(adjustEvery) / 10
		}
	}
	step(0, 30*time.Millisecond)
	if fast := r.Get(); fast < initialPathRate*1.3 {
		t.Fatalf("rate %v after a clean second: no fast start", fast)
	}
	step(1<<20, 30*time.Millisecond) // heavy loss: settles
	if !r.settled {
		t.Fatal("loss did not end the fast start")
	}

	// What it settled at seeds new paths through the same TURN server.
	var l LearnedRates
	if l.Start("vk1") != initialPathRate {
		t.Fatal("unknown server must start at the initial rate")
	}
	r.Seed(600_000)
	l.Note("vk1", &r)
	if got := l.Start("vk1"); got < 500_000 || got > 600_000 {
		t.Fatalf("learned start %v", got)
	}
	var fresh PathRate // never congested: teaches nothing
	l.Note("vk2", &fresh)
	if l.Start("vk2") != initialPathRate {
		t.Fatal("unsettled path taught a rate")
	}
}

// A path that a reporting client stopped answering (sent on, no FEEDBACK
// back) is left out after pathStall, long before pathFresh, and used again
// once anything arrives on it.
func TestPathStall(t *testing.T) {
	now := time.Now().UnixNano()
	fresh := now - int64(pathFresh)
	dead, ok := testPath(50, now), testPath(90, now)
	for _, s := range []*session{dead, ok} {
		s.dp.pr.mu.Lock()
		s.dp.pr.fbSeen = time.Now()
		s.dp.pr.mu.Unlock()
	}
	sent := now + int64(100*time.Millisecond)
	dead.dp.pending.Store(sent) // sent on after the last answer
	if !dead.dp.usable(sent+int64(pathStall)/2, fresh) {
		t.Fatal("left out before pathStall")
	}
	later := sent + int64(pathStall) + 1
	if dead.dp.usable(later, fresh) {
		t.Fatal("still used after pathStall without an answer")
	}
	list := []*session{dead, ok}
	p := &pacer{}
	dead.dp.pr.Refill(later)
	ok.dp.pr.Refill(later)
	if p.pick(list, 100, later, fresh, nil, false) != ok {
		t.Fatal("stalled path picked")
	}
	dead.dp.lastRx.Store(later) // the client's ping
	if !dead.dp.usable(later, fresh) {
		t.Fatal("not used again after an answer")
	}
	// A client without FEEDBACK is judged by pathFresh only.
	old := testPath(50, now)
	old.dp.pending.Store(sent)
	if !old.dp.usable(later, fresh) {
		t.Fatal("client without FEEDBACK left out by pathStall")
	}
}

// An idle path with the shorter round trip carries small packets even when
// the other one is paced at a lower rate (the spare tokens of a slow path
// are no reason to prefer it).
func TestPacerPickShortestIdle(t *testing.T) {
	now := time.Now().UnixNano()
	fast, slow := testPath(20, now), testPath(40, now)
	slow.dp.pr.Seed(60_000)
	fast.dp.pr.Seed(400_000)
	p := &pacer{}
	if p.pick([]*session{slow, fast}, 100, now, now-int64(pathFresh), nil, false) != fast {
		t.Fatal("small packet not on the path with the shorter round trip")
	}
}

// The copy of a small packet goes through another VK TURN server, even
// when a path on the same one has the shorter round trip.
func TestPacerCopyOtherRelay(t *testing.T) {
	now := time.Now().UnixNano()
	fresh := now - int64(pathFresh)
	a1, a2, b := testPath(10, now), testPath(12, now), testPath(30, now)
	a1.dp.raddr = netip.MustParseAddrPort("1.1.1.1:19302")
	a2.dp.raddr = netip.MustParseAddrPort("1.1.1.1:19303")
	b.dp.raddr = netip.MustParseAddrPort("2.2.2.2:19302")
	list := []*session{a1, a2, b}
	p := &pacer{}
	if p.pick(list, 100, now, fresh, nil, false) != a1 {
		t.Fatal("first copy not on the shortest path")
	}
	if p.pickCopy(list, 100, now, fresh, a1) != b {
		t.Fatal("second copy not through the other relay")
	}
	if p.pickCopy(list[:2], 100, now, fresh, a1) != a2 {
		t.Fatal("no copy with a single relay")
	}
}
