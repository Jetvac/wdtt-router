package link

import (
	"bytes"
	"math/rand/v2"
	"net/netip"
	"testing"
	"time"
)

func testKeys() keys { return deriveKeys(bytes.Repeat([]byte{7}, 32)) }

func TestMaskHidesHeaders(t *testing.T) {
	k := testKeys()
	// A WireGuard transport header: type 4, zeros, receiver index, counter.
	msg := []byte{4, 0, 0, 0, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 9}
	same := 0
	for i := 0; i < 50; i++ {
		dg := append(make([]byte, nonceLen), append([]byte{kindWhole, 0, 0, 0}, msg...)...)
		k.seal(dg)
		if bytes.Contains(dg, []byte{4, 0, 0, 0, 1, 2, 3, 4}) {
			t.Fatal("WireGuard header visible on the wire")
		}
		if dg[nonceLen] == kindWhole {
			same++
		}
		hdr, payload, err := k.open(dg)
		if err != nil || hdr[0] != kindWhole || !bytes.Equal(payload, msg) {
			t.Fatalf("round trip: %v %v %x", err, hdr, payload)
		}
	}
	if same > 10 {
		t.Fatalf("the kind byte showed through %d times of 50", same)
	}
}

func TestProbeMAC(t *testing.T) {
	k := testKeys()
	for _, size := range []int{0, ProbeSize, 1252} {
		dg := k.probeDatagram(42, 1234567, size)
		if size > ProbeSize && len(dg) != size {
			t.Fatalf("probe size %d, want %d", len(dg), size)
		}
		hdr, payload, _ := k.open(dg)
		if hdr[0] != kindProbe || !k.checkMAC(hdr, payload, probeBody) {
			t.Fatalf("size %d: probe rejected", size)
		}
		if seq, sent := probeFields(payload); seq != 42 || sent != 1234567 {
			t.Fatalf("fields %d %d", seq, sent)
		}
		payload[len(payload)-macLen-1] ^= 1
		if k.checkMAC(hdr, payload, probeBody) {
			t.Fatal("a changed probe passed")
		}
	}
	other := deriveKeys(bytes.Repeat([]byte{8}, 32))
	dg := k.replyDatagram(7, 99, 1200, 42)
	if hdr, payload, _ := other.open(append([]byte(nil), dg...)); hdr[0] == kindReply && other.checkMAC(hdr, payload, replyBody) {
		t.Fatal("a reply under another key passed")
	}
	hdr, payload, _ := k.open(dg)
	if hdr[0] != kindReply || !k.checkMAC(hdr, payload, replyBody) {
		t.Fatal("reply rejected")
	}
}

func TestSplit(t *testing.T) {
	for _, tc := range []struct{ n, chunk, parts int }{
		{1300, 1107, 2}, {1372, 524, 3}, {1201, 1200, 2}, {300, 1200, 2},
	} {
		msg := make([]byte, tc.n)
		ps := split(msg, tc.chunk)
		total := 0
		for _, p := range ps {
			if len(p) > tc.chunk {
				t.Fatalf("%v: part of %d", tc, len(p))
			}
			total += len(p)
		}
		if len(ps) != tc.parts || total != tc.n {
			t.Fatalf("%v: %d parts, %d bytes", tc, len(ps), total)
		}
	}
	if split(make([]byte, 2000), 100) != nil {
		t.Fatal("more than maxParts parts")
	}
}

func TestReassemble(t *testing.T) {
	src := netip.MustParseAddrPort("100.96.0.16:40000")
	now := time.Now()
	var r reassembler
	msg := make([]byte, 1340)
	for i := range msg {
		msg[i] = byte(i)
	}
	ps := split(msg, 500)
	order := rand.Perm(len(ps))
	var got []byte
	for _, i := range append(order, order[0]) { // shuffled, one duplicate
		if m := r.add(src, 9, i, len(ps), ps[i], now); m != nil {
			if got != nil {
				t.Fatal("completed twice")
			}
			got = m
		}
	}
	if !bytes.Equal(got, msg) {
		t.Fatal("message changed")
	}
	// A message missing a part expires and frees its slot. (The late
	// duplicate above waits too, for nothing, until it expires.)
	w := r.waiting()
	r.add(src, 10, 0, 2, ps[0], now)
	if r.waiting() != w+1 {
		t.Fatal("not waiting")
	}
	if m := r.add(src, 10, 1, 2, ps[1], now.Add(time.Second)); m != nil {
		t.Fatal("joined parts of a stale message")
	}
	// Garbage headers are ignored.
	for _, h := range [][2]int{{0, 1}, {3, 3}, {0, 16}} {
		if r.add(src, 11, h[0], h[1], ps[0], now) != nil {
			t.Fatal("bad header accepted")
		}
	}
	// Memory is bounded.
	for id := 0; id < 3*reasmMax; id++ {
		r.add(src, uint16(1000+id), 0, 2, ps[0], now)
	}
	if r.waiting() > reasmMax {
		t.Fatalf("%d messages waiting", r.waiting())
	}
}

func TestLimitLapsesWithTheInterface(t *testing.T) {
	path := 1252
	b := NewBind(bytes.Repeat([]byte{7}, 32), netip.AddrPort{}, func() int { return path })
	b.Limit(1188)
	if b.Datagram() != 1188 || b.Limited() != 1188 {
		t.Fatalf("capped: datagram %d, limit %d", b.Datagram(), b.Limited())
	}
	// Cloudflare lowers the MTU: the old cap means nothing now.
	path = 1119
	if b.Datagram() != 1119 || b.Limited() != 0 {
		t.Fatalf("lower MTU: datagram %d, limit %d", b.Datagram(), b.Limited())
	}
	// And raises it back: no cap is left over from before (the exit never
	// probes to lift one).
	b.Limit(1055)
	path = 1252
	if b.Datagram() != 1252 || b.Limited() != 0 {
		t.Fatalf("MTU back: datagram %d, limit %d", b.Datagram(), b.Limited())
	}
	b.Limit(0)
	if b.Datagram() != 1252 {
		t.Fatalf("no cap: datagram %d", b.Datagram())
	}
}
