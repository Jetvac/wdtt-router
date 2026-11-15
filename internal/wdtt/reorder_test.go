package wdtt

import (
	"encoding/binary"
	"sync"
	"testing"
	"time"
)

func wgPacket(idx uint32, ctr uint64) []byte {
	p := make([]byte, 48)
	p[0] = 4
	binary.LittleEndian.PutUint32(p[4:8], idx)
	binary.LittleEndian.PutUint64(p[8:16], ctr)
	return p
}

type collector struct {
	mu  sync.Mutex
	got []uint64
}

func (c *collector) add(v uint64) { c.mu.Lock(); c.got = append(c.got, v); c.mu.Unlock() }
func (c *collector) list() []uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]uint64(nil), c.got...)
}

func TestReorder(t *testing.T) {
	c := &collector{}
	r := &Reorder[uint64]{Out: c.add, Hold: 30 * time.Millisecond}
	push := func(ctr uint64) {
		idx, got, ok := WGData(wgPacket(7, ctr))
		if !ok || idx != 7 || got != ctr {
			t.Fatal("WGData")
		}
		r.Push(idx, got, ctr)
	}
	// Shuffled within a few packets: out in order, at once.
	for _, v := range []uint64{100, 102, 101, 104, 103, 105} {
		push(v)
	}
	want := []uint64{100, 101, 102, 103, 104, 105}
	if g := c.list(); len(g) != 6 || g[5] != 105 || g[1] != 101 || g[3] != 103 {
		t.Fatalf("got %v, want %v", g, want)
	}

	// A lost packet: the ones after it wait at most Hold, then go in order.
	push(107)
	push(108)
	if n := len(c.list()); n != 6 {
		t.Fatalf("%d out before the gap expired", n)
	}
	time.Sleep(80 * time.Millisecond)
	g := c.list()
	if len(g) != 8 || g[6] != 107 || g[7] != 108 {
		t.Fatalf("after the gap: %v", g)
	}
	// The lost one arriving late, and a duplicate: passed on at once.
	push(106)
	push(108)
	if n := len(c.list()); n != 10 {
		t.Fatalf("late packets held: %d out", n)
	}
	push(109)
	if g := c.list(); g[len(g)-1] != 109 {
		t.Fatal("stream did not continue after the gap")
	}

	// Other messages are not WireGuard data.
	if _, _, ok := WGData([]byte{1, 0, 0, 0}); ok {
		t.Fatal("handshake taken for data")
	}
	// A big jump starts afresh.
	push(109 + reorderJump + 10)
	if g := c.list(); g[len(g)-1] != 109+reorderJump+10 {
		t.Fatal("jump held")
	}
}
