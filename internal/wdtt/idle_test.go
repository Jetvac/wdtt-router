package wdtt

import (
	"testing"
	"time"
)

// With no fresh path (an idle phone pings only every 25 s), packets go on
// the path heard from last, not the first in the list.
func TestPacerIdleFallback(t *testing.T) {
	now := time.Now()
	older := testPath(30, now.Add(-20*time.Second).UnixNano())
	newer := testPath(30, now.Add(-12*time.Second).UnixNano())
	b := newBind()
	b.devPaths["d"] = &pathSet{list: []*session{older, newer}}
	p := &pacer{b: b, dev: "d"}
	p.hi = []queued{{n: 100, at: now.UnixNano()}}
	out, _ := p.step(nil)
	if len(out) != 1 || out[0].s != newer {
		t.Fatalf("sent %d, on the newest path: %v", len(out), len(out) == 1 && out[0].s == newer)
	}
}
