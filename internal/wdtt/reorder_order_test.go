package wdtt

import (
	"sync"
	"testing"
	"time"
)

// Two routes deliver one after the other: the second packet must not
// overtake the first while the first is still being handed on.
func TestReorderOutInOrder(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var mu sync.Mutex
	var got []uint64
	r := &Reorder[uint64]{Out: func(v uint64) {
		if v == 1 {
			close(entered)
			<-release
		}
		mu.Lock()
		got = append(got, v)
		mu.Unlock()
	}}
	go r.Push(7, 1, 1)
	<-entered
	done := make(chan struct{})
	go func() { r.Push(7, 2, 2); close(done) }()
	time.Sleep(30 * time.Millisecond)
	close(release)
	<-done
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 || got[0] != 1 || got[1] != 2 {
		t.Fatalf("handed on %v, want [1 2]", got)
	}
}
