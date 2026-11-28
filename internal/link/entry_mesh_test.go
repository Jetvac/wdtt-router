package link

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// The entry checks Mesh only while the probes go unanswered, repeats a
// failed check, stops once one passes, and forgets the verdict when the
// probes are answered again.
func TestEntryChecksMeshOnlyInSilence(t *testing.T) {
	var calls atomic.Int32
	up := atomic.Bool{}
	e := &Entry{MeshCheck: func(context.Context) error {
		calls.Add(1)
		if up.Load() {
			return nil
		}
		return errors.New("i/o timeout")
	}}
	e.defaults()
	ctx := context.Background()
	now := time.Now()
	e.tr.lastReply = now
	if m := e.meshTick(ctx, now.Add(time.Second)); m != MeshUnknown || calls.Load() != 0 {
		t.Fatalf("checked Mesh while the probes were answered: %v", m)
	}
	wait := func(want MeshState, at time.Time) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for {
			if m := e.meshTick(ctx, at); m == want {
				return
			} else if time.Now().After(deadline) {
				t.Fatalf("Mesh %v, want %v", m, want)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	at := now.Add(2 * time.Second)
	if m := e.meshTick(ctx, at); m != MeshChecking {
		t.Fatalf("first tick of a silence: %v", m)
	}
	wait(MeshDown, at)
	n := calls.Load()
	for deadline := time.Now().Add(2 * time.Second); calls.Load() == n; time.Sleep(5 * time.Millisecond) {
		if e.meshTick(ctx, at.Add(time.Second)) != MeshDown || time.Now().After(deadline) {
			t.Fatal("a failed check is not repeated")
		}
	}
	up.Store(true)
	wait(MeshUp, at.Add(2*time.Second))
	n = calls.Load()
	time.Sleep(20 * time.Millisecond)
	e.meshTick(ctx, at.Add(3*time.Second))
	time.Sleep(20 * time.Millisecond)
	if calls.Load() != n {
		t.Fatal("checked again after Mesh answered")
	}
	// Answered again: the verdict is gone.
	e.tr.lastReply = at.Add(3 * time.Second)
	if m := e.meshTick(ctx, at.Add(3*time.Second)); m != MeshUnknown {
		t.Fatalf("verdict kept after the probes were answered: %v", m)
	}
}
