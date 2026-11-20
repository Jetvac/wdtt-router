package wdtt

import "testing"

// A path that spikes now and then scores worse than a steady one with a
// slightly longer round trip, even right after a quick ping; big packets
// still go by the last round trip.
func TestJitter(t *testing.T) {
	var steady, spiky jitter
	var a, b int32
	for i := 0; i < 40; i++ {
		a = steady.add(35)
		r := int32(25)
		if i%5 == 0 {
			r = 230
		}
		b = spiky.add(r)
	}
	b = spiky.add(25)
	if b <= a || a < 35 || a > 40 {
		t.Fatalf("spiky %d, steady %d", b, a)
	}
}
