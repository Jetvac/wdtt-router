package wdtt

import "sync"

// jitter keeps a path's smoothed round trip and its mean deviation, the
// way TCP does (RFC 6298), from the round trips the client reports in its
// pings, so that small packets avoid a path that spikes even when its
// last ping was quick.
type jitter struct {
	mu           sync.Mutex
	srtt, rttvar int32 // ms
}

// add takes one round trip (ms) and returns what a packet should expect:
// srtt + 2·rttvar.
func (j *jitter) add(rtt int32) int32 {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.srtt == 0 {
		j.srtt, j.rttvar = rtt, rtt/4
	} else {
		d := j.srtt - rtt
		if d < 0 {
			d = -d
		}
		j.rttvar = (3*j.rttvar + d) / 4
		j.srtt = (7*j.srtt + rtt) / 8
	}
	return j.srtt + 2*j.rttvar
}
