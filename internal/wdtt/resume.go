package wdtt

import (
	"encoding/json"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

// After a crash the clients' sessions point at a server that no longer
// knows them, and a client finds out only when it next sends something
// (a stale session gets a reset) or when its own timeout fires. The server
// therefore keeps a list of its live sessions (relay address, key, RTP
// payload type) in a file under /run, refreshed with the status file, and
// on start sends each of them the stale-session reset straight away.
// Clients that act on the reset reconnect at once; others are unaffected.

type liveSession struct {
	Addr netip.AddrPort `json:"addr"`
	Key  string         `json:"key"`
	PT   byte           `json:"pt"`
	// Direct is a direct path (TurnVK client) rather than a DTLS session.
	Direct bool `json:"direct,omitempty"`
}

// sessionsFile sits next to the status file and is named after it, so the
// two servers (wdtt-status.json, wdtt-turnvk-status.json) keep separate
// lists: wdtt-sessions.json and wdtt-turnvk-sessions.json.
func sessionsFile(statusFile string) string {
	if statusFile == "" {
		return ""
	}
	base := strings.TrimSuffix(filepath.Base(statusFile), ".json")
	base = strings.TrimSuffix(base, "-status")
	if base == "" || base == "status" {
		base = "wdtt"
	}
	return filepath.Join(filepath.Dir(statusFile), base+"-sessions.json")
}

func (m *mux) live() []liveSession {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]liveSession, 0, len(m.conns))
	for _, c := range m.conns {
		out = append(out, liveSession{Addr: c.raddr, Key: c.keyID, PT: c.tx.pt})
	}
	for _, p := range m.paths {
		out = append(out, liveSession{Addr: p.raddr, Key: p.keyID, PT: p.tx.pt, Direct: true})
	}
	return out
}

func writeSessions(path string, list []liveSession) {
	if path == "" {
		return
	}
	b, _ := json.Marshal(list)
	tmp := path + ".tmp"
	if os.WriteFile(tmp, b, 0600) == nil {
		_ = os.Rename(tmp, path)
	}
}

// resetPrevious sends a reset to every session the previous run of the
// server had, and removes the list.
func (m *mux) resetPrevious(path string) int {
	if path == "" {
		return 0
	}
	b, err := os.ReadFile(path)
	_ = os.Remove(path)
	if err != nil {
		return 0
	}
	var list []liveSession
	if json.Unmarshal(b, &list) != nil {
		return 0
	}
	keys := map[string]keyEntry{}
	for _, k := range *m.keys.Load() {
		keys[k.id] = k
	}
	n := 0
	for _, ls := range list {
		k, ok := keys[ls.Key]
		if !ok || !ls.Addr.IsValid() {
			continue
		}
		if ls.Direct {
			m.sendDirectReset(m.socks[0], ls.Addr, k, ls.PT)
		} else {
			m.sendReset(m.socks[0], ls.Addr, k, ls.PT)
		}
		n++
	}
	return n
}

// logResets reports the resets sent at start.
func logResets(n int) {
	if n > 0 {
		log.Printf("sent a reset to %d sessions of the previous run, so their clients reconnect now", n)
	}
}
