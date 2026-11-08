package wdtt

import (
	"encoding/json"
	"log"
	"net/netip"
	"os"
	"path/filepath"
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
}

func sessionsFile(statusFile string) string {
	if statusFile == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(statusFile), "wdtt-sessions.json")
}

func (m *mux) live() []liveSession {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]liveSession, 0, len(m.conns))
	for _, c := range m.conns {
		out = append(out, liveSession{Addr: c.raddr, Key: c.keyID, PT: c.tx.pt})
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
		m.sendReset(m.socks[0], ls.Addr, k, ls.PT)
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
