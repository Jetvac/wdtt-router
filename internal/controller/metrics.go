package controller

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/Jetvac/wdtt-router/internal/auth"
)

// Metrics: one sample per server a minute (load, memory, traffic, WDTT
// sessions on the panel's server) and the chain latency every few minutes,
// kept for a week.

type counters struct {
	rx, tx int64
	at     time.Time
}

type rates struct {
	mu   sync.Mutex
	last map[int64]counters
}

func (a *App) recordMetrics(n Node) {
	st := n.Status
	mem := 0.0
	if st.MemTotalMB > 0 {
		mem = 100 * float64(st.MemTotalMB-st.MemAvailMB) / float64(st.MemTotalMB)
	}
	var rx, tx float64
	now := time.Now()
	a.rates.mu.Lock()
	if a.rates.last == nil {
		a.rates.last = map[int64]counters{}
	}
	if prev, ok := a.rates.last[n.ID]; ok {
		dt := now.Sub(prev.at).Seconds()
		if dt > 5 && st.NetRxBytes >= prev.rx && st.NetTxBytes >= prev.tx {
			rx = float64(st.NetRxBytes-prev.rx) * 8 / dt / 1e6
			tx = float64(st.NetTxBytes-prev.tx) * 8 / dt / 1e6
		}
	}
	a.rates.last[n.ID] = counters{st.NetRxBytes, st.NetTxBytes, now}
	a.rates.mu.Unlock()
	sessions := -1
	if n.Local && st.WDTT != nil {
		sessions = st.WDTT.Sessions
	}
	_, _ = a.Store.DB.Exec(`INSERT INTO metrics(node_id,at,load,mem,rx_mbps,tx_mbps,sessions,ping_ms) VALUES(?,?,?,?,?,?,?,-1)`,
		n.ID, now.Unix(), st.Load1, mem, rx, tx, sessions)
}

func (a *App) recordPing(ms int64) {
	_, _ = a.Store.DB.Exec(`INSERT INTO metrics(node_id,at,ping_ms) VALUES(0,?,?)`, time.Now().Unix(), ms)
}

type seriesPoint struct {
	At       int64   `json:"t"`
	Load     float64 `json:"load"`
	Mem      float64 `json:"mem"`
	Rx       float64 `json:"rx"`
	Tx       float64 `json:"tx"`
	Sessions float64 `json:"sessions"`
}

// getMetrics returns averages per time bucket (about 240 points).
func (a *App) getMetrics(w http.ResponseWriter, r *http.Request, s auth.Session) {
	hours, _ := strconv.Atoi(r.URL.Query().Get("hours"))
	if hours <= 0 || hours > 168 {
		hours = 24
	}
	from := time.Now().Add(-time.Duration(hours) * time.Hour).Unix()
	bucket := int64(hours * 3600 / 240)
	rows, err := a.Store.DB.Query(`SELECT node_id, (at/?)*? AS b, AVG(load), AVG(mem), AVG(rx_mbps), AVG(tx_mbps), MAX(sessions)
		FROM metrics WHERE node_id>0 AND at>=? GROUP BY node_id, b ORDER BY b`, bucket, bucket, from)
	if err != nil {
		apiError(w, 500, err.Error())
		return
	}
	nodes := map[int64][]seriesPoint{}
	for rows.Next() {
		var id int64
		var p seriesPoint
		if rows.Scan(&id, &p.At, &p.Load, &p.Mem, &p.Rx, &p.Tx, &p.Sessions) == nil {
			nodes[id] = append(nodes[id], p)
		}
	}
	rows.Close()
	type pingPoint struct {
		At int64   `json:"t"`
		Ms float64 `json:"ms"`
	}
	ping := []pingPoint{}
	prow, err := a.Store.DB.Query(`SELECT (at/?)*? AS b, AVG(ping_ms) FROM metrics WHERE node_id=0 AND ping_ms>=0 AND at>=? GROUP BY b ORDER BY b`, bucket, bucket, from)
	if err == nil {
		for prow.Next() {
			var p pingPoint
			if prow.Scan(&p.At, &p.Ms) == nil {
				ping = append(ping, p)
			}
		}
		prow.Close()
	}
	out := map[string]any{"hours": hours, "bucket": bucket, "ping": ping, "nodes": map[string][]seriesPoint{}}
	byNode := out["nodes"].(map[string][]seriesPoint)
	for id, pts := range nodes {
		byNode[strconv.FormatInt(id, 10)] = pts
	}
	writeJSON(w, 200, out)
}
