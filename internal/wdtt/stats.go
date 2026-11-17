package wdtt

// Statistics: what TurnVK clients report about their connections (STATS
// messages on their direct paths, through VK's TURN servers like
// everything else) and what the server sees of each device, one line of
// JSON per record, for analysing how the transport behaves.
//
// Files: <data dir>/stats/YYYY-MM-DD-HH.jsonl for the current hour, gzip
// for earlier hours. The panel sets a size limit (limit.json in the same
// directory, read every minute); the oldest hours go first, and when the
// current hour alone is over the limit, new records are dropped until the
// next hour. The panel also shows the size and clears the files.
//
// STATS (client -> server, after HELLO on the path):
//
//	0x49 | version | report id (4) | zlib(JSON object)
//
// STATSACK (server -> client): 0x4A | version | report id (4). The server
// acknowledges every well-formed report, stored or not, so that the client
// stops resending it.

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/json"
	"io"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	msgStats    = 0x49
	msgStatsAck = 0x4A

	// StatsDirName is the statistics directory inside the data directory.
	StatsDirName = "stats"
	// DefaultStatsLimitMB is the size limit when the panel set none.
	DefaultStatsLimitMB = 500

	statsLimitFile  = "limit.json"
	maxReportBytes  = 64 << 10 // a report, uncompressed
	reportsPerMin   = 20       // per device
	statsFlushEvery = 10 * time.Second
	maxPending      = 4 << 20 // records waiting for the next flush
)

// StatsLimit is the panel's setting, kept next to the files.
type StatsLimit struct {
	MB  int  `json:"mb"`  // 0 means DefaultStatsLimitMB
	Off bool `json:"off"` // collect nothing
}

func (l StatsLimit) bytes() int64 {
	mb := l.MB
	if mb <= 0 {
		mb = DefaultStatsLimitMB
	}
	return int64(mb) << 20
}

// ReadStatsLimit reads the setting (the default when there is none).
func ReadStatsLimit(dir string) StatsLimit {
	var l StatsLimit
	if b, err := os.ReadFile(filepath.Join(dir, statsLimitFile)); err == nil {
		_ = json.Unmarshal(b, &l)
	}
	return l
}

// WriteStatsLimit saves the setting; the server applies it within a minute.
func WriteStatsLimit(dir string, l StatsLimit) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, _ := json.Marshal(l)
	tmp := filepath.Join(dir, statsLimitFile+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, statsLimitFile))
}

// StatsFile is one hour of records.
type StatsFile struct {
	Name string
	Size int64
	Hour time.Time
}

// ListStats returns the files, oldest first.
func ListStats(dir string) []StatsFile {
	ents, _ := os.ReadDir(dir)
	var out []StatsFile
	for _, e := range ents {
		name := e.Name()
		base := strings.TrimSuffix(strings.TrimSuffix(name, ".gz"), ".jsonl")
		if e.IsDir() || base == name {
			continue
		}
		h, err := time.ParseInLocation("2006-01-02-15", base, time.UTC)
		if err != nil {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, StatsFile{Name: name, Size: fi.Size(), Hour: h})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ClearStats deletes every file of records (the setting stays).
func ClearStats(dir string) error {
	var first error
	for _, f := range ListStats(dir) {
		if err := os.Remove(filepath.Join(dir, f.Name)); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// stats collects records and writes them out every statsFlushEvery.
type stats struct {
	dir string

	mu      sync.Mutex
	pending bytes.Buffer
	dropped int
	limit   StatsLimit
	full    string // the hour that alone went over the limit
	rate    map[string]*devRate
	prev    map[string][2]int64 // device -> up, down at the last server record
}

type devRate struct {
	minute int64
	n      int
	seen   [32]uint32 // recent report ids (resends)
	next   int
}

func newStats(dataDir string) *stats {
	st := &stats{dir: filepath.Join(dataDir, StatsDirName), rate: map[string]*devRate{}, prev: map[string][2]int64{}}
	st.limit = ReadStatsLimit(st.dir)
	return st
}

// add queues one record; the time goes in as "t" (unix ms).
func (st *stats) add(rec map[string]any) {
	if st == nil {
		return
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.limit.Off {
		return
	}
	if st.pending.Len() > maxPending {
		st.dropped++
		return
	}
	if _, ok := rec["t"]; !ok {
		rec["t"] = time.Now().UnixMilli()
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	st.pending.Write(b)
	st.pending.WriteByte('\n')
}

// clientReport handles a STATS message; it returns the id to acknowledge.
func (st *stats) clientReport(sess *session, from netip.AddrPort, msg []byte, now time.Time) (ack []byte, ok bool) {
	if len(msg) < 7 || sess == nil {
		return nil, false
	}
	id := uint32(msg[2])<<24 | uint32(msg[3])<<16 | uint32(msg[4])<<8 | uint32(msg[5])
	ack = []byte{msgStatsAck, directVersion, msg[2], msg[3], msg[4], msg[5]}
	if st == nil {
		return ack, true
	}
	st.mu.Lock()
	r := st.rate[sess.dev]
	if r == nil {
		r = &devRate{}
		st.rate[sess.dev] = r
	}
	for _, s := range r.seen {
		if s == id && id != 0 {
			st.mu.Unlock()
			return ack, true // a resend of a report we have
		}
	}
	m := now.Unix() / 60
	if r.minute != m {
		r.minute, r.n = m, 0
	}
	r.n++
	over := r.n > reportsPerMin
	if !over {
		r.seen[r.next%len(r.seen)] = id
		r.next++
	}
	st.mu.Unlock()
	if over {
		return ack, true
	}
	zr, err := zlib.NewReader(bytes.NewReader(msg[6:]))
	if err != nil {
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(zr, maxReportBytes+1))
	if err != nil || len(body) > maxReportBytes || len(body) == 0 || body[0] != '{' || !json.Valid(body) {
		return nil, false
	}
	st.add(map[string]any{"t": now.UnixMilli(), "type": "client", "key": sess.keyID, "dev": sess.dev, "turn": from.String(), "r": json.RawMessage(body)})
	return ack, true
}

// serverRecords notes what the server sees of each device and of itself.
func (st *stats) serverRecords(s Status, now time.Time) {
	if st == nil {
		return
	}
	seen := map[string]bool{}
	for keyID, ks := range s.Keys {
		for _, d := range ks.Devices {
			st.mu.Lock()
			p, had := st.prev[d.ID]
			st.prev[d.ID] = [2]int64{d.Up, d.Down}
			st.mu.Unlock()
			seen[d.ID] = true
			up, down := d.Up-p[0], d.Down-p[1]
			if !had || up < 0 || down < 0 {
				up, down = 0, 0
			}
			if d.Paths == 0 && up == 0 && down == 0 {
				continue
			}
			st.add(map[string]any{"t": now.UnixMilli(), "type": "device", "key": keyID, "dev": d.ID, "paths": d.Paths, "sessions": d.Sessions, "rtt": d.RTT, "up": up, "down": down})
		}
	}
	st.mu.Lock()
	for id := range st.prev {
		if !seen[id] {
			delete(st.prev, id)
		}
	}
	for id, r := range st.rate {
		if r.minute < now.Unix()/60-60 {
			delete(st.rate, id)
		}
	}
	st.mu.Unlock()
	st.add(map[string]any{"t": now.UnixMilli(), "type": "server", "version": s.Version, "sessions": s.Sessions, "devices": s.Devices,
		"handshake_failures": s.HandshakeFailures, "auth_failures": s.AuthFailures, "stale_resets": s.StaleResets})
}

// flush writes the queued records to the current hour's file, compresses
// the earlier hours and keeps the files under the limit.
func (st *stats) flush(now time.Time, checkLimit bool) {
	if st == nil {
		return
	}
	st.mu.Lock()
	if checkLimit {
		st.limit = ReadStatsLimit(st.dir)
	}
	data := append([]byte(nil), st.pending.Bytes()...)
	st.pending.Reset()
	dropped := st.dropped
	st.dropped = 0
	limit, full := st.limit, st.full
	st.mu.Unlock()
	if dropped > 0 {
		log.Printf("statistics: %d records dropped (the disk is slow or the queue is full)", dropped)
	}
	if limit.Off {
		return
	}
	hour := now.UTC().Format("2006-01-02-15")
	if full == hour {
		return
	}
	if len(data) > 0 {
		if err := os.MkdirAll(st.dir, 0o700); err != nil {
			log.Printf("statistics: %v", err)
			return
		}
		f, err := os.OpenFile(filepath.Join(st.dir, hour+".jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			log.Printf("statistics: %v", err)
			return
		}
		_, err = f.Write(data)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			log.Printf("statistics: %v", err)
		}
	}
	if !checkLimit {
		return
	}
	files := ListStats(st.dir)
	for _, f := range files {
		if strings.HasSuffix(f.Name, ".jsonl") && !strings.HasPrefix(f.Name, hour) {
			if err := gzipFile(filepath.Join(st.dir, f.Name)); err != nil {
				log.Printf("statistics: compressing %s: %v", f.Name, err)
			}
		}
	}
	files = ListStats(st.dir)
	var total int64
	for _, f := range files {
		total += f.Size
	}
	max := limit.bytes()
	for i := 0; total > max && i < len(files); i++ {
		f := files[i]
		if strings.HasPrefix(f.Name, hour) {
			// The current hour alone is over the limit: stop until the next.
			st.mu.Lock()
			st.full = hour
			st.mu.Unlock()
			log.Printf("statistics: this hour's records reached the %d MB limit; collecting again next hour", max>>20)
			break
		}
		if err := os.Remove(filepath.Join(st.dir, f.Name)); err == nil {
			total -= f.Size
		}
	}
}

// gzipFile replaces name with name.gz.
func gzipFile(name string) error {
	in, err := os.Open(name)
	if err != nil {
		return err
	}
	tmp := name + ".gz.tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		in.Close()
		return err
	}
	zw, _ := gzip.NewWriterLevel(out, gzip.BestCompression)
	_, err = io.Copy(zw, in)
	in.Close()
	if cerr := zw.Close(); err == nil {
		err = cerr
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, name+".gz"); err != nil {
		return err
	}
	return os.Remove(name)
}
