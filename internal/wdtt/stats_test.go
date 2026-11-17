package wdtt

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func statsMsg(t *testing.T, id byte, body string) []byte {
	t.Helper()
	var b bytes.Buffer
	b.Write([]byte{msgStats, directVersion, 0, 0, 0, id})
	zw := zlib.NewWriter(&b)
	zw.Write([]byte(body))
	zw.Close()
	return b.Bytes()
}

func TestStatsClientReports(t *testing.T) {
	dir := t.TempDir()
	st := newStats(dir)
	sess := &session{keyID: "k1", dev: "pc-1"}
	from := netip.MustParseAddrPort("1.2.3.4:5")
	now := time.Date(2026, 11, 17, 10, 5, 0, 0, time.UTC)

	ack, ok := st.clientReport(sess, from, statsMsg(t, 7, `{"app":"0.5.0","m":[{"rx":1}]}`), now)
	if !ok || !bytes.Equal(ack, []byte{msgStatsAck, directVersion, 0, 0, 0, 7}) {
		t.Fatalf("ack %x %v", ack, ok)
	}
	// A resend is acknowledged but not stored twice.
	if _, ok := st.clientReport(sess, from, statsMsg(t, 7, `{"app":"0.5.0","m":[{"rx":1}]}`), now); !ok {
		t.Fatal("resend not acknowledged")
	}
	// Not JSON, not an object: no ack, the client has a bug.
	if _, ok := st.clientReport(sess, from, statsMsg(t, 8, `[1]`), now); ok {
		t.Fatal("array accepted")
	}
	st.flush(now, true)
	b, err := os.ReadFile(filepath.Join(dir, StatsDirName, "2026-11-17-10.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(b), "\n"); n != 1 || !strings.Contains(string(b), `"dev":"pc-1"`) || !strings.Contains(string(b), `"r":{"app":"0.5.0"`) {
		t.Fatalf("%d lines: %s", n, b)
	}

	// The next hour: the previous one is compressed.
	st.add(map[string]any{"type": "server"})
	st.flush(now.Add(time.Hour), true)
	files := ListStats(filepath.Join(dir, StatsDirName))
	if len(files) != 2 || files[0].Name != "2026-11-17-10.jsonl.gz" || files[1].Name != "2026-11-17-11.jsonl" {
		t.Fatalf("files %+v", files)
	}
	f, _ := os.Open(filepath.Join(dir, StatsDirName, files[0].Name))
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	gz, _ := io.ReadAll(zr)
	f.Close()
	if !bytes.Equal(gz, b) {
		t.Fatal("compressed file differs")
	}

	if err := ClearStats(filepath.Join(dir, StatsDirName)); err != nil {
		t.Fatal(err)
	}
	if n := len(ListStats(filepath.Join(dir, StatsDirName))); n != 0 {
		t.Fatalf("%d files after clearing", n)
	}
}

func TestStatsRateLimit(t *testing.T) {
	st := newStats(t.TempDir())
	sess := &session{keyID: "k1", dev: "a"}
	now := time.Now()
	for i := 0; i < reportsPerMin+5; i++ {
		if _, ok := st.clientReport(sess, netip.AddrPort{}, statsMsg(t, byte(i+1), `{}`), now); !ok {
			t.Fatal("not acknowledged")
		}
	}
	if n := strings.Count(st.pending.String(), "\n"); n != reportsPerMin {
		t.Fatalf("%d stored, want %d", n, reportsPerMin)
	}
}

func TestStatsLimit(t *testing.T) {
	dir := t.TempDir()
	sd := filepath.Join(dir, StatsDirName)
	os.MkdirAll(sd, 0o700)
	big := bytes.Repeat([]byte("x"), 400<<10)
	for _, h := range []string{"2026-11-17-01", "2026-11-17-02", "2026-11-17-03"} {
		os.WriteFile(filepath.Join(sd, h+".jsonl.gz"), big, 0o600)
	}
	if err := WriteStatsLimit(sd, StatsLimit{MB: 1}); err != nil {
		t.Fatal(err)
	}
	st := newStats(dir)
	st.flush(time.Date(2026, 11, 17, 4, 0, 0, 0, time.UTC), true)
	files := ListStats(sd)
	if len(files) != 2 || files[0].Name != "2026-11-17-02.jsonl.gz" {
		t.Fatalf("files %+v", files)
	}

	// Off: nothing is written.
	WriteStatsLimit(sd, StatsLimit{MB: 1, Off: true})
	st.flush(time.Date(2026, 11, 17, 4, 0, 0, 0, time.UTC), true)
	st.add(map[string]any{"type": "server"})
	st.flush(time.Date(2026, 11, 17, 4, 0, 10, 0, time.UTC), false)
	if _, err := os.Stat(filepath.Join(sd, "2026-11-17-04.jsonl")); err == nil {
		t.Fatal("written while off")
	}
}

// A TurnVK client's report over a direct path is acknowledged and stored.
func TestStatsOverDirectPath(t *testing.T) {
	cfg := Config{MainPassword: "owner-pass", Kind: KindTurnVK, Iface: "wdtt1", Network: "10.66.67.0/24"}
	s, _, addr, stop := startServer(t, cfg)
	defer stop()
	c := newDClient(t, addr, "owner-pass", randKey())
	if w := c.hello("pc-1", time.Now()); w == nil || w[18] != welcomeOK {
		t.Fatalf("welcome %v", w)
	}
	c.send(statsMsg(t, 9, `{"client":"TurnVK test","m":[{"rx":5}]}`))
	var ack []byte
	for m := c.recv(2 * time.Second); m != nil; m = c.recv(2 * time.Second) {
		if m[0] == msgStatsAck {
			ack = m
			break
		}
	}
	if !bytes.Equal(ack, []byte{msgStatsAck, directVersion, 0, 0, 0, 9}) {
		t.Fatalf("ack %v", ack)
	}
	s.stats.flush(time.Now(), true)
	files := ListStats(filepath.Join(s.cfg.DataDir, StatsDirName))
	if len(files) != 1 {
		t.Fatalf("files %+v", files)
	}
	b, _ := os.ReadFile(filepath.Join(s.cfg.DataDir, StatsDirName, files[0].Name))
	if !strings.Contains(string(b), `"type":"client"`) || !strings.Contains(string(b), `"dev":"pc-1"`) || !strings.Contains(string(b), `"key":"main"`) {
		t.Fatalf("record: %s", b)
	}
}
