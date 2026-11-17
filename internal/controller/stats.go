package controller

import (
	"archive/zip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Jetvac/wdtt-router/internal/agent"
	"github.com/Jetvac/wdtt-router/internal/auth"
	"github.com/Jetvac/wdtt-router/internal/spec"
	"github.com/Jetvac/wdtt-router/internal/wdtt"
)

// Statistics of TurnVK connections: the TurnVK server writes them next to
// its state (internal/wdtt/stats.go); the panel shows their size, sets
// the limit, clears and downloads them.

const maxStatsLimitMB = 100 << 10 // 100 GB

func statsDir() string {
	return filepath.Join(agent.WDTTServerOf(spec.WDTTTurnVK).Data, wdtt.StatsDirName)
}

type statsInfo struct {
	Enabled   bool  `json:"enabled"`
	LimitMB   int   `json:"limit_mb"`
	DefaultMB int   `json:"default_mb"`
	Bytes     int64 `json:"bytes"`
	Files     int   `json:"files"`
	Oldest    int64 `json:"oldest,omitempty"` // unix seconds of the oldest hour
	Newest    int64 `json:"newest,omitempty"`
	DiskFree  int64 `json:"disk_free"`
	DiskTotal int64 `json:"disk_total"`
}

func readStatsInfo() statsInfo {
	dir := statsDir()
	l := wdtt.ReadStatsLimit(dir)
	in := statsInfo{Enabled: !l.Off, LimitMB: l.MB, DefaultMB: wdtt.DefaultStatsLimitMB}
	if in.LimitMB <= 0 {
		in.LimitMB = wdtt.DefaultStatsLimitMB
	}
	files := wdtt.ListStats(dir)
	for _, f := range files {
		in.Bytes += f.Size
	}
	in.Files = len(files)
	if len(files) > 0 {
		in.Oldest, in.Newest = files[0].Hour.Unix(), files[len(files)-1].Hour.Unix()
	}
	// The disk the statistics are on (the data directory's parent exists
	// even before the first record).
	var fs syscall.Statfs_t
	if syscall.Statfs(filepath.Dir(dir), &fs) == nil {
		in.DiskFree = int64(fs.Bavail) * int64(fs.Bsize)
		in.DiskTotal = int64(fs.Blocks) * int64(fs.Bsize)
	}
	return in
}

func (a *App) getStats(w http.ResponseWriter, r *http.Request, s auth.Session) {
	writeJSON(w, 200, readStatsInfo())
}

func (a *App) putStats(w http.ResponseWriter, r *http.Request, s auth.Session) {
	var body struct {
		Enabled bool `json:"enabled"`
		LimitMB int  `json:"limit_mb"`
	}
	if !decode(w, r, &body) {
		return
	}
	if body.LimitMB < 10 || body.LimitMB > maxStatsLimitMB {
		apiError(w, 400, fmt.Sprintf("лимит — от 10 МБ до %d ГБ", maxStatsLimitMB>>10))
		return
	}
	if err := wdtt.WriteStatsLimit(statsDir(), wdtt.StatsLimit{MB: body.LimitMB, Off: !body.Enabled}); err != nil {
		apiError(w, 500, err.Error())
		return
	}
	a.audit(r, s, "stats.settings", fmt.Sprintf("enabled=%v limit=%d MB", body.Enabled, body.LimitMB))
	writeJSON(w, 200, readStatsInfo())
}

func (a *App) clearStats(w http.ResponseWriter, r *http.Request, s auth.Session) {
	before := readStatsInfo()
	if err := wdtt.ClearStats(statsDir()); err != nil {
		apiError(w, 500, err.Error())
		return
	}
	a.audit(r, s, "stats.clear", fmt.Sprintf("%d files, %d KB", before.Files, before.Bytes>>10))
	writeJSON(w, 200, readStatsInfo())
}

// downloadStats sends every file in one ZIP (the earlier hours are gzip
// already and go in as they are).
func (a *App) downloadStats(w http.ResponseWriter, r *http.Request, s auth.Session) {
	dir := statsDir()
	files := wdtt.ListStats(dir)
	if len(files) == 0 {
		apiError(w, 404, "статистики пока нет")
		return
	}
	a.audit(r, s, "stats.download", fmt.Sprintf("%d files", len(files)))
	name := "turnvk-stats-" + time.Now().UTC().Format("20060102-1504") + ".zip"
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	zw := zip.NewWriter(w)
	for _, f := range files {
		method := zip.Deflate
		if strings.HasSuffix(f.Name, ".gz") {
			method = zip.Store
		}
		hw, err := zw.CreateHeader(&zip.FileHeader{Name: f.Name, Method: method, Modified: f.Hour})
		if err != nil {
			return
		}
		in, err := os.Open(filepath.Join(dir, f.Name))
		if err != nil {
			continue // removed meanwhile (limit)
		}
		_, err = io.Copy(hw, in)
		in.Close()
		if err != nil {
			return
		}
	}
	_ = zw.Close()
}
