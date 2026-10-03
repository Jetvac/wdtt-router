package controller

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/Jetvac/wdtt-router/internal/auth"
)

var releaseTagPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)

type panelUpdateState struct {
	Mode      string `json:"mode"`
	Target    string `json:"target"`
	Unit      string `json:"unit"`
	StartedAt string `json:"started_at"`
}

func (a *App) latestRelease(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/repos/Jetvac/wdtt-router/releases/latest", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub release API returned %d", resp.StatusCode)
	}
	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&release); err != nil {
		return "", err
	}
	if !releaseTagPattern.MatchString(release.TagName) {
		return "", errors.New("invalid latest release tag")
	}
	return release.TagName, nil
}

func (a *App) previousVersion() string {
	if _, err := os.Stat(filepath.Join(a.DataDir, "last-update-backup")); err != nil {
		return ""
	}
	out, err := exec.Command(a.BinaryPath+".previous", "version").Output()
	if err != nil {
		return ""
	}
	previous := strings.TrimSpace(string(out))
	if !releaseTagPattern.MatchString(previous) {
		return ""
	}
	return previous
}

func (a *App) updateStatus(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	latest, err := a.latestRelease(r.Context())
	status := map[string]any{"current": a.Version, "latest": latest, "previous": a.previousVersion(), "can_update": latest != "" && latest != a.Version}
	if err != nil {
		status["latest_error"] = "Could not reach GitHub Releases"
	}
	if b, readErr := os.ReadFile(filepath.Join(a.DataDir, "last-app-update.json")); readErr == nil {
		var last panelUpdateState
		if json.Unmarshal(b, &last) == nil {
			status["last"] = last
			status["last_completed"] = last.Target == a.Version
		}
	}
	writeJSON(w, 200, status)
}

func (a *App) scheduleUpdate(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	var body struct {
		Mode string `json:"mode"`
	}
	if !decode(w, r, &body) {
		return
	}
	var tag, target string
	switch body.Mode {
	case "update":
		var err error
		tag, err = a.latestRelease(r.Context())
		if err != nil || tag == a.Version {
			apiError(w, 400, "No newer GitHub Release is available")
			return
		}
		target = tag
	case "rollback":
		target = a.previousVersion()
		if target == "" || !releaseTagPattern.MatchString(a.Version) {
			apiError(w, 400, "Previous panel version is unavailable")
			return
		}
		tag = a.Version
	default:
		apiError(w, 400, "Unsupported update mode")
		return
	}
	var publicHost string
	if err := a.Store.DB.QueryRow(`SELECT host FROM servers WHERE transport='local' LIMIT 1`).Scan(&publicHost); err != nil || publicHost == "" {
		apiError(w, 500, "Local panel address is unavailable")
		return
	}
	_, port, err := net.SplitHostPort(a.ListenAddr)
	if err != nil {
		apiError(w, 500, "Panel listen port is unavailable")
		return
	}
	work := filepath.Join(a.DataDir, "updates", tag)
	if err := os.MkdirAll(work, 0700); err != nil {
		apiError(w, 500, "Could not prepare update directory")
		return
	}
	assets := []string{"install.sh", "SHA256SUMS"}
	if body.Mode == "update" {
		assets = append(assets, "wdtt-panel-linux-"+runtime.GOARCH+".tar.gz")
	}
	for _, name := range assets {
		if err := downloadReleaseAsset(r.Context(), tag, name, work); err != nil {
			apiError(w, 502, "Could not download verified release files")
			return
		}
	}
	for _, name := range assets {
		if name == "SHA256SUMS" {
			continue
		}
		if err := verifyReleaseAsset(work, name); err != nil {
			apiError(w, 502, "Release checksum verification failed")
			return
		}
	}
	if err := os.Chmod(filepath.Join(work, "install.sh"), 0700); err != nil {
		apiError(w, 500, "Could not prepare verified installer")
		return
	}
	id := make([]byte, 6)
	if _, err := rand.Read(id); err != nil {
		apiError(w, 500, "Could not schedule update")
		return
	}
	unit := "wdtt-panel-app-" + hex.EncodeToString(id)
	args := []string{"--quiet", "--unit=" + unit, "--on-active=5s", "--setenv=WDTT_PANEL_ARTIFACT_DIR=" + work, "/bin/bash", filepath.Join(work, "install.sh"), body.Mode, "--public-host", publicHost, "--port", port}
	if out, err := exec.CommandContext(r.Context(), "systemd-run", args...).CombinedOutput(); err != nil {
		a.loggerError(fmt.Errorf("systemd-run: %w: %s", err, trim(string(out), 200)))
		apiError(w, 500, "Could not schedule independent update")
		return
	}
	last := panelUpdateState{Mode: body.Mode, Target: target, Unit: unit, StartedAt: time.Now().UTC().Format(time.RFC3339)}
	if b, err := json.Marshal(last); err == nil {
		_ = os.WriteFile(filepath.Join(a.DataDir, "last-app-update.json"), b, 0600)
	}
	writeJSON(w, 202, last)
}

func downloadReleaseAsset(ctx context.Context, tag, name, dir string) error {
	url := "https://github.com/Jetvac/wdtt-router/releases/download/" + tag + "/" + name
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := (&http.Client{Timeout: 90 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("asset download returned %d", resp.StatusCode)
	}
	file, err := os.CreateTemp(dir, ".asset-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	limit := int64(16 << 20)
	if _, err := io.Copy(file, io.LimitReader(resp.Body, limit+1)); err != nil {
		file.Close()
		return err
	}
	if size, _ := file.Seek(0, io.SeekCurrent); size == 0 || size > limit {
		file.Close()
		return errors.New("invalid release asset size")
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), filepath.Join(dir, name))
}

func verifyReleaseAsset(dir, name string) error {
	sums, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	if err != nil {
		return err
	}
	var want string
	for _, line := range strings.Split(string(sums), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == name {
			want = fields[0]
			break
		}
	}
	if len(want) != 64 {
		return errors.New("release asset has no checksum")
	}
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return err
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != want {
		return errors.New("release checksum mismatch")
	}
	return nil
}
