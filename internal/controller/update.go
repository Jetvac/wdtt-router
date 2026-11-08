package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Jetvac/wdtt-router/internal/agent"
	"github.com/Jetvac/wdtt-router/internal/auth"
	"github.com/Jetvac/wdtt-router/internal/update"
)

const (
	installerPath = "/var/lib/wdtt-router/install.sh"
	backupsDir    = "/var/lib/wdtt-router/backups"
	EventUpdate   = "update"
)

type updateInfo struct {
	Release update.Release `json:"release"`
	Checked string         `json:"checked"`
	Error   string         `json:"error,omitempty"`
}

func (a *App) updateInfo() updateInfo {
	var u updateInfo
	_ = json.Unmarshal([]byte(a.Store.Setting("update_latest", "{}")), &u)
	return u
}

// checkUpdate looks for a newer release and reports it once.
func (a *App) checkUpdate(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	r, err := update.Latest(ctx)
	u := a.updateInfo()
	u.Checked = now()
	if err != nil {
		u.Error = err.Error()
	} else {
		u.Error = ""
		if r.Tag != u.Release.Tag && update.Newer(r.Tag, agent.Version) {
			a.event(EventUpdate, "⬆️ Доступна новая версия панели %s (сейчас %s)", r.Tag, agent.Version)
		}
		u.Release = r
	}
	b, _ := json.Marshal(u)
	_ = a.Store.SetSetting("update_latest", string(b))
}

func (a *App) updateChecker(ctx context.Context) {
	t := time.NewTicker(6 * time.Hour)
	defer t.Stop()
	for {
		a.checkUpdate(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// rollbackVersion is the version saved before the last update, if any.
func rollbackVersion() string {
	target, err := os.Readlink(filepath.Join(backupsDir, "last"))
	if err != nil {
		return ""
	}
	// "<date>-<time>-<version>"
	parts := strings.SplitN(filepath.Base(target), "-", 3)
	if len(parts) == 3 {
		return parts[2]
	}
	return ""
}

func (a *App) getUpdate(w http.ResponseWriter, r *http.Request, s auth.Session) {
	u := a.updateInfo()
	writeJSON(w, 200, map[string]any{
		"current":   agent.Version,
		"latest":    u.Release,
		"available": u.Release.Tag != "" && update.Newer(u.Release.Tag, agent.Version),
		"checked":   u.Checked,
		"error":     u.Error,
		"rollback":  rollbackVersion(),
	})
}

func (a *App) postUpdateCheck(w http.ResponseWriter, r *http.Request, s auth.Session) {
	a.checkUpdate(r.Context())
	a.getUpdate(w, r, s)
}

func (a *App) postUpdate(w http.ResponseWriter, r *http.Request, s auth.Session) {
	var body struct {
		Action string `json:"action"` // update | rollback
	}
	if !decode(w, r, &body) {
		return
	}
	var title string
	switch body.Action {
	case "update":
		u := a.updateInfo()
		if !update.Newer(u.Release.Tag, agent.Version) {
			apiError(w, 400, "новой версии нет")
			return
		}
		title = "Обновление панели до " + u.Release.Tag
	case "rollback":
		if rollbackVersion() == "" {
			apiError(w, 400, "нет сохранённой версии для отката")
			return
		}
		title = "Откат панели к версии " + rollbackVersion()
	default:
		apiError(w, 400, "unknown action")
		return
	}
	id, err := a.Enqueue("panel."+body.Action, 0, title, s.Username, nil)
	if err != nil {
		apiError(w, 500, err.Error())
		return
	}
	a.audit(r, s, "panel."+body.Action, title)
	writeJSON(w, 202, map[string]int64{"job_id": id})
}

// jobPanelUpdate fetches the signed installer of the release and runs it
// outside the panel's service: the installer restarts the panel and
// rolls back by itself if the new version does not start.
func (a *App) jobPanelUpdate(ctx context.Context, j *jobRun) error {
	return a.runInstaller(ctx, j, "update")
}

func (a *App) jobPanelRollback(ctx context.Context, j *jobRun) error {
	return a.runInstaller(ctx, j, "rollback")
}

func (a *App) runInstaller(ctx context.Context, j *jobRun, mode string) error {
	// A rollback needs no download: the installer keeps a copy of itself.
	if _, err := os.Stat(installerPath); mode == "rollback" && err == nil {
		return a.startInstaller(ctx, j, mode, "")
	}
	tag := a.updateInfo().Release.Tag
	if tag == "" {
		a.checkUpdate(ctx)
		if tag = a.updateInfo().Release.Tag; tag == "" {
			return fmt.Errorf("не удалось узнать последнюю версию: %s", a.updateInfo().Error)
		}
	}
	j.Log("Загружаю установщик %s и проверяю подпись релиза", tag)
	script, err := update.Installer(ctx, tag)
	if err != nil {
		return err
	}
	if err := os.WriteFile(installerPath, script, 0700); err != nil {
		return err
	}
	return a.startInstaller(ctx, j, mode, tag)
}

func (a *App) startInstaller(ctx context.Context, j *jobRun, mode, tag string) error {
	args := []string{"--unit=wdtt-router-update-" + fmt.Sprint(time.Now().Unix()), "--collect", "--quiet", "/bin/bash", installerPath, mode}
	if mode == "update" {
		args = append(args, "--version", tag)
	}
	if out, err := exec.CommandContext(ctx, "systemd-run", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("systemd-run: %v: %s", err, strings.TrimSpace(string(out)))
	}
	if mode == "update" {
		j.Log("Установщик запущен: панель перезапустится через несколько секунд. Если новая версия не запустится, вернётся прежняя.")
	} else {
		j.Log("Откат запущен: панель перезапустится через несколько секунд.")
	}
	return nil
}
