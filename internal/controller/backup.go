package controller

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Jetvac/wdtt-router/internal/agent"
	"github.com/Jetvac/wdtt-router/internal/auth"
	"github.com/Jetvac/wdtt-router/internal/backup"
	"github.com/Jetvac/wdtt-router/internal/sshx"
)

// postBackup returns an encrypted backup of the panel state.
func (a *App) postBackup(w http.ResponseWriter, r *http.Request, s auth.Session) {
	var body struct {
		Passphrase string `json:"passphrase"`
	}
	if !decode(w, r, &body) {
		return
	}
	if len(body.Passphrase) < backup.MinPassphrase {
		apiError(w, 400, fmt.Sprintf("пароль копии — не короче %d символов", backup.MinPassphrase))
		return
	}
	tmp := filepath.Join(a.DataDir, fmt.Sprintf(".backup-%d.db", time.Now().UnixNano()))
	defer os.Remove(tmp)
	// A consistent snapshot of the live database.
	if _, err := a.Store.DB.Exec(`VACUUM INTO ?`, tmp); err != nil {
		apiError(w, 500, "снимок базы: "+err.Error())
		return
	}
	db, err := os.ReadFile(tmp)
	if err != nil {
		apiError(w, 500, err.Error())
		return
	}
	entries, err := backup.Collect(a.DataDir, agent.WDTTDataDirs(), db)
	if err != nil {
		apiError(w, 500, err.Error())
		return
	}
	sealed, err := backup.Seal(entries, body.Passphrase)
	if err != nil {
		apiError(w, 500, err.Error())
		return
	}
	a.audit(r, s, "backup.download", fmt.Sprintf("%d KB", len(sealed)>>10))
	a.event(EventSecurity, "💾 Скачана резервная копия панели (%s, адрес %s)", s.Username, clientIP(r))
	name := "wdtt-router-backup-" + time.Now().UTC().Format("20060102-1504") + ".wbk"
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(sealed)
}

func (a *App) rotateSSHKey(w http.ResponseWriter, r *http.Request, s auth.Session) {
	id, err := a.Enqueue("ssh.rotate", 0, "Замена SSH-ключа панели на всех серверах", s.Username, nil)
	if err != nil {
		apiError(w, 500, err.Error())
		return
	}
	a.audit(r, s, "ssh.rotate", "")
	writeJSON(w, 202, map[string]int64{"job_id": id})
}

// runOn runs a shell command on a remote node with the given key, over
// the node's addresses in turn.
func (a *App) runOn(ctx context.Context, key sshx.SSH, n Node, cmd string) error {
	var last error
	for _, t := range a.targets(n) {
		if _, last = key.Run(ctx, t, cmd, nil, nil); last == nil {
			return nil
		}
	}
	return last
}

// jobRotateSSH replaces the panel's SSH key: the new key is added on every
// remote server and checked, and only then the old one is removed and the
// panel switches over. If any server cannot take the new key, nothing
// changes.
func (a *App) jobRotateSSH(ctx context.Context, j *jobRun) error {
	nodes, err := a.nodes()
	if err != nil {
		return err
	}
	oldPub, err := sshx.EnsureKey(a.SSH.KeyPath)
	if err != nil {
		return err
	}
	newPath := a.SSH.KeyPath + ".new"
	_ = os.Remove(newPath)
	newPub, err := sshx.EnsureKey(newPath)
	if err != nil {
		return err
	}
	switched := false
	defer func() {
		if !switched {
			_ = os.Remove(newPath)
		}
	}()
	newKey := sshx.SSH{KeyPath: newPath}
	oldB64, newB64 := strings.Fields(oldPub)[1], strings.Fields(newPub)[1]
	var remote []Node
	for _, n := range nodes {
		if !n.Local {
			remote = append(remote, n)
		}
	}
	add := fmt.Sprintf(`umask 077; mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys && (grep -qF %q ~/.ssh/authorized_keys || echo %q >> ~/.ssh/authorized_keys)`, newB64, newPub+" wdtt-router-panel")
	for i, n := range remote {
		j.Log("%s: добавляю новый ключ", n.Name)
		if err := a.runOn(ctx, a.SSH, n, add); err != nil {
			// Undo on the servers done so far; the old key stays valid.
			for _, d := range remote[:i] {
				_ = a.runOn(ctx, a.SSH, d, removeKeyCmd(newB64))
			}
			return fmt.Errorf("%s: %w — ключ не заменён", n.Name, err)
		}
		if err := a.runOn(ctx, newKey, n, "true"); err != nil {
			for _, d := range remote[:i+1] {
				_ = a.runOn(ctx, a.SSH, d, removeKeyCmd(newB64))
			}
			return fmt.Errorf("%s: вход с новым ключом не работает: %w — ключ не заменён", n.Name, err)
		}
	}
	if err := os.Rename(a.SSH.KeyPath, a.SSH.KeyPath+".old"); err != nil {
		return err
	}
	if err := os.Rename(newPath, a.SSH.KeyPath); err != nil {
		_ = os.Rename(a.SSH.KeyPath+".old", a.SSH.KeyPath)
		return err
	}
	switched = true
	for _, n := range remote {
		if err := a.runOn(ctx, a.SSH, n, removeKeyCmd(oldB64)); err != nil {
			j.Log("%s: не удалось удалить старый ключ: %v", n.Name, err)
			continue
		}
		j.Log("%s: старый ключ удалён", n.Name)
	}
	_ = os.Remove(a.SSH.KeyPath + ".old")
	a.event(EventSecurity, "🔑 SSH-ключ панели заменён на %d серверах. Скачайте новую резервную копию: в прежних копиях старый ключ", len(remote))
	j.Log("Скачайте новую резервную копию: в прежних копиях старый ключ, он на серверах уже удалён")
	return nil
}

func removeKeyCmd(b64 string) string {
	return fmt.Sprintf(`f=~/.ssh/authorized_keys; if [ -f "$f" ]; then grep -vF %q "$f" > "$f.wdtt"; cat "$f.wdtt" > "$f"; rm -f "$f.wdtt"; fi`, b64)
}

// postDiagnostics returns a ZIP with each server's diagnostics (logs,
// service states, firewall, routes; secrets masked) and the panel's view.
func (a *App) postDiagnostics(w http.ResponseWriter, r *http.Request, s auth.Session) {
	nodes, err := a.nodes()
	if err != nil {
		apiError(w, 500, err.Error())
		return
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	add := func(name, text string) {
		f, err := zw.Create(name)
		if err == nil {
			_, _ = f.Write([]byte(text))
		}
	}
	type result struct {
		name, text string
	}
	results := make([]result, len(nodes))
	var wg sync.WaitGroup
	for i, n := range nodes {
		wg.Add(1)
		go func(i int, n Node) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
			defer cancel()
			// The agent on the server may predate the diag command.
			if !n.Local {
				_ = a.ensureAgent(ctx, n, func(string) {})
			}
			out, err := a.agentCall(ctx, n, nil, nil, "diag")
			text := string(out)
			if err != nil {
				text = fmt.Sprintf("не удалось получить данные: %v\n%s", err, text)
			}
			results[i] = result{safeFileName(n.Name) + ".txt", text}
		}(i, n)
	}
	wg.Wait()
	for _, res := range results {
		add(res.name, res.text)
	}
	var panel strings.Builder
	fmt.Fprintf(&panel, "WDTT Router %s\n\n", agent.Version)
	for _, n := range nodes {
		fmt.Fprintf(&panel, "%s: last seen %s, last error %q, Mesh %s\n", n.Name, n.LastSeen, n.LastError, n.MeshIP)
	}
	fmt.Fprintf(&panel, "\nLast chain check: %s\n\nRecent events:\n", a.Store.Setting("last_probe", "none"))
	for _, e := range a.recentEvents(50) {
		fmt.Fprintf(&panel, "%s [%s] %s\n", e.At, e.Kind, e.Text)
	}
	if jobs, err := a.jobs(30); err == nil {
		panel.WriteString("\nRecent jobs:\n")
		for _, j := range jobs {
			fmt.Fprintf(&panel, "#%d %s %s %s %s\n", j.ID, j.CreatedAt, j.Status, j.Title, j.Error)
		}
	}
	add("panel.txt", agent.Redact(panel.String()))
	if err := zw.Close(); err != nil {
		apiError(w, 500, err.Error())
		return
	}
	a.audit(r, s, "diagnostics.download", "")
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="wdtt-router-diagnostics-`+time.Now().UTC().Format("20060102-1504")+`.zip"`)
	_, _ = w.Write(buf.Bytes())
}

func safeFileName(s string) string {
	return strings.Map(func(r rune) rune {
		if strings.ContainsRune(`/\:`, r) || r < 32 {
			return '_'
		}
		return r
	}, s)
}
