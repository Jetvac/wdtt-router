package controller

import (
	"fmt"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Jetvac/wdtt-router/internal/agent"
	"github.com/Jetvac/wdtt-router/internal/auth"
)

// DesktopSession is what the Windows app receives over SSH: a panel session
// and how to reach the panel through the SSH tunnel. Only root on the panel
// server can create one, and root controls the panel anyway, so the app's
// SSH key is its credential and no password is involved.
type DesktopSession struct {
	Token       string `json:"token"`
	CSRF        string `json:"csrf"`
	Username    string `json:"username"`
	Port        int    `json:"port"`
	Fingerprint string `json:"fingerprint"`
	Version     string `json:"version"`
	Expires     string `json:"expires"`
}

// DesktopLogin creates a panel session for the app on the named computer.
func (a *App) DesktopLogin(device string) (DesktopSession, error) {
	var id int64
	var user string
	if err := a.Store.DB.QueryRow(`SELECT id,username FROM users ORDER BY id LIMIT 1`).Scan(&id, &user); err != nil {
		return DesktopSession{}, fmt.Errorf("нет пользователя панели: %w", err)
	}
	token, csrf, err := auth.NewSession(a.Store.DB, id)
	if err != nil {
		return DesktopSession{}, err
	}
	device = cleanDevice(device)
	a.Store.Audit(user, "login.desktop", device, "ssh")
	a.desktopSeen(device)
	port, _ := strconv.Atoi(a.Store.Setting("panel_port", ""))
	if port == 0 {
		port = a.PanelPort
	}
	return DesktopSession{Token: token, CSRF: csrf, Username: user, Port: port, Fingerprint: a.CertFingerprint(),
		Version: agent.Version, Expires: time.Now().UTC().Add(12 * time.Hour).Format(time.RFC3339)}, nil
}

func cleanDevice(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if s == "" {
		s = "без имени"
	}
	return short(s, 40)
}

// desktopSeen reports the first login from each computer: the app renews
// its session every 12 hours, so every login would be noise.
func (a *App) desktopSeen(device string) {
	known := strings.Split(a.Store.Setting("desktop_devices", ""), "\n")
	if slices.Contains(known, device) {
		return
	}
	a.event(EventSecurity, "🖥 Панель подключена в приложении на компьютере «%s» (вход по SSH-ключу)", device)
	known = append([]string{device}, known...)
	if len(known) > 20 {
		known = known[:20]
	}
	_ = a.Store.SetSetting("desktop_devices", strings.Trim(strings.Join(known, "\n"), "\n"))
}

// viaTunnel reports a request that came through an SSH tunnel on the panel
// server itself (the Windows app, or ssh -L): its source is loopback.
func viaTunnel(r *http.Request) bool {
	ip := net.ParseIP(clientIP(r))
	return ip != nil && ip.IsLoopback()
}

// getSummary is a short state of the whole setup for the app's tray icon:
// the same text the Telegram bot sends for /status.
func (a *App) getSummary(w http.ResponseWriter, r *http.Request, s auth.Session) {
	text := a.statusSummary()
	level := "ok"
	if strings.Contains(text, "🔴") {
		level = "bad"
	}
	writeJSON(w, 200, map[string]string{"level": level, "text": text})
}
