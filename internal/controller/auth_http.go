package controller

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Jetvac/wdtt-router/internal/auth"
)

type authedHandler func(http.ResponseWriter, *http.Request, auth.Session)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func apiError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		apiError(w, 400, "Invalid request")
		return false
	}
	return true
}

func (a *App) withAuth(h authedHandler, mutate bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("__Host-wdtt_session")
		if err != nil {
			apiError(w, 401, "Login required")
			return
		}
		s, err := auth.ReadSession(a.Store.DB, cookie.Value)
		if err != nil {
			apiError(w, 401, "Session expired")
			return
		}
		if mutate && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(s.CSRF)) != 1 {
			apiError(w, 403, "CSRF token required")
			return
		}
		h(w, r, s)
	}
}

func (a *App) allowLogin(ip string) bool {
	a.loginMu.Lock()
	defer a.loginMu.Unlock()
	cutoff := time.Now().Add(-15 * time.Minute)
	list := a.loginFailures[ip]
	keep := list[:0]
	for _, t := range list {
		if t.After(cutoff) {
			keep = append(keep, t)
		}
	}
	a.loginFailures[ip] = keep
	return len(keep) < 5
}
func (a *App) failedLogin(ip string) {
	a.loginMu.Lock()
	a.loginFailures[ip] = append(a.loginFailures[ip], time.Now())
	a.loginMu.Unlock()
}
func (a *App) clearLogin(ip string) {
	a.loginMu.Lock()
	delete(a.loginFailures, ip)
	a.loginMu.Unlock()
}

func (a *App) login(w http.ResponseWriter, r *http.Request) {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip == "" {
		ip = r.RemoteAddr
	}
	if !a.allowLogin(ip) {
		apiError(w, 429, "Too many attempts. Try again later.")
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decode(w, r, &body) {
		return
	}
	if len(body.Username) > 128 || len(body.Password) > 256 {
		apiError(w, 400, "Invalid credentials")
		return
	}
	id, ok := auth.Authenticate(a.Store.DB, strings.TrimSpace(body.Username), body.Password)
	if !ok {
		a.failedLogin(ip)
		apiError(w, 401, "Invalid credentials")
		return
	}
	a.clearLogin(ip)
	token, csrf, err := auth.NewSession(a.Store.DB, id)
	if err != nil {
		apiError(w, 500, "Could not create session")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "__Host-wdtt_session", Value: token, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: int((12 * time.Hour).Seconds())})
	writeJSON(w, 200, map[string]string{"username": body.Username, "csrf": csrf})
}

func (a *App) logout(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	c, _ := r.Cookie("__Host-wdtt_session")
	if c != nil {
		_ = auth.Revoke(a.Store.DB, c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: "__Host-wdtt_session", Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *App) me(w http.ResponseWriter, r *http.Request, s auth.Session) {
	writeJSON(w, 200, map[string]string{"username": s.Username, "csrf": s.CSRF})
}

func (a *App) changePassword(w http.ResponseWriter, r *http.Request, s auth.Session) {
	var body struct {
		Old string `json:"old"`
		New string `json:"new"`
	}
	if !decode(w, r, &body) {
		return
	}
	if err := auth.ChangePassword(a.Store.DB, s.UserID, body.Old, body.New); err != nil {
		if errors.Is(err, auth.ErrWeakPassword) {
			apiError(w, 400, "Password must have at least 16 characters")
		} else {
			apiError(w, 400, "Current password is incorrect")
		}
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "__Host-wdtt_session", Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	writeJSON(w, 200, map[string]bool{"ok": true})
}
