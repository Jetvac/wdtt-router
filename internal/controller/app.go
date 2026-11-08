// Package controller is the web panel: HTTPS API, job queue, planner and the
// embedded user interface.
package controller

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/fs"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Jetvac/wdtt-router/internal/auth"
	"github.com/Jetvac/wdtt-router/internal/sshx"
	"github.com/Jetvac/wdtt-router/internal/store"
)

// App is the controller.
type App struct {
	Store      *store.Store
	SSH        sshx.SSH
	DataDir    string
	PanelPort  int
	PublicHost string
	UI         fs.FS
	wake       chan struct{}

	loginMu    sync.Mutex
	loginFails map[string][]time.Time
}

// Open opens the panel state in dir.
func Open(dir string, port int, publicHost string, ui fs.FS) (*App, error) {
	st, err := store.Open(dir)
	if err != nil {
		return nil, err
	}
	a := &App{Store: st, SSH: sshx.SSH{KeyPath: filepath.Join(dir, "ssh_ed25519")}, DataDir: dir, PanelPort: port,
		PublicHost: publicHost, UI: ui, wake: make(chan struct{}, 1), loginFails: map[string][]time.Time{}}
	if _, err := sshx.EnsureKey(a.SSH.KeyPath); err != nil {
		return nil, err
	}
	return a, nil
}

// Init creates the first user and the local node. It returns the generated
// password once; later calls return empty values.
func (a *App) Init(publicHost string) (string, string, error) {
	var count int
	_ = a.Store.DB.QueryRow(`SELECT COUNT(*) FROM nodes WHERE local=1`).Scan(&count)
	if count == 0 {
		host, _ := os.Hostname()
		if host == "" {
			host = "entry"
		}
		if _, err := a.Store.DB.Exec(`INSERT INTO nodes(name,host,ssh_port,local,ssh_public,firewall,created_at) VALUES(?,?,22,1,1,1,?)`, host, publicHost, now()); err != nil {
			return "", "", err
		}
	}
	if publicHost != "" {
		_, _ = a.Store.DB.Exec(`UPDATE nodes SET host=? WHERE local=1`, publicHost)
	}
	return auth.CreateInitialUser(a.Store.DB)
}

// Serve runs the HTTPS server and background workers until ctx ends.
func (a *App) Serve(ctx context.Context, listen string) error {
	cert, err := a.certificate()
	if err != nil {
		return err
	}
	go a.worker(ctx)
	go a.refresher(ctx)
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			_ = a.Store.Prune()
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
	srv := &http.Server{
		Addr:              listen,
		Handler:           a.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}},
		ErrorLog:          log.New(os.Stderr, "http: ", 0),
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	log.Printf("panel listening on https://%s", listen)
	if err := srv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// certificate loads or creates the self-signed panel certificate.
func (a *App) certificate() (tls.Certificate, error) {
	crt, key := filepath.Join(a.DataDir, "panel.crt"), filepath.Join(a.DataDir, "panel.key")
	if c, err := tls.LoadX509KeyPair(crt, key); err == nil {
		return c, nil
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "WDTT Router panel"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(10, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	if ip := net.ParseIP(a.PublicHost); ip != nil {
		tpl.IPAddresses = append(tpl.IPAddresses, ip)
	} else if a.PublicHost != "" {
		tpl.DNSNames = append(tpl.DNSNames, a.PublicHost)
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	kb, _ := x509.MarshalECPrivateKey(priv)
	if err := os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0600); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(crt, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		return tls.Certificate{}, err
	}
	return tls.LoadX509KeyPair(crt, key)
}

// CertFingerprint returns the SHA-256 fingerprint of the panel certificate.
func (a *App) CertFingerprint() string {
	c, err := a.certificate()
	if err != nil || len(c.Certificate) == 0 {
		return ""
	}
	sum := sha256.Sum256(c.Certificate[0])
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = strings.ToUpper(hex.EncodeToString([]byte{b}))
	}
	return strings.Join(parts, ":")
}

// ---- HTTP plumbing --------------------------------------------------------

type ctxUser struct{}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func apiError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		apiError(w, http.StatusBadRequest, "некорректный запрос: "+err.Error())
		return false
	}
	return true
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Strict-Transport-Security", "max-age=31536000")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// authed wraps a handler with session and CSRF checks.
func (a *App) authed(h func(http.ResponseWriter, *http.Request, auth.Session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("wdttr_session")
		if err != nil {
			apiError(w, http.StatusUnauthorized, "требуется вход")
			return
		}
		s, err := auth.ReadSession(a.Store.DB, c.Value)
		if err != nil {
			apiError(w, http.StatusUnauthorized, "сессия истекла")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if r.Header.Get("X-CSRF-Token") != s.CSRF {
				apiError(w, http.StatusForbidden, "CSRF-токен не совпадает, обновите страницу")
				return
			}
		}
		h(w, r, s)
	}
}

func (a *App) loginAllowed(ip string) bool {
	a.loginMu.Lock()
	defer a.loginMu.Unlock()
	cut := time.Now().Add(-15 * time.Minute)
	keep := a.loginFails[ip][:0]
	for _, t := range a.loginFails[ip] {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	a.loginFails[ip] = keep
	return len(keep) < 8
}

func (a *App) loginFailed(ip string) {
	a.loginMu.Lock()
	a.loginFails[ip] = append(a.loginFails[ip], time.Now())
	a.loginMu.Unlock()
}

func (a *App) static() http.Handler {
	files := http.FileServer(http.FS(a.UI))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p == "" || p == "index.html" {
			a.serveIndex(w)
			return
		}
		if _, err := fs.Stat(a.UI, p); err != nil {
			// Client-side routes fall back to the SPA.
			a.serveIndex(w)
			return
		}
		if strings.HasPrefix(p, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		files.ServeHTTP(w, r)
	})
}

func (a *App) serveIndex(w http.ResponseWriter) {
	b, err := fs.ReadFile(a.UI, "index.html")
	if err != nil {
		http.Error(w, "UI is not built", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(b)
}
