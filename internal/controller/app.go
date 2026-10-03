package controller

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Jetvac/wdtt-router/internal/auth"
	"github.com/Jetvac/wdtt-router/internal/store"
	"github.com/Jetvac/wdtt-router/internal/transport"
)

//go:embed static/*
var staticFiles embed.FS

type App struct {
	Store         *store.Store
	SSH           transport.SSH
	DataDir       string
	BinaryPath    string
	Version       string
	ListenAddr    string
	logger        *log.Logger
	loginMu       sync.Mutex
	updateMu      sync.Mutex
	loginFailures map[string][]time.Time
}

func New(dataDir, binaryPath string) (*App, error) {
	s, err := store.Open(dataDir)
	if err != nil {
		return nil, err
	}
	keyPath := filepath.Join(dataDir, "controller_ssh_key")
	if _, err := transport.EnsureKey(keyPath); err != nil {
		s.Close()
		return nil, err
	}
	return &App{Store: s, SSH: transport.SSH{KeyPath: keyPath}, DataDir: dataDir, BinaryPath: binaryPath, logger: log.New(os.Stderr, "wdtt-panel: ", log.LstdFlags), loginFailures: map[string][]time.Time{}}, nil
}

func Initialize(dataDir, publicHost string) (string, string, error) {
	a, err := New(dataDir, "")
	if err != nil {
		return "", "", err
	}
	defer a.Store.Close()
	user, password, err := auth.CreateInitialUser(a.Store.DB)
	if err != nil {
		return "", "", err
	}
	if publicHost != "" {
		hostname, _ := os.Hostname()
		_, err = a.Store.DB.Exec(`INSERT INTO servers(id,name,host,port,role,transport,created_at) VALUES(1,?,?,22,'ingress','local',?) ON CONFLICT(id) DO NOTHING`, hostname, publicHost, time.Now().UTC().Format(time.RFC3339))
		if err != nil {
			return "", "", err
		}
	}
	return user, password, nil
}

func (a *App) Close() error { return a.Store.Close() }

func (a *App) Serve(ctx context.Context, addr string) error {
	a.ListenAddr = addr
	var count int
	if err := a.Store.DB.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		return errors.New("panel has no user; run wdtt-panel init first")
	}
	if err := a.Store.Prune(); err != nil {
		return err
	}
	var publicHost string
	_ = a.Store.DB.QueryRow(`SELECT host FROM servers WHERE transport='local' LIMIT 1`).Scan(&publicHost)
	cert, key, err := ensureTLS(a.DataDir, publicHost)
	if err != nil {
		return err
	}
	server := &http.Server{Addr: addr, Handler: a.routes(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 16}
	go a.work(ctx)
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = a.Store.Prune()
			}
		}
	}()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	a.logger.Printf("serving HTTPS on %s", addr)
	err = server.ListenAndServeTLS(cert, key)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func ensureTLS(dir, publicHost string) (string, string, error) {
	certPath := filepath.Join(dir, "panel.crt")
	keyPath := filepath.Join(dir, "panel.key")
	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			return certPath, keyPath, nil
		}
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", err
	}
	hostname, _ := os.Hostname()
	tpl := x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "WDTT Mesh Control Panel"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, DNSNames: []string{"localhost", hostname}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}}
	if ip := net.ParseIP(publicHost); ip != nil {
		tpl.IPAddresses = append(tpl.IPAddresses, ip)
	} else if publicHost != "" {
		tpl.DNSNames = append(tpl.DNSNames, publicHost)
	}
	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &priv.PublicKey, priv)
	if err != nil {
		return "", "", err
	}
	keyDer, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return "", "", err
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDer}), 0600); err != nil {
		return "", "", err
	}
	return certPath, keyPath, nil
}

func (a *App) routes() http.Handler {
	mux := http.NewServeMux()
	root, err := fs.Sub(staticFiles, "static")
	if err != nil {
		panic(err)
	}
	mux.Handle("/", http.FileServer(http.FS(root)))
	mux.HandleFunc("POST /api/login", a.login)
	mux.HandleFunc("POST /api/logout", a.withAuth(a.logout, true))
	mux.HandleFunc("GET /api/me", a.withAuth(a.me, false))
	mux.HandleFunc("POST /api/password", a.withAuth(a.changePassword, true))
	mux.HandleFunc("GET /api/overview", a.withAuth(a.overview, false))
	mux.HandleFunc("GET /api/servers", a.withAuth(a.servers, false))
	mux.HandleFunc("POST /api/servers", a.withAuth(a.addServer, true))
	mux.HandleFunc("POST /api/servers/{id}/actions", a.withAuth(a.action, true))
	mux.HandleFunc("GET /api/servers/{id}/status", a.withAuth(a.serverStatus, false))
	mux.HandleFunc("GET /api/servers/{id}/secrets/{kind}", a.withAuth(a.serverSecret, false))
	mux.HandleFunc("GET /api/jobs", a.withAuth(a.jobs, false))
	mux.HandleFunc("GET /api/chains", a.withAuth(a.chains, false))
	mux.HandleFunc("POST /api/chains", a.withAuth(a.addChain, true))
	mux.HandleFunc("GET /api/events", a.withAuth(a.events, false))
	mux.HandleFunc("POST /api/cloudflare", a.withAuth(a.saveCloudflare, true))
	mux.HandleFunc("GET /api/cloudflare", a.withAuth(a.cloudflareSettings, false))
	mux.HandleFunc("GET /api/cloudflare/live", a.withAuth(a.cloudflareLive, false))
	mux.HandleFunc("POST /api/mesh/preflight", a.withAuth(a.meshPreflight, true))
	mux.HandleFunc("POST /api/cloudflare/deploy", a.withAuth(a.queueCloudflareDeploy, true))
	mux.HandleFunc("GET /api/cloudflare/resources", a.withAuth(a.cloudflareResources, false))
	mux.HandleFunc("GET /api/diagnostics", a.withAuth(a.diagnostics, false))
	mux.HandleFunc("GET /api/update", a.withAuth(a.updateStatus, false))
	mux.HandleFunc("POST /api/update", a.withAuth(a.scheduleUpdate, true))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; form-action 'self'")
		w.Header().Set("Cache-Control", "no-store")
		mux.ServeHTTP(w, r)
	})
}

func (a *App) loggerError(err error) {
	if err != nil {
		a.logger.Print(fmt.Sprintf("operation failed: %T", err))
	}
}
