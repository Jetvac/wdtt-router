package desktop

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// panelSession mirrors controller.DesktopSession: what `wdtt-router
// desktop-login` prints on the server.
type panelSession struct {
	Token       string `json:"token"`
	CSRF        string `json:"csrf"`
	Username    string `json:"username"`
	Port        int    `json:"port"`
	Fingerprint string `json:"fingerprint"`
	Version     string `json:"version"`
}

var errOldPanel = errors.New("версия панели на сервере не поддерживает приложение")

// Conn is the connection to one panel: an SSH client to the panel server,
// a panel session made over SSH and HTTPS to the panel through the SSH
// tunnel, with the panel certificate checked against the fingerprint the
// server reported over SSH.
type Conn struct {
	app *App
	srv Server

	mu     sync.Mutex
	client *ssh.Client
	sess   panelSession
	closed bool

	transport *http.Transport
	stop      chan struct{}
}

func newConn(a *App, srv Server) *Conn {
	c := &Conn{app: a, srv: srv, stop: make(chan struct{})}
	c.transport = &http.Transport{
		DialTLSContext:        c.dialPanel,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 2 * time.Minute,
		ForceAttemptHTTP2:     false,
	}
	return c
}

// sshClient returns a live SSH client, connecting if needed.
func (c *Conn) sshClient(ctx context.Context) (*ssh.Client, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errors.New("отключено")
	}
	if c.client != nil {
		return c.client, nil
	}
	cl, _, err := dial(ctx, c.srv, c.app.store.Signer(), nil)
	if err != nil {
		return nil, err
	}
	c.client = cl
	go c.keepalive(cl)
	return cl, nil
}

// keepalive notices a dead connection early, so the next request redials
// instead of waiting for TCP to time out.
func (c *Conn) keepalive(cl *ssh.Client) {
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
		}
		res := make(chan error, 1)
		go func() {
			_, _, err := cl.SendRequest("keepalive@openssh.com", true, nil)
			res <- err
		}()
		var err error
		select {
		case err = <-res:
		case <-time.After(15 * time.Second):
			err = errors.New("timeout")
		}
		if err != nil {
			c.drop(cl)
			return
		}
	}
}

// drop forgets a broken SSH client.
func (c *Conn) drop(cl *ssh.Client) {
	c.mu.Lock()
	if c.client == cl {
		c.client = nil
	}
	c.mu.Unlock()
	cl.Close()
	c.transport.CloseIdleConnections()
}

// login makes a new panel session over SSH.
func (c *Conn) login(ctx context.Context) (panelSession, error) {
	cl, err := c.sshClient(ctx)
	if err != nil {
		return panelSession{}, err
	}
	var out, errb bytes.Buffer
	if err := runWith(ctx, cl, "wdtt-router desktop-login --device "+shellQuote(c.app.device), &out, &errb); err != nil {
		msg := errb.String()
		switch {
		case strings.Contains(msg, "wdtt-router serve"): // the usage text of a version without desktop-login
			return panelSession{}, errOldPanel
		case strings.Contains(msg, "not found"):
			return panelSession{}, errors.New("на сервере нет панели WDTT Router")
		case strings.TrimSpace(msg) != "":
			return panelSession{}, fmt.Errorf("вход в панель: %s", lastLines(msg, 3))
		}
		return panelSession{}, fmt.Errorf("вход в панель: %w", err)
	}
	var s panelSession
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &s); err != nil || s.Token == "" {
		return panelSession{}, fmt.Errorf("неожиданный ответ сервера: %q", lastLines(out.String(), 2))
	}
	c.mu.Lock()
	c.sess = s
	c.mu.Unlock()
	return s, nil
}

func (c *Conn) session() panelSession {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sess
}

// dialPanel opens TLS to the panel through the SSH tunnel.
func (c *Conn) dialPanel(ctx context.Context, _, _ string) (net.Conn, error) {
	s := c.session()
	var nc net.Conn
	for attempt := 0; ; attempt++ {
		cl, err := c.sshClient(ctx)
		if err != nil {
			return nil, err
		}
		nc, err = cl.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(s.Port)))
		if err == nil {
			break
		}
		// The SSH connection may have died (sleep, network change): redial once.
		c.drop(cl)
		if attempt == 1 {
			return nil, fmt.Errorf("панель на сервере не отвечает: %w", err)
		}
	}
	want := strings.ReplaceAll(strings.ToLower(s.Fingerprint), ":", "")
	tc := tls.Client(nc, &tls.Config{
		InsecureSkipVerify: true, // self-signed; checked against the fingerprint below
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("нет сертификата панели")
			}
			sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if hex.EncodeToString(sum[:]) != want {
				return errors.New("сертификат панели не совпадает с отпечатком, полученным по SSH")
			}
			return nil
		},
	})
	hctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := tc.HandshakeContext(hctx); err != nil {
		nc.Close()
		return nil, err
	}
	return tc, nil
}

// Do sends a request to the panel with the app's session, renewing the
// session once if the panel says it has expired.
func (c *Conn) Do(ctx context.Context, method, path string, header http.Header, body []byte) (*http.Response, error) {
	for attempt := 0; ; attempt++ {
		s := c.session()
		if s.Token == "" {
			var err error
			if s, err = c.login(ctx); err != nil {
				return nil, err
			}
		}
		req, err := http.NewRequestWithContext(ctx, method, "https://panel"+path, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		for k, v := range header {
			req.Header[k] = v
		}
		req.Header.Set("Cookie", "wdttr_session="+s.Token)
		if method != http.MethodGet && method != http.MethodHead {
			// The page may hold the token of an expired session.
			req.Header.Set("X-CSRF-Token", s.CSRF)
		}
		resp, err := c.transport.RoundTrip(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			resp.Body.Close()
			c.mu.Lock()
			c.sess.Token = ""
			c.mu.Unlock()
			continue
		}
		return resp, nil
	}
}

// getJSON is Do for the app's own requests.
func (c *Conn) getJSON(ctx context.Context, path string, v any) error {
	resp, err := c.Do(ctx, http.MethodGet, path, nil, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("%s: %s", path, resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(v)
}

// hop-by-hop and headers the app owns.
var dropRequest = []string{"Cookie", "Connection", "Keep-Alive", "Proxy-Connection", "Te", "Trailer", "Transfer-Encoding", "Upgrade", "Origin", "Referer", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Forwarded"}
var dropResponse = []string{"Set-Cookie", "Strict-Transport-Security", "Connection", "Keep-Alive", "Transfer-Encoding", "Trailer"}

// proxy relays a request from the window to the panel.
func (c *Conn) proxy(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<20))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	h := r.Header.Clone()
	for _, k := range dropRequest {
		h.Del(k)
	}
	// Lets the panel warn before closing the SSH the app depends on.
	h.Set("X-WDTT-App-Host", c.srv.Host)
	resp, err := c.Do(r.Context(), r.Method, r.URL.RequestURI(), h, body)
	if err != nil {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Нет связи с сервером: " + err.Error()})
			return
		}
		offline(w, err)
		return
	}
	defer resp.Body.Close()
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	for _, k := range dropResponse {
		w.Header().Del(k)
	}
	w.Header().Set("X-WDTT-Desktop", "1")
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (c *Conn) Close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	cl := c.client
	c.client = nil
	c.mu.Unlock()
	close(c.stop)
	c.transport.CloseIdleConnections()
	if cl != nil {
		cl.Close()
	}
}

func offline(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadGateway)
	fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><title>Нет связи</title>
<body style="font-family:system-ui,sans-serif;max-width:560px;margin:15vh auto;padding:0 16px;color:#333">
<h2>Нет связи с сервером</h2><p>%s</p>
<p><button onclick="location.reload()">Повторить</button> <a href="/_app/">К списку серверов</a></p></body>`, htmlEscape(err.Error()))
}

func htmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(s)
}
