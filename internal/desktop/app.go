package desktop

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"slices"
	"strings"
	"sync"
	"time"
)

// App is the Windows app's core: a local HTTP server that shows the
// launcher (server list and setup) under /_app/ and relays everything else
// to the connected panel.
type App struct {
	Version string
	// Status is called when the overall state changes: level is ok, bad,
	// off (not connected) or wait (connecting).
	Status func(level, text string)
	// Notify shows a desktop notification.
	Notify func(title, text string)

	store  *Store
	ui     fs.FS
	device string
	secret string
	addr   string

	mu         sync.Mutex
	conn       *Conn
	connecting string
	lastErr    string
	level      string
	text       string
	ops        map[string]*op
}

func New(dir string, ui fs.FS, version string) (*App, error) {
	st, err := OpenStore(dir)
	if err != nil {
		return nil, err
	}
	device, _ := os.Hostname()
	if device == "" {
		device = "Windows"
	}
	a := &App{Version: version, store: st, ui: ui, device: device, secret: randomHex(24), ops: map[string]*op{},
		Status: func(string, string) {}, Notify: func(string, string) {}, level: "off", text: "Не подключено"}
	return a, nil
}

func (a *App) Store() *Store { return a.store }

// Listen opens the local server on a random loopback port and returns the
// address the window should open (it carries the one-time secret).
func (a *App) Listen() (net.Listener, string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", err
	}
	a.addr = l.Addr().String()
	return l, "http://" + a.addr + "/_app/auth?k=" + a.secret, nil
}

// Base is the local server's address, for links from the tray.
func (a *App) Base() string { return "http://" + a.addr }

func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Only the app's own window: the exact host (no DNS rebinding) and the
	// secret cookie (no other local program or web page).
	if r.Host != a.addr {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.URL.Path == "/_app/auth" {
		if subtle.ConstantTimeCompare([]byte(r.URL.Query().Get("k")), []byte(a.secret)) != 1 {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "wdtt_app", Value: a.secret, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
		http.Redirect(w, r, "/_app/?auto=1", http.StatusFound)
		return
	}
	if c, err := r.Cookie("wdtt_app"); err != nil || subtle.ConstantTimeCompare([]byte(c.Value), []byte(a.secret)) != 1 {
		http.Error(w, "Откройте WDTT Router из меню «Пуск» или значка в трее.", http.StatusForbidden)
		return
	}
	switch {
	case strings.HasPrefix(r.URL.Path, "/_app/api/"):
		a.api(w, r)
	case strings.HasPrefix(r.URL.Path, "/_app/"):
		a.static(w, r)
	default:
		a.mu.Lock()
		c := a.conn
		a.mu.Unlock()
		if c == nil {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				apiErr(w, http.StatusServiceUnavailable, "Приложение не подключено к серверу — откройте список серверов")
				return
			}
			http.Redirect(w, r, "/_app/", http.StatusFound)
			return
		}
		if r.URL.Path == "/api/logout" {
			// "Log out" in the app means leaving this server.
			a.Disconnect()
			writeJSON(w, 200, map[string]bool{"ok": true})
			return
		}
		c.proxy(w, r)
	}
}

func (a *App) static(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(path.Clean(r.URL.Path), "/_app")
	p = strings.TrimPrefix(p, "/")
	if p == "" || strings.HasSuffix(r.URL.Path, "/") {
		p = "launcher.html"
	}
	b, err := fs.ReadFile(a.ui, p)
	if err != nil {
		p = "launcher.html"
		if b, err = fs.ReadFile(a.ui, p); err != nil {
			http.Error(w, "launcher not built", 500)
			return
		}
	}
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	switch path.Ext(p) {
	case ".html":
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("Cache-Control", "no-store")
	case ".js":
		h.Set("Content-Type", "text/javascript; charset=utf-8")
	case ".css":
		h.Set("Content-Type", "text/css; charset=utf-8")
	case ".svg":
		h.Set("Content-Type", "image/svg+xml")
	}
	_, _ = w.Write(b)
}

// ---- launcher API ------------------------------------------------------------

type serverView struct {
	Server
	Active bool `json:"active"`
}

func (a *App) api(w http.ResponseWriter, r *http.Request) {
	route := strings.TrimPrefix(r.URL.Path, "/_app/api/")
	parts := strings.Split(route, "/")
	if r.Method != http.MethodGet && r.Header.Get("Content-Type") != "application/json" {
		apiErr(w, 415, "нужен JSON")
		return
	}
	switch {
	case r.Method == "GET" && route == "state":
		a.mu.Lock()
		active := ""
		if a.conn != nil {
			active = a.conn.srv.ID
		}
		state := map[string]any{"version": a.Version, "device": a.device, "public_key": a.store.PublicKey(a.device),
			"active": active, "connecting": a.connecting, "error": a.lastErr, "level": a.level, "text": a.text}
		a.mu.Unlock()
		list := a.store.List()
		slices.SortStableFunc(list, func(x, y Server) int { return strings.Compare(y.LastUsed, x.LastUsed) })
		views := make([]serverView, len(list))
		for i, s := range list {
			views[i] = serverView{s, s.ID == active}
		}
		state["servers"] = views
		writeJSON(w, 200, state)
	case r.Method == "POST" && route == "servers":
		var body struct {
			Name, Host, User, Password, Key, Passphrase string
			Port                                        int
		}
		if !decodeJSON(w, r, &body) {
			return
		}
		srv, err := cleanServer(body.Host, body.Port, body.User, body.Name)
		if err != nil {
			apiErr(w, 400, err.Error())
			return
		}
		login := &Login{Password: body.Password, Key: body.Key, Passphrase: body.Passphrase}
		if body.Password == "" && body.Key == "" {
			login = nil
		}
		writeJSON(w, 202, map[string]string{"op": a.startOp(func(ctx context.Context, o *op) (any, error) { return a.addServer(ctx, o, srv, login) })})
	case r.Method == "GET" && len(parts) == 2 && parts[0] == "ops":
		a.mu.Lock()
		o := a.ops[parts[1]]
		a.mu.Unlock()
		if o == nil {
			apiErr(w, 404, "операция не найдена")
			return
		}
		writeJSON(w, 200, o.view())
	case r.Method == "POST" && route == "disconnect":
		a.Disconnect()
		writeJSON(w, 200, map[string]bool{"ok": true})
	case len(parts) >= 2 && parts[0] == "servers":
		srv, ok := a.store.Get(parts[1])
		if !ok {
			apiErr(w, 404, "сервер не найден")
			return
		}
		a.serverAPI(w, r, srv, strings.Join(parts[2:], "/"))
	default:
		apiErr(w, 404, "нет такого действия")
	}
}

func (a *App) serverAPI(w http.ResponseWriter, r *http.Request, srv Server, action string) {
	switch {
	case r.Method == "POST" && action == "connect":
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		if err := a.Connect(ctx, srv.ID); err != nil {
			apiErr(w, 502, err.Error())
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	case r.Method == "POST" && (action == "install" || action == "update" || action == "restart" || action == "check"):
		var body struct {
			PublicHost string `json:"public_host"`
		}
		if !decodeJSON(w, r, &body) {
			return
		}
		writeJSON(w, 202, map[string]string{"op": a.startOp(func(ctx context.Context, o *op) (any, error) {
			return a.serverOp(ctx, o, srv, action, body.PublicHost)
		})})
	case r.Method == "PATCH" && action == "":
		var body struct {
			Name string `json:"name"`
		}
		if !decodeJSON(w, r, &body) {
			return
		}
		name := strings.TrimSpace(body.Name)
		if name == "" || len([]rune(name)) > 60 {
			apiErr(w, 400, "название — от 1 до 60 символов")
			return
		}
		if _, err := a.store.Update(srv.ID, func(s *Server) { s.Name = name }); err != nil {
			apiErr(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	case r.Method == "DELETE" && action == "":
		a.mu.Lock()
		active := a.conn != nil && a.conn.srv.ID == srv.ID
		a.mu.Unlock()
		if active {
			a.Disconnect()
		}
		if err := a.store.Delete(srv.ID); err != nil {
			apiErr(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	default:
		apiErr(w, 404, "нет такого действия")
	}
}

// ---- connection ----------------------------------------------------------------

// Connect switches the window to the panel on a server.
func (a *App) Connect(ctx context.Context, id string) error {
	srv, ok := a.store.Get(id)
	if !ok {
		return errors.New("сервер не найден")
	}
	a.mu.Lock()
	old := a.conn
	a.conn, a.connecting, a.lastErr = nil, id, ""
	a.mu.Unlock()
	if old != nil {
		old.Close()
	}
	a.setStatus("wait", "Подключение к "+srv.Name+"…")
	c := newConn(a, srv)
	s, err := c.login(ctx)
	if err == nil {
		var me struct {
			Version string `json:"version"`
		}
		err = c.getJSON(ctx, "/api/me", &me)
	}
	if err != nil {
		c.Close()
		switch {
		case errors.Is(err, errAuth):
			err = errors.New("сервер больше не принимает ключ приложения. Добавьте сервер заново, указав пароль root")
		case errors.Is(err, errOldPanel):
			err = errors.New("панель на сервере устарела и не поддерживает приложение: обновите её (меню сервера → «Обновить панель»)")
		}
		a.mu.Lock()
		if a.connecting == id {
			a.connecting, a.lastErr = "", srv.Name+": "+err.Error()
		}
		a.mu.Unlock()
		a.setStatus("off", "Не подключено: "+err.Error())
		log.Printf("connect %s: %v", srv.Host, err)
		return err
	}
	a.mu.Lock()
	if a.connecting != id { // another server was chosen meanwhile
		a.mu.Unlock()
		c.Close()
		return errors.New("подключение отменено")
	}
	a.conn, a.connecting = c, ""
	a.mu.Unlock()
	_, _ = a.store.Update(id, func(v *Server) {
		v.LastUsed = time.Now().UTC().Format(time.RFC3339)
		v.Version = s.Version
	})
	a.setStatus("ok", srv.Name+": подключено")
	log.Printf("connected to %s, panel %s", srv.Host, s.Version)
	go a.watch(c)
	return nil
}

// AutoConnect reconnects to the server used last, at start.
func (a *App) AutoConnect() {
	list := a.store.List()
	if len(list) == 0 {
		return
	}
	slices.SortStableFunc(list, func(x, y Server) int { return strings.Compare(y.LastUsed, x.LastUsed) })
	if list[0].LastUsed == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_ = a.Connect(ctx, list[0].ID)
}

func (a *App) Disconnect() {
	a.mu.Lock()
	c := a.conn
	a.conn, a.connecting = nil, ""
	a.mu.Unlock()
	if c != nil {
		c.Close()
	}
	a.setStatus("off", "Не подключено")
}

// Active is the connected server's name ("" when none).
func (a *App) Active() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.conn == nil {
		return ""
	}
	return a.conn.srv.Name
}

func (a *App) setStatus(level, text string) {
	a.mu.Lock()
	changed := a.level != level || a.text != text
	a.level, a.text = level, text
	a.mu.Unlock()
	if changed {
		a.Status(level, text)
	}
}

// watch keeps the tray state and notifications current while connected:
// the same summary and events the Telegram bot sends.
func (a *App) watch(c *Conn) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	fails := 0
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		var sum struct{ Level, Text string }
		err := c.getJSON(ctx, "/api/summary", &sum)
		if err == nil {
			fails = 0
			a.setStatus(sum.Level, c.srv.Name+"\n"+sum.Text)
			a.checkEvents(ctx, c)
		} else if fails++; fails >= 2 {
			a.setStatus("bad", c.srv.Name+": нет связи с сервером ("+err.Error()+")")
		}
		cancel()
		select {
		case <-c.stop:
			return
		case <-t.C:
		}
	}
}

type panelEvent struct {
	ID   int64  `json:"id"`
	Kind string `json:"kind"`
	Text string `json:"text"`
}

var eventTitles = map[string]string{"server": "Серверы", "chain": "Цепочка", "wdtt": "WDTT", "security": "Безопасность", "jobs": "Задачи", "update": "Обновление"}

func (a *App) checkEvents(ctx context.Context, c *Conn) {
	var events []panelEvent
	if c.getJSON(ctx, "/api/events", &events) != nil || len(events) == 0 {
		return
	}
	srv, _ := a.store.Get(c.srv.ID)
	var newest int64
	var fresh []panelEvent
	for _, e := range events {
		newest = max(newest, e.ID)
		if e.ID > srv.LastEvent && e.Kind != "test" {
			fresh = append(fresh, e)
		}
	}
	if newest <= srv.LastEvent {
		return
	}
	_, _ = a.store.Update(srv.ID, func(v *Server) { v.LastEvent = newest })
	if srv.LastEvent == 0 { // first connection: no flood of old events
		return
	}
	slices.SortFunc(fresh, func(x, y panelEvent) int { return int(x.ID - y.ID) })
	if len(fresh) > 3 {
		a.Notify(srv.Name, fmtCount(len(fresh))+": откройте панель, раздел «Обзор»")
		return
	}
	for _, e := range fresh {
		title := eventTitles[e.Kind]
		if title == "" {
			title = "Событие"
		}
		a.Notify(srv.Name+" · "+title, e.Text)
	}
}

func fmtCount(n int) string {
	return "Новых событий: " + itoa(n)
}

// ---- helpers -----------------------------------------------------------------------

func cleanServer(host string, port int, user, name string) (Server, error) {
	host = strings.TrimSpace(host)
	host = strings.TrimPrefix(host, "ssh://")
	if i := strings.LastIndex(host, "@"); i >= 0 {
		if user == "" {
			user = host[:i]
		}
		host = host[i+1:]
	}
	if h, p, err := net.SplitHostPort(host); err == nil {
		host = h
		if port == 0 {
			port = atoi(p)
		}
	}
	host = strings.Trim(host, "[]/ ")
	if host == "" || strings.ContainsAny(host, " /\\'\"`$;") {
		return Server{}, errors.New("укажите IP-адрес или имя сервера")
	}
	if port == 0 {
		port = 22
	}
	if port < 1 || port > 65535 {
		return Server{}, errors.New("некорректный порт SSH")
	}
	user = strings.TrimSpace(user)
	if user == "" {
		user = "root"
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = host
	}
	return Server{Host: host, Port: port, User: user, Name: name}, nil
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v); err != nil && !errors.Is(err, io.EOF) {
		apiErr(w, 400, "некорректный запрос")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func apiErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
