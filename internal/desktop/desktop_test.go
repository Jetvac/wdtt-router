package desktop

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func TestCleanServer(t *testing.T) {
	s, err := cleanServer(" ssh://admin@203.0.113.5:2222 ", 0, "", "")
	if err != nil || s.Host != "203.0.113.5" || s.Port != 2222 || s.User != "admin" || s.Name != "203.0.113.5" {
		t.Fatalf("got %+v, %v", s, err)
	}
	if s, _ = cleanServer("example.org", 0, "", "Мой сервер"); s.Port != 22 || s.User != "root" || s.Name != "Мой сервер" {
		t.Fatalf("defaults: %+v", s)
	}
	for _, bad := range []string{"", "1.2.3.4; reboot", "a b", "$(id)", "x'y"} {
		if _, err := cleanServer(bad, 0, "", ""); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestCleanLine(t *testing.T) {
	if got := cleanLine("\x1b[1;34m•\x1b[0m Загружаю\r"); got != "• Загружаю" {
		t.Fatalf("%q", got)
	}
}

func TestStoreKeepsKey(t *testing.T) {
	dir := t.TempDir()
	a, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if a.PublicKey("pc") != b.PublicKey("pc") || !strings.HasPrefix(a.PublicKey("my pc"), "ssh-ed25519 ") || !strings.HasSuffix(a.PublicKey("my pc"), " wdtt-router-app@my_pc") {
		t.Fatalf("key not kept: %q vs %q", a.PublicKey("pc"), b.PublicKey("pc"))
	}
}

// The local server answers only the app's own window.
func TestLocalAccess(t *testing.T) {
	ui := fstest.MapFS{"launcher.html": {Data: []byte("<html>launcher</html>")}}
	a, err := New(t.TempDir(), ui, "test")
	if err != nil {
		t.Fatal(err)
	}
	l, start, err := a.Listen()
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	host := strings.TrimPrefix(a.Base(), "http://")
	do := func(method, target, h string, cookie *http.Cookie, ct string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, target, strings.NewReader("{}"))
		r.Host = h
		if cookie != nil {
			r.AddCookie(cookie)
		}
		if ct != "" {
			r.Header.Set("Content-Type", ct)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	if w := do("GET", "/_app/", "evil.example:80", nil, ""); w.Code != 403 {
		t.Fatalf("foreign host: %d", w.Code)
	}
	if w := do("GET", "/_app/api/state", host, nil, ""); w.Code != 403 {
		t.Fatalf("no cookie: %d", w.Code)
	}
	if w := do("GET", "/_app/auth?k=wrong", host, nil, ""); w.Code != 403 {
		t.Fatalf("wrong secret: %d", w.Code)
	}
	w := do("GET", strings.TrimPrefix(start, "http://"+host), host, nil, "")
	if w.Code != 302 || len(w.Result().Cookies()) != 1 {
		t.Fatalf("auth: %d %v", w.Code, w.Result().Cookies())
	}
	c := w.Result().Cookies()[0]
	if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie flags: %+v", c)
	}
	if w := do("GET", "/_app/api/state", host, &http.Cookie{Name: "wdtt_app", Value: "guess"}, ""); w.Code != 403 {
		t.Fatalf("guessed cookie: %d", w.Code)
	}
	w = do("GET", "/_app/api/state", host, c, "")
	var st struct {
		PublicKey string `json:"public_key"`
		Level     string `json:"level"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &st) != nil || !strings.HasPrefix(st.PublicKey, "ssh-ed25519 ") || st.Level != "off" {
		t.Fatalf("state: %d %s", w.Code, w.Body)
	}
	if w := do("POST", "/_app/api/disconnect", host, c, "text/plain"); w.Code != 415 {
		t.Fatalf("form post accepted: %d", w.Code)
	}
	if w := do("GET", "/", host, c, ""); w.Code != 302 || w.Header().Get("Location") != "/_app/" {
		t.Fatalf("panel without connection: %d %s", w.Code, w.Header().Get("Location"))
	}
	if w := do("GET", "/_app/", host, c, ""); w.Code != 200 || !strings.Contains(w.Body.String(), "launcher") {
		t.Fatalf("launcher: %d", w.Code)
	}
}
