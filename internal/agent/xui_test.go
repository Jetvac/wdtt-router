package agent

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Jetvac/wdtt-router/internal/spec"
)

func testXUIDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "x-ui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	for _, q := range []string{
		`CREATE TABLE settings (id INTEGER PRIMARY KEY, key TEXT, value TEXT)`,
		`CREATE TABLE inbounds (id INTEGER PRIMARY KEY, remark TEXT, enable INTEGER, listen TEXT, port INTEGER, protocol TEXT, settings TEXT, stream_settings TEXT)`,
		`INSERT INTO settings(key,value) VALUES ('subListen','127.0.0.1'),('subPort','2096'),('subPath','/abc/'),('subJsonPath','/js/')`,
		`INSERT INTO inbounds(remark,enable,listen,port,protocol,settings,stream_settings) VALUES
			('reality', 1, '', 443, 'vless', '{"clients":[{"flow":"xtls-rprx-vision"}]}', '{"network":"tcp"}'),
			('broken', 1, '', 56813, 'vless', '{"clients":[{"flow":"xtls-rprx-vision"}]}', '{"network":"xhttp"}'),
			('fine', 1, '', 8443, 'vless', '{"clients":[{"flow":""}]}', '{"network":"xhttp"}'),
			('local', 1, '127.0.0.1', 9000, 'vless', '{"clients":[]}', '{"network":"tcp"}'),
			('off', 0, '', 9001, 'vless', '{"clients":[{"flow":"xtls-rprx-vision"}]}', '{"network":"ws"}')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func TestXUISubscriptions(t *testing.T) {
	db := testXUIDB(t)
	xuiSubURIMarker = filepath.Join(t.TempDir(), "marker")
	if got := xuiPorts(db); len(got) != 3 || got[0] != 443 {
		t.Fatalf("local subscriptions must stay closed: %v", got)
	}
	d, err := reconcileXUISubURI(db, spec.XUISpec{PublicSub: true, SubHost: "203.0.113.5"})
	if err != nil || !d {
		t.Fatal(d, err)
	}
	if v, _, _ := xuiSetting(db, "subURI"); v != "http://203.0.113.5:2096/abc/" {
		t.Fatal(v)
	}
	if v, _, _ := xuiSetting(db, "subJsonURI"); v != "http://203.0.113.5:2096/js/" {
		t.Fatal(v)
	}
	_ = xuiPut(db, "subListen", "")
	if got := xuiPorts(db); len(got) != 4 || got[0] != 443 || got[1] != 2096 {
		t.Fatalf("public subscriptions must be opened: %v", got)
	}
	// Closing again clears only what the panel set.
	_ = xuiPut(db, "subJsonURI", "https://sub.example.com/js/")
	if _, err := reconcileXUISubURI(db, spec.XUISpec{}); err != nil {
		t.Fatal(err)
	}
	if v, _, _ := xuiSetting(db, "subURI"); v != "" {
		t.Fatal("panel value left:", v)
	}
	if v, _, _ := xuiSetting(db, "subJsonURI"); v != "https://sub.example.com/js/" {
		t.Fatal("administrator value lost:", v)
	}
}

func TestXUIProblems(t *testing.T) {
	p := xuiProblems(testXUIDB(t))
	if len(p) != 1 || !strings.Contains(p[0], "«broken» (порт 56813)") || !strings.Contains(p[0], "XHTTP") {
		t.Fatalf("%q", p)
	}
}
