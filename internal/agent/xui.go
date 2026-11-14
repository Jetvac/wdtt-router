package agent

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"github.com/Jetvac/wdtt-router/internal/spec"
	_ "modernc.org/sqlite"
)

const (
	xuiVersion   = "v3.11.0"
	xuiInstaller = "https://raw.githubusercontent.com/MHSanaei/3x-ui/v3.11.0/install.sh"
	xuiSHA       = "9684bae4f769b2127fcceceb4f200045657381311867529e6ba76c6b58e2825d"
	xuiBin       = "/usr/local/x-ui/x-ui"
	xuiDB        = "/etc/x-ui/x-ui.db"
	xuiOwned     = EtcDir + "/xui-owned"
	chainTag     = "wdtt-chain"
)

//go:embed xui_template.json
var xuiDefaultTemplate string

func xuiInstalled() bool { return exists(xuiBin) }

func openXUIDB() (*sql.DB, error) {
	return sql.Open("sqlite", "file:"+xuiDB+"?_pragma=busy_timeout(5000)")
}

func xuiSetting(db *sql.DB, key string) (string, bool, error) {
	var v string
	err := db.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return v, err == nil, err
}

func xuiPut(db *sql.DB, key, value string) error {
	res, err := db.Exec(`UPDATE settings SET value=? WHERE key=?`, value, key)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		_, err = db.Exec(`INSERT INTO settings(key,value) VALUES(?,?)`, key, value)
	}
	return err
}

// patchTemplate adds or removes the chain outbound. With add=true the chain
// becomes the first (default) outbound of 3x-ui.
func patchTemplate(tpl string, add bool, e *spec.EntrySpec) (string, error) {
	var cfg map[string]any
	if err := json.Unmarshal([]byte(tpl), &cfg); err != nil {
		return "", fmt.Errorf("3x-ui Xray template is not valid JSON: %w", err)
	}
	outs, _ := cfg["outbounds"].([]any)
	kept := []any{}
	for _, o := range outs {
		if m, ok := o.(map[string]any); ok && m["tag"] == chainTag {
			continue
		}
		kept = append(kept, o)
	}
	if add {
		chain := map[string]any{
			"tag": chainTag, "protocol": "socks",
			"settings": map[string]any{"address": "127.0.0.1", "port": e.SocksPort, "user": e.SocksUser, "pass": e.SocksPass},
		}
		kept = append([]any{chain}, kept...)
	}
	cfg["outbounds"] = kept
	b, err := json.MarshalIndent(cfg, "", "  ")
	return string(b), err
}

func reconcileXUI(ctx context.Context, e *spec.EntrySpec, changed *[]string, secrets map[string]string) error {
	want := e != nil && e.XUI.Enabled
	if !want {
		if !xuiInstalled() {
			return nil
		}
		if !exists(xuiOwned) {
			// Not ours: only detach from the chain, never uninstall.
			return detachXUI(ctx, changed)
		}
		Logf("removing 3x-ui")
		_ = systemctl(ctx, "disable", "--now", "x-ui.service")
		removeIfExists("/etc/systemd/system/x-ui.service", "/usr/local/x-ui", "/etc/x-ui", "/usr/bin/x-ui", xuiOwned)
		_ = systemctl(ctx, "daemon-reload")
		_ = systemctl(ctx, "reset-failed", "x-ui.service")
		*changed = append(*changed, "3x-ui: removed")
		return nil
	}
	if !xuiInstalled() {
		Logf("installing 3x-ui %s", xuiVersion)
		if err := aptInstall(ctx, "curl", "tar", "ca-certificates"); err != nil {
			return err
		}
		script, err := fetch(ctx, xuiInstaller, xuiSHA)
		if err != nil {
			return err
		}
		path := VarDir + "/xui-install.sh"
		if err := os.MkdirAll(VarDir, 0700); err != nil {
			return err
		}
		if err := os.WriteFile(path, script, 0700); err != nil {
			return err
		}
		c := exec.CommandContext(ctx, "bash", path, xuiVersion)
		c.Env = append(os.Environ(), "XUI_NONINTERACTIVE=1", "XUI_SSL_MODE=none", "XUI_DB_TYPE=sqlite", "DEBIAN_FRONTEND=noninteractive")
		c.Stdin = nil
		out, err := c.CombinedOutput()
		_ = os.Remove(path)
		if err != nil || !xuiInstalled() {
			return fmt.Errorf("3x-ui installer failed: %v: %s", err, tail(redact(string(out)), 400))
		}
		if err := os.WriteFile(xuiOwned, []byte(xuiVersion+"\n"), 0600); err != nil {
			return err
		}
		for k, v := range XUICredentials() {
			secrets[k] = v
		}
		*changed = append(*changed, "3x-ui: installed")
	}
	db, err := openXUIDB()
	if err != nil {
		return err
	}
	defer db.Close()
	dirty := false
	subListen := "127.0.0.1"
	if e.XUI.PublicSub {
		subListen = "" // all addresses
	}
	for key, val := range map[string]string{"webListen": "127.0.0.1", "subListen": subListen} {
		cur, _, err := xuiSetting(db, key)
		if err != nil {
			return err
		}
		if cur != val {
			if err := xuiPut(db, key, val); err != nil {
				return err
			}
			dirty = true
		}
	}
	if d, err := reconcileXUISubURI(db, e.XUI); err != nil {
		return err
	} else if d {
		dirty = true
		if e.XUI.PublicSub {
			*changed = append(*changed, "3x-ui: subscriptions open to the Internet")
		} else {
			*changed = append(*changed, "3x-ui: subscriptions local only")
		}
	}
	tpl, ok, err := xuiSetting(db, "xrayTemplateConfig")
	if err != nil {
		return err
	}
	if !ok || strings.TrimSpace(tpl) == "" {
		tpl = xuiDefaultTemplate
	}
	patched, err := patchTemplate(tpl, e.XUI.RouteViaChain, e)
	if err != nil {
		return err
	}
	if normJSON(patched) != normJSON(tpl) || !ok {
		if err := xuiPut(db, "xrayTemplateConfig", patched); err != nil {
			return err
		}
		dirty = true
		if e.XUI.RouteViaChain {
			*changed = append(*changed, "3x-ui: traffic routed through the chain")
		} else {
			*changed = append(*changed, "3x-ui: chain outbound removed")
		}
	}
	if dirty || unitState("x-ui.service") != "active" {
		if err := systemctl(ctx, "restart", "x-ui.service"); err != nil {
			return err
		}
	}
	return waitActive(ctx, "x-ui.service")
}

func detachXUI(ctx context.Context, changed *[]string) error {
	db, err := openXUIDB()
	if err != nil {
		return nil
	}
	defer db.Close()
	tpl, ok, _ := xuiSetting(db, "xrayTemplateConfig")
	if !ok || !strings.Contains(tpl, chainTag) {
		return nil
	}
	patched, err := patchTemplate(tpl, false, nil)
	if err != nil {
		return err
	}
	if err := xuiPut(db, "xrayTemplateConfig", patched); err != nil {
		return err
	}
	*changed = append(*changed, "3x-ui: detached from the chain")
	return systemctl(ctx, "restart", "x-ui.service")
}

func normJSON(s string) string {
	var v any
	if json.Unmarshal([]byte(s), &v) != nil {
		return s
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// xuiSubURIMarker remembers the subscription addresses the panel wrote into
// 3x-ui, so it clears only its own values when subscriptions close again.
var xuiSubURIMarker = VarDir + "/xui-sub-uri"

func xuiSettingDef(db *sql.DB, key, def string) string {
	if v, ok, _ := xuiSetting(db, key); ok && v != "" {
		return v
	}
	return def
}

// reconcileXUISubURI points the subscription links 3x-ui shows at the
// public address (3x-ui would build them from the address its web panel was
// opened at, which is 127.0.0.1 through the SSH tunnel).
func reconcileXUISubURI(db *sql.DB, x spec.XUISpec) (bool, error) {
	want := map[string]string{"subURI": "", "subJsonURI": ""}
	if x.PublicSub && x.SubHost != "" {
		host := x.SubHost
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
		base := "http://" + host + ":" + xuiSettingDef(db, "subPort", "2096")
		want["subURI"] = base + xuiSettingDef(db, "subPath", "/sub/")
		want["subJsonURI"] = base + xuiSettingDef(db, "subJsonPath", "/json/")
	}
	ours := map[string]string{}
	if b, err := os.ReadFile(xuiSubURIMarker); err == nil {
		_ = json.Unmarshal(b, &ours)
	}
	dirty := false
	for key, val := range want {
		cur, _, err := xuiSetting(db, key)
		if err != nil {
			return false, err
		}
		// A value the administrator set in 3x-ui (a domain behind a
		// reverse proxy) is kept.
		if cur == val || (cur != "" && cur != ours[key]) {
			continue
		}
		if err := xuiPut(db, key, val); err != nil {
			return false, err
		}
		dirty = true
	}
	if dirty {
		b, _ := json.Marshal(want)
		if err := os.WriteFile(xuiSubURIMarker, b, 0600); err != nil {
			return false, err
		}
	}
	return dirty, nil
}

// XUIProblems finds 3x-ui inbounds that accept clients but cannot carry
// their traffic.
func XUIProblems() []string {
	if !xuiInstalled() {
		return nil
	}
	db, err := openXUIDB()
	if err != nil {
		return nil
	}
	defer db.Close()
	return xuiProblems(db)
}

func xuiProblems(db *sql.DB) []string {
	rows, err := db.Query(`SELECT COALESCE(remark,''), port, COALESCE(protocol,''), COALESCE(settings,''), COALESCE(stream_settings,'') FROM inbounds WHERE enable=1`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var remark, proto, settings, stream string
		var port int
		if rows.Scan(&remark, &port, &proto, &settings, &stream) != nil || proto != "vless" {
			continue
		}
		var st struct {
			Network string `json:"network"`
		}
		var cs struct {
			Clients []struct {
				Flow string `json:"flow"`
			} `json:"clients"`
		}
		_ = json.Unmarshal([]byte(stream), &st)
		_ = json.Unmarshal([]byte(settings), &cs)
		if st.Network == "" || st.Network == "tcp" || st.Network == "raw" {
			continue
		}
		for _, c := range cs.Clients {
			if c.Flow != "" {
				name := remark
				if name == "" {
					name = "без названия"
				}
				out = append(out, fmt.Sprintf("3x-ui: у подключения «%s» (порт %d) транспорт %s, а у клиентов задан Flow %s — он работает только с TCP: клиент подключится, но сайты открываться не будут. В настройках клиента выберите Flow «нет» или верните транспорт TCP (RAW)",
					name, port, strings.ToUpper(st.Network), c.Flow))
				break
			}
		}
	}
	return out
}

// XUIPorts lists the public ports of enabled 3x-ui inbounds and, when it
// listens publicly, of the subscription server.
func XUIPorts() []int {
	if !xuiInstalled() {
		return nil
	}
	db, err := openXUIDB()
	if err != nil {
		return nil
	}
	defer db.Close()
	return xuiPorts(db)
}

func xuiPorts(db *sql.DB) []int {
	rows, err := db.Query(`SELECT port, COALESCE(listen,'') FROM inbounds WHERE enable=1`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	seen := map[int]bool{}
	for rows.Next() {
		var port int
		var listen string
		if rows.Scan(&port, &listen) != nil || port < 1 || port > 65535 {
			continue
		}
		if isLoopback(listen) {
			continue
		}
		seen[port] = true
	}
	if l, _, _ := xuiSetting(db, "subListen"); !isLoopback(l) && xuiSettingDef(db, "subEnable", "true") == "true" {
		if p, err := strconv.Atoi(xuiSettingDef(db, "subPort", "2096")); err == nil && p > 0 && p < 65536 {
			seen[p] = true
		}
	}
	ports := []int{}
	for p := range seen {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports
}

// XUICredentials returns the access data written by the installer.
func XUICredentials() map[string]string {
	b, err := os.ReadFile("/etc/x-ui/install-result.env")
	if err != nil {
		return map[string]string{}
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), "'\"")
		switch k {
		case "XUI_USERNAME", "XUI_PASSWORD", "XUI_PANEL_PORT", "XUI_WEB_BASE_PATH":
			out[k] = v
		}
	}
	return out
}

// ResetXUICredentials sets a new login and password for 3x-ui.
func ResetXUICredentials(ctx context.Context, user, pass string) (map[string]string, error) {
	if !xuiInstalled() {
		return nil, errors.New("3x-ui is not installed")
	}
	if err := run(ctx, xuiBin, "setting", "-username", user, "-password", pass); err != nil {
		return nil, errors.New("could not change 3x-ui credentials")
	}
	_ = systemctl(ctx, "restart", "x-ui.service")
	creds := XUICredentials()
	creds["XUI_USERNAME"], creds["XUI_PASSWORD"] = user, pass
	if out, err := output(ctx, xuiBin, "setting", "-show"); err == nil {
		for _, l := range strings.Split(out, "\n") {
			if v, ok := strings.CutPrefix(strings.TrimSpace(l), "port: "); ok {
				creds["XUI_PANEL_PORT"] = v
			}
			if v, ok := strings.CutPrefix(strings.TrimSpace(l), "webBasePath: "); ok {
				creds["XUI_WEB_BASE_PATH"] = strings.Trim(v, "/")
			}
		}
	}
	return creds, nil
}

func redact(s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		low := strings.ToLower(l)
		if strings.Contains(low, "password") || strings.Contains(low, "token") || strings.Contains(low, "username") {
			lines[i] = "<redacted>"
		}
	}
	return strings.Join(lines, "\n")
}

func isLoopback(addr string) bool {
	return strings.HasPrefix(addr, "127.") || addr == "::1" || addr == "localhost"
}
