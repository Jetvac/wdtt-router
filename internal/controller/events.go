package controller

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Jetvac/wdtt-router/internal/auth"
	"github.com/Jetvac/wdtt-router/internal/spec"
)

// Events are what the panel tells the administrator about: shown on the
// dashboard and forwarded by the Telegram bot.
const (
	EventServer   = "server"   // a server became unreachable or came back
	EventChain    = "chain"    // the chain check failed or recovered
	EventWDTT     = "wdtt"     // the WDTT server stopped or started
	EventSecurity = "security" // logins from new addresses, password guessing
	EventJobs     = "jobs"     // failed jobs
	EventTest     = "test"
)

// Event is one recorded event.
type Event struct {
	ID   int64  `json:"id"`
	At   string `json:"at"`
	Kind string `json:"kind"`
	Text string `json:"text"`
}

func (a *App) event(kind, format string, args ...any) {
	text := fmt.Sprintf(format, args...)
	if _, err := a.Store.DB.Exec(`INSERT INTO events(at,kind,text) VALUES(?,?,?)`, now(), kind, text); err != nil {
		log.Printf("event: %v", err)
	}
}

func (a *App) recentEvents(limit int) []Event {
	rows, err := a.Store.DB.Query(`SELECT id,at,kind,text FROM events ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var e Event
		if rows.Scan(&e.ID, &e.At, &e.Kind, &e.Text) == nil {
			out = append(out, e)
		}
	}
	return out
}

// ---- monitor ---------------------------------------------------------------

// monitor turns state changes seen by the status refresher into events.
type monitor struct {
	mu        sync.Mutex
	fails     map[int64]int
	offline   map[int64]time.Time
	wdttDown  bool
	chainDown bool
	round     int
}

// offlineAfter: consecutive failed status checks (one a minute) before a
// server counts as unreachable; one failure is often just a slow SSH.
const offlineAfter = 2

func (a *App) observe(ctx context.Context, n Node, err error) {
	m := &a.mon
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fails == nil {
		m.fails, m.offline = map[int64]int{}, map[int64]time.Time{}
	}
	if err != nil {
		m.fails[n.ID]++
		if m.fails[n.ID] == offlineAfter {
			m.offline[n.ID] = time.Now()
			a.event(EventServer, "🔴 Сервер %s не отвечает (%s)", n.Name, short(err.Error(), 160))
		}
		return
	}
	m.fails[n.ID] = 0
	a.recordMetrics(n)
	if since, was := m.offline[n.ID]; was {
		delete(m.offline, n.ID)
		a.event(EventServer, "🟢 Сервер %s снова на связи (был недоступен %s)", n.Name, ago(time.Since(since)))
	}
	// Remembered in the settings so that a panel restart does not repeat it.
	if h := n.Status.Hardening; h != nil {
		key := fmt.Sprintf("node:%d:reboot_alerted", n.ID)
		was := a.Store.Setting(key, "0") == "1"
		if h.RebootRequired && !was {
			a.event(EventSecurity, "ℹ️ На сервере %s установлены обновления, которым нужна перезагрузка", n.Name)
		}
		if h.RebootRequired != was {
			_ = a.Store.SetSetting(key, map[bool]string{true: "1", false: "0"}[h.RebootRequired])
		}
	}
	if n.Local && a.entrySettings().WDTTEnabled && n.Status.WDTTInstalled {
		down := n.Status.WDTTActive != "active"
		if down != m.wdttDown {
			m.wdttDown = down
			if down {
				a.event(EventWDTT, "🔴 Сервер WDTT остановлен (%s)", n.Status.WDTTActive)
			} else {
				a.event(EventWDTT, "🟢 Сервер WDTT снова работает")
			}
		}
	}
}

// checkChain runs the end-to-end chain check every few minutes.
func (a *App) checkChain(ctx context.Context) {
	a.mon.mu.Lock()
	a.mon.round++
	due := a.mon.round%5 == 1
	a.mon.mu.Unlock()
	if !due || len(a.chainIDs()) < 2 {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	err := a.probe(cctx, &jobRun{a: a})
	cancel()
	var pr ProbeRecord
	if err == nil && json.Unmarshal([]byte(a.Store.Setting("last_probe", "")), &pr) == nil && pr.OK {
		a.recordPing(pr.TCPms)
	}
	a.mon.mu.Lock()
	defer a.mon.mu.Unlock()
	if (err != nil) == a.mon.chainDown {
		return
	}
	a.mon.chainDown = err != nil
	if err != nil {
		a.event(EventChain, "🔴 Цепочка не работает: %s", short(err.Error(), 200))
	} else {
		a.event(EventChain, "🟢 Цепочка снова работает")
	}
}

// loginSeen records a successful login and reports a new address.
func (a *App) loginSeen(user, ip string) {
	known := strings.Split(a.Store.Setting("login_ips", ""), ",")
	if slices.Contains(known, ip) {
		return
	}
	if a.Store.Setting("login_ips", "") != "" {
		a.event(EventSecurity, "🔐 Вход в панель (%s) с нового адреса %s", user, ip)
	}
	known = append([]string{ip}, known...)
	if len(known) > 20 {
		known = known[:20]
	}
	_ = a.Store.SetSetting("login_ips", strings.Trim(strings.Join(known, ","), ","))
}

// ---- bot settings -------------------------------------------------------------

type botChat struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Added string `json:"added"`
}

type botAlerts struct {
	Servers  bool `json:"servers"`
	Chain    bool `json:"chain"`
	WDTT     bool `json:"wdtt"`
	Security bool `json:"security"`
	Jobs     bool `json:"jobs"`
}

func (a *App) botNodeID() int64 {
	id, _ := strconv.ParseInt(a.Store.Setting("bot_node", "0"), 10, 64)
	return id
}

func (a *App) botChats() []botChat {
	var c []botChat
	_ = json.Unmarshal([]byte(a.Store.Setting("bot_chats", "[]")), &c)
	return c
}

func (a *App) setBotChats(c []botChat) {
	b, _ := json.Marshal(c)
	_ = a.Store.SetSetting("bot_chats", string(b))
}

func (a *App) botAlerts() botAlerts {
	al := botAlerts{true, true, true, true, true}
	_ = json.Unmarshal([]byte(a.Store.Setting("bot_alerts", "{}")), &al)
	return al
}

func (al botAlerts) wants(kind string) bool {
	switch kind {
	case EventServer:
		return al.Servers
	case EventChain:
		return al.Chain
	case EventWDTT:
		return al.WDTT
	case EventSecurity:
		return al.Security
	case EventJobs:
		return al.Jobs
	case EventUpdate:
		return al.Security
	}
	return true
}

// botSpec is the bot's part of the plan for the node it runs on.
func (a *App) botSpec(n Node, entry Node) (*spec.BotSpec, error) {
	tok, err := a.Store.Secret("bot_token")
	if err != nil {
		return nil, fmt.Errorf("не задан токен Telegram-бота")
	}
	key, err := a.secret("bot_api_token", func() (string, error) { return randomHex(32) })
	if err != nil {
		return nil, err
	}
	host := "127.0.0.1"
	if !n.Local {
		if entry.MeshIP == "" || n.MeshIP == "" {
			return nil, fmt.Errorf("Telegram-бот на %s: сервер панели и %s должны быть в Mesh", n.Name, n.Name)
		}
		host = entry.MeshIP
	}
	return &spec.BotSpec{Token: tok, PanelURL: fmt.Sprintf("https://%s:%d", host, a.PanelPort), PanelFingerprint: a.CertFingerprint(), APIToken: key}, nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// botHealth is what the bot last reported.
type botHealth struct {
	mu       sync.Mutex
	seen     time.Time
	telegram string
}

// pairing codes: one at a time, 10 minutes, a few wrong tries.
type pairing struct {
	mu      sync.Mutex
	code    string
	expires time.Time
	tries   int
}

const pairAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

func (a *App) newPairCode() (string, time.Time) {
	b := make([]byte, 8)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(pairAlphabet))))
		b[i] = pairAlphabet[n.Int64()]
	}
	p := &a.pair
	p.mu.Lock()
	defer p.mu.Unlock()
	p.code, p.expires, p.tries = string(b), time.Now().Add(10*time.Minute), 0
	return p.code, p.expires
}

func (a *App) usePairCode(code string) bool {
	p := &a.pair
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.code == "" || time.Now().After(p.expires) {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(strings.ToUpper(strings.TrimSpace(code))), []byte(p.code)) == 1 {
		p.code = ""
		return true
	}
	if p.tries++; p.tries >= 5 {
		p.code = ""
	}
	return false
}

func (a *App) getBot(w http.ResponseWriter, r *http.Request, s auth.Session) {
	_, err := a.Store.Secret("bot_token")
	out := map[string]any{"node_id": a.botNodeID(), "has_token": err == nil, "chats": a.botChats(), "alerts": a.botAlerts()}
	a.botHealth.mu.Lock()
	if !a.botHealth.seen.IsZero() {
		out["bot_seen"], out["bot_telegram"] = a.botHealth.seen.UTC().Format(time.RFC3339), a.botHealth.telegram
	}
	a.botHealth.mu.Unlock()
	a.pair.mu.Lock()
	if a.pair.code != "" && time.Now().Before(a.pair.expires) {
		out["pair_code"], out["pair_expires"] = a.pair.code, a.pair.expires.UTC().Format(time.RFC3339)
	}
	a.pair.mu.Unlock()
	writeJSON(w, 200, out)
}

func (a *App) putBot(w http.ResponseWriter, r *http.Request, s auth.Session) {
	var body struct {
		NodeID int64      `json:"node_id"`
		Token  string     `json:"token"`
		Alerts *botAlerts `json:"alerts"`
	}
	if !decode(w, r, &body) {
		return
	}
	if t := strings.TrimSpace(body.Token); t != "" {
		if !spec.ValidBotToken(t) {
			apiError(w, 400, "токен не похож на токен Telegram-бота (вида 123456789:AA…), получите его у @BotFather")
			return
		}
		_ = a.Store.PutSecret("bot_token", t)
	}
	if body.Alerts != nil {
		b, _ := json.Marshal(body.Alerts)
		_ = a.Store.SetSetting("bot_alerts", string(b))
	}
	if body.NodeID != 0 {
		n, err := a.node(body.NodeID)
		if err != nil {
			apiError(w, 400, err.Error())
			return
		}
		if _, err := a.Store.Secret("bot_token"); err != nil {
			apiError(w, 400, "укажите токен бота")
			return
		}
		entry, _ := a.localNode()
		if !n.Local && (n.CFNodeID == "" || entry.MeshIP == "") {
			apiError(w, 400, "бот может работать на сервере панели или на сервере, подключённом к Mesh")
			return
		}
	}
	old := a.botNodeID()
	_ = a.Store.SetSetting("bot_node", strconv.FormatInt(body.NodeID, 10))
	a.audit(r, s, "bot.update", fmt.Sprintf("node=%d", body.NodeID))
	if old == body.NodeID && body.Token == "" {
		writeJSON(w, 200, map[string]bool{"ok": true})
		return
	}
	if _, err := a.Plan(); err != nil {
		apiError(w, 409, "настройки сохранены, но применить нельзя: "+err.Error())
		return
	}
	id, err := a.Enqueue("apply.all", 0, "Применение настроек Telegram-бота", s.Username, nil)
	if err != nil {
		apiError(w, 500, err.Error())
		return
	}
	writeJSON(w, 202, map[string]int64{"job_id": id})
}

func (a *App) botCode(w http.ResponseWriter, r *http.Request, s auth.Session) {
	code, exp := a.newPairCode()
	writeJSON(w, 200, map[string]string{"pair_code": code, "pair_expires": exp.UTC().Format(time.RFC3339)})
}

func (a *App) deleteBotChat(w http.ResponseWriter, r *http.Request, s auth.Session) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	chats := slices.DeleteFunc(a.botChats(), func(c botChat) bool { return c.ID == id })
	a.setBotChats(chats)
	a.audit(r, s, "bot.chat.remove", strconv.FormatInt(id, 10))
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *App) botTest(w http.ResponseWriter, r *http.Request, s auth.Session) {
	a.event(EventTest, "👋 Проверка связи: панель WDTT Router на связи")
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *App) listEvents(w http.ResponseWriter, r *http.Request, s auth.Session) {
	writeJSON(w, 200, a.recentEvents(50))
}

// ---- the bot's API ----------------------------------------------------------

// botAuthed admits the bot by its key. The key only reads events and the
// status summary and pairs chats with a code shown in the panel.
func (a *App) botAuthed(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key, err := a.Store.Secret("bot_api_token")
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if err != nil || a.botNodeID() == 0 || !ok || subtle.ConstantTimeCompare([]byte(got), []byte(key)) != 1 {
			apiError(w, 401, "unauthorized")
			return
		}
		a.botHealth.mu.Lock()
		a.botHealth.seen, a.botHealth.telegram = time.Now(), short(r.Header.Get("X-Bot-Telegram"), 200)
		a.botHealth.mu.Unlock()
		h(w, r)
	}
}

func (a *App) botSync(w http.ResponseWriter, r *http.Request) {
	after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	var last int64
	_ = a.Store.DB.QueryRow(`SELECT COALESCE(MAX(id),0) FROM events`).Scan(&last)
	al := a.botAlerts()
	events := []Event{}
	rows, err := a.Store.DB.Query(`SELECT id,at,kind,text FROM events WHERE id > ? ORDER BY id LIMIT 50`, after)
	if err == nil {
		for rows.Next() {
			var e Event
			if rows.Scan(&e.ID, &e.At, &e.Kind, &e.Text) == nil && al.wants(e.Kind) {
				events = append(events, e)
			}
		}
		rows.Close()
	}
	chats := []int64{}
	for _, c := range a.botChats() {
		chats = append(chats, c.ID)
	}
	type ev struct {
		ID   int64  `json:"id"`
		Text string `json:"text"`
	}
	out := make([]ev, 0, len(events))
	for _, e := range events {
		out = append(out, ev{e.ID, e.Text})
	}
	if len(events) == 50 {
		last = events[len(events)-1].ID
	}
	writeJSON(w, 200, map[string]any{"chats": chats, "events": out, "last": last})
}

func (a *App) botPair(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ChatID int64  `json:"chat_id"`
		Name   string `json:"name"`
		Code   string `json:"code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil || body.ChatID == 0 {
		writeJSON(w, 200, map[string]any{"ok": false, "error": "некорректный запрос"})
		return
	}
	if !a.usePairCode(body.Code) {
		writeJSON(w, 200, map[string]any{"ok": false, "error": "код неверный или устарел — получите новый в панели"})
		return
	}
	chats := slices.DeleteFunc(a.botChats(), func(c botChat) bool { return c.ID == body.ChatID })
	chats = append(chats, botChat{ID: body.ChatID, Name: short(body.Name, 64), Added: now()})
	a.setBotChats(chats)
	a.Store.Audit("telegram", "bot.chat.add", fmt.Sprintf("%d %s", body.ChatID, short(body.Name, 64)), "")
	writeJSON(w, 200, map[string]any{"ok": true})
}

// botStatus is the /status summary: states and counts only, no addresses,
// keys or settings.
func (a *App) botStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]string{"text": a.statusSummary()})
}

func (a *App) statusSummary() string {
	var b strings.Builder
	nodes, _ := a.nodes()
	roles := map[string]string{spec.RoleEntry: "вход", spec.RoleRelay: "промежуточный", spec.RoleExit: "выход", spec.RoleIdle: "вне цепочки"}
	plans, _ := a.Plan()
	b.WriteString("Серверы\n")
	for _, n := range nodes {
		role := ""
		if p := plans[n.ID]; p != nil {
			role = " · " + roles[p.Role]
		}
		seen, _ := time.Parse(time.RFC3339, n.LastSeen)
		if n.LastError != "" || seen.IsZero() || time.Since(seen) > 3*time.Minute {
			since := "нет данных"
			if !seen.IsZero() {
				since = "нет связи " + ago(time.Since(seen))
			}
			fmt.Fprintf(&b, "🔴 %s%s — %s\n", n.Name, role, since)
			continue
		}
		st := n.Status
		mem := 0
		if st.MemTotalMB > 0 {
			mem = int(100 - 100*st.MemAvailMB/st.MemTotalMB)
		}
		fmt.Fprintf(&b, "🟢 %s%s — работает %s, нагрузка %.2f, память %d%%\n", n.Name, role, ago(time.Duration(st.UptimeSec)*time.Second), st.Load1, mem)
	}
	var pr ProbeRecord
	if json.Unmarshal([]byte(a.Store.Setting("last_probe", "")), &pr) == nil && pr.At != "" {
		at, _ := time.Parse(time.RFC3339, pr.At)
		if pr.OK && pr.Match {
			fmt.Fprintf(&b, "\nЦепочка: 🟢 работает (TCP %d мс), проверена %s назад\n", pr.TCPms, ago(time.Since(at)))
		} else {
			fmt.Fprintf(&b, "\nЦепочка: 🔴 не работает, проверена %s назад\n", ago(time.Since(at)))
		}
	}
	if a.entrySettings().WDTTEnabled {
		for _, n := range nodes {
			if !n.Local {
				continue
			}
			if rt := n.Status.WDTT; rt != nil && n.Status.WDTTActive == "active" {
				online := 0
				for _, k := range rt.Keys {
					if k.Sessions > 0 {
						online++
					}
				}
				fmt.Fprintf(&b, "WDTT: 🟢 работает, сессий %d, ключей в сети %d\n", rt.Sessions, online)
			} else {
				fmt.Fprintf(&b, "WDTT: 🔴 %s\n", n.Status.WDTTActive)
			}
		}
	}
	return strings.TrimSpace(b.String())
}

func short(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

func ago(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d с", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d мин", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d ч", int(d.Hours()))
	}
	return fmt.Sprintf("%d дн", int(d.Hours()/24))
}
