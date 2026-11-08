package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Jetvac/wdtt-router/internal/agent"
	"github.com/Jetvac/wdtt-router/internal/auth"
	"github.com/Jetvac/wdtt-router/internal/cfapi"
	"github.com/Jetvac/wdtt-router/internal/spec"
)

func (a *App) routes() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("POST /api/login", a.login)
	m.HandleFunc("POST /api/logout", a.authed(a.logout))
	m.HandleFunc("GET /api/me", a.authed(a.me))
	m.HandleFunc("GET /api/overview", a.authed(a.overview))

	m.HandleFunc("GET /api/nodes", a.authed(a.listNodes))
	m.HandleFunc("POST /api/nodes", a.authed(a.addNode))
	m.HandleFunc("PATCH /api/nodes/{id}", a.authed(a.patchNode))
	m.HandleFunc("POST /api/nodes/{id}/{action}", a.authed(a.nodeAction))
	m.HandleFunc("GET /api/nodes/{id}/plan", a.authed(a.nodePlan))

	m.HandleFunc("GET /api/chain", a.authed(a.getChain))
	m.HandleFunc("PUT /api/chain", a.authed(a.putChain))
	m.HandleFunc("POST /api/apply", a.authed(a.applyAll))
	m.HandleFunc("POST /api/probe", a.authed(a.queueProbe))

	m.HandleFunc("GET /api/services", a.authed(a.getServices))
	m.HandleFunc("PUT /api/services/wdtt", a.authed(a.putWDTT))
	m.HandleFunc("PUT /api/services/xui", a.authed(a.putXUI))
	m.HandleFunc("GET /api/services/{name}/secret", a.authed(a.serviceSecret))
	m.HandleFunc("POST /api/services/xui/reset", a.authed(a.resetXUI))
	m.HandleFunc("GET /api/wdtt/keys", a.authed(a.listWDTTKeys))
	m.HandleFunc("POST /api/wdtt/keys", a.authed(a.createWDTTKey))
	m.HandleFunc("PATCH /api/wdtt/keys/{id}", a.authed(a.patchWDTTKey))
	m.HandleFunc("DELETE /api/wdtt/keys/{id}", a.authed(a.deleteWDTTKey))
	m.HandleFunc("GET /api/wdtt/keys/{id}/link", a.authed(a.wdttLink))

	m.HandleFunc("GET /api/cloudflare", a.authed(a.getCloudflare))
	m.HandleFunc("PUT /api/cloudflare", a.authed(a.putCloudflare))
	m.HandleFunc("GET /api/cloudflare/preflight", a.authed(a.cfPreflight))
	m.HandleFunc("POST /api/cloudflare/fix", a.authed(a.cfFix))

	m.HandleFunc("GET /api/settings", a.authed(a.getSettings))
	m.HandleFunc("PUT /api/settings/panel", a.authed(a.putPanel))
	m.HandleFunc("POST /api/account/password", a.authed(a.changePassword))

	m.HandleFunc("GET /api/jobs", a.authed(a.listJobs))
	m.HandleFunc("GET /api/jobs/{id}", a.authed(a.getJob))
	m.HandleFunc("GET /api/audit", a.authed(a.listAudit))
	m.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) { apiError(w, 404, "не найдено") })
	m.Handle("/", a.static())
	return securityHeaders(m)
}

func (a *App) audit(r *http.Request, s auth.Session, action, detail string) {
	a.Store.Audit(s.Username, action, detail, clientIP(r))
}

// ---- session ---------------------------------------------------------------

func (a *App) login(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !a.loginAllowed(ip) {
		apiError(w, http.StatusTooManyRequests, "слишком много попыток, подождите 15 минут")
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decode(w, r, &body) {
		return
	}
	id, ok := auth.Authenticate(a.Store.DB, body.Username, body.Password)
	if !ok {
		a.loginFailed(ip)
		a.Store.Audit(body.Username, "login.failed", "", ip)
		time.Sleep(500 * time.Millisecond)
		apiError(w, http.StatusUnauthorized, "неверный логин или пароль")
		return
	}
	token, csrf, err := auth.NewSession(a.Store.DB, id)
	if err != nil {
		apiError(w, 500, "не удалось создать сессию")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "wdttr_session", Value: token, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: 12 * 3600})
	a.Store.Audit(body.Username, "login", "", ip)
	writeJSON(w, 200, map[string]string{"username": body.Username, "csrf": csrf})
}

func (a *App) logout(w http.ResponseWriter, r *http.Request, s auth.Session) {
	if c, err := r.Cookie("wdttr_session"); err == nil {
		_ = auth.Revoke(a.Store.DB, c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: "wdttr_session", Value: "", Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *App) me(w http.ResponseWriter, r *http.Request, s auth.Session) {
	writeJSON(w, 200, map[string]any{"username": s.Username, "csrf": s.CSRF, "version": agent.Version})
}

func (a *App) changePassword(w http.ResponseWriter, r *http.Request, s auth.Session) {
	var body struct {
		Old string `json:"old"`
		New string `json:"new"`
	}
	if !decode(w, r, &body) {
		return
	}
	if len(body.New) < 16 {
		apiError(w, 400, "новый пароль должен быть не короче 16 символов")
		return
	}
	if err := auth.ChangePassword(a.Store.DB, s.UserID, body.Old, body.New); err != nil {
		apiError(w, 400, "текущий пароль неверен")
		return
	}
	a.audit(r, s, "password.change", "")
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// ---- overview --------------------------------------------------------------

type nodeView struct {
	Node
	Role        string `json:"role"`
	InChain     bool   `json:"in_chain"`
	Position    int    `json:"position"`
	PlanError   string `json:"plan_error,omitempty"`
	OutOfSync   bool   `json:"out_of_sync"`
	HasPassword bool   `json:"-"`
}

func (a *App) nodeViews() ([]nodeView, string) {
	nodes, _ := a.nodes()
	plans, planErr := a.Plan()
	chain := a.chainIDs()
	out := []nodeView{}
	for _, n := range nodes {
		v := nodeView{Node: n, Role: spec.RoleIdle, Position: -1}
		if i := slices.Index(chain, n.ID); i >= 0 {
			v.InChain, v.Position = true, i
		}
		if p, ok := plans[n.ID]; ok {
			v.Role = p.Role
			v.OutOfSync = n.Status.SpecHash != planHash(p)
		} else if n.Local {
			v.Role = spec.RoleEntry
		}
		out = append(out, v)
	}
	msg := ""
	if planErr != nil {
		msg = planErr.Error()
	}
	return out, msg
}

func (a *App) overview(w http.ResponseWriter, r *http.Request, s auth.Session) {
	nodes, planErr := a.nodeViews()
	var probe *ProbeRecord
	if p := a.Store.Setting("last_probe", ""); p != "" {
		probe = &ProbeRecord{}
		_ = json.Unmarshal([]byte(p), probe)
	}
	jobs, _ := a.jobs(8)
	var running int
	_ = a.Store.DB.QueryRow(`SELECT COUNT(*) FROM jobs WHERE status IN ('queued','running')`).Scan(&running)
	writeJSON(w, 200, map[string]any{
		"nodes": nodes, "chain": a.chainIDs(), "plan_error": planErr, "probe": probe,
		"services": a.entrySettings(), "cloudflare": a.cfConfigured(), "jobs": jobs, "active_jobs": running,
		"version": agent.Version,
	})
}

// ---- nodes -----------------------------------------------------------------

func pathID(r *http.Request) (int64, error) {
	return strconv.ParseInt(r.PathValue("id"), 10, 64)
}

func (a *App) listNodes(w http.ResponseWriter, r *http.Request, s auth.Session) {
	nodes, planErr := a.nodeViews()
	writeJSON(w, 200, map[string]any{"nodes": nodes, "plan_error": planErr})
}

var reNodeName = regexp.MustCompile(`^[\p{L}\p{N} ._-]{1,40}$`)

func validHost(h string) bool {
	if ip := net.ParseIP(h); ip != nil {
		return !ip.IsLoopback() && !ip.IsUnspecified()
	}
	return regexp.MustCompile(`^[A-Za-z0-9.-]{1,253}$`).MatchString(h) && strings.Contains(h, ".")
}

func (a *App) addNode(w http.ResponseWriter, r *http.Request, s auth.Session) {
	var in addNodeInput
	if !decode(w, r, &in) {
		return
	}
	in.Name, in.Host = strings.TrimSpace(in.Name), strings.TrimSpace(in.Host)
	if in.Port == 0 {
		in.Port = 22
	}
	if !reNodeName.MatchString(in.Name) {
		apiError(w, 400, "имя: 1–40 букв, цифр, пробелов, точек, дефисов")
		return
	}
	if !validHost(in.Host) || in.Port < 1 || in.Port > 65535 {
		apiError(w, 400, "некорректный адрес или порт SSH")
		return
	}
	if in.Password == "" || len(in.Password) > 256 {
		apiError(w, 400, "введите пароль root")
		return
	}
	var dup int
	_ = a.Store.DB.QueryRow(`SELECT COUNT(*) FROM nodes WHERE name=? OR host=?`, in.Name, in.Host).Scan(&dup)
	if dup > 0 {
		apiError(w, 409, "сервер с таким именем или адресом уже добавлен")
		return
	}
	id, err := a.Enqueue("node.add", 0, "Добавление сервера "+in.Name, s.Username, in)
	if err != nil {
		apiError(w, 500, err.Error())
		return
	}
	a.audit(r, s, "node.add", in.Host)
	writeJSON(w, 202, map[string]int64{"job_id": id})
}

func (a *App) patchNode(w http.ResponseWriter, r *http.Request, s auth.Session) {
	id, err := pathID(r)
	if err != nil {
		apiError(w, 400, "bad id")
		return
	}
	n, err := a.node(id)
	if err != nil {
		apiError(w, 404, err.Error())
		return
	}
	var body struct {
		Name      *string   `json:"name"`
		SSHPublic *bool     `json:"ssh_public"`
		SSHAllow  *[]string `json:"ssh_allow"`
		AllowPing *bool     `json:"allow_ping"`
		Firewall  *bool     `json:"firewall"`
	}
	if !decode(w, r, &body) {
		return
	}
	if body.Name != nil {
		if !reNodeName.MatchString(strings.TrimSpace(*body.Name)) {
			apiError(w, 400, "некорректное имя")
			return
		}
		n.Name = strings.TrimSpace(*body.Name)
	}
	if body.SSHAllow != nil {
		clean := []string{}
		for _, c := range *body.SSHAllow {
			if c = strings.TrimSpace(c); c == "" {
				continue
			}
			if !spec.ValidCIDR(c) {
				apiError(w, 400, "некорректный адрес: "+c)
				return
			}
			clean = append(clean, c)
		}
		if n.Local && len(clean) > 0 && !allowedBy(clientIP(r), clean) {
			apiError(w, 400, "ваш текущий адрес "+clientIP(r)+" не входит в список — вы потеряете доступ по SSH")
			return
		}
		n.SSHAllow = clean
	}
	if body.SSHPublic != nil {
		if !*body.SSHPublic && n.CFNodeID == "" {
			apiError(w, 400, "закрыть публичный SSH можно только после подключения сервера к Mesh")
			return
		}
		n.SSHPublic = *body.SSHPublic
	}
	if body.AllowPing != nil {
		n.AllowPing = *body.AllowPing
	}
	if body.Firewall != nil {
		n.Firewall = *body.Firewall
	}
	_, err = a.Store.DB.Exec(`UPDATE nodes SET name=?, ssh_public=?, ssh_allow=?, allow_ping=?, firewall=? WHERE id=?`, n.Name, b2i(n.SSHPublic), strings.Join(n.SSHAllow, ","), b2i(n.AllowPing), b2i(n.Firewall), n.ID)
	if err != nil {
		apiError(w, 409, "имя уже занято")
		return
	}
	a.audit(r, s, "node.update", n.Name)
	writeJSON(w, 200, n)
}

func allowedBy(ip string, list []string) bool {
	addr := net.ParseIP(ip)
	for _, c := range list {
		if _, n, err := net.ParseCIDR(c); err == nil && n.Contains(addr) {
			return true
		}
		if x := net.ParseIP(c); x != nil && x.Equal(addr) {
			return true
		}
	}
	return false
}

func (a *App) nodeAction(w http.ResponseWriter, r *http.Request, s auth.Session) {
	id, err := pathID(r)
	if err != nil {
		apiError(w, 400, "bad id")
		return
	}
	n, err := a.node(id)
	if err != nil {
		apiError(w, 404, err.Error())
		return
	}
	var kind, title string
	var input any
	switch r.PathValue("action") {
	case "enroll":
		if !a.cfConfigured() {
			apiError(w, 400, "сначала настройте Cloudflare")
			return
		}
		kind, title = "node.enroll", "Подключение к Mesh: "+n.Name
	case "leave":
		kind, title = "node.leave", "Отключение от Mesh: "+n.Name
	case "apply":
		kind, title = "node.apply", "Применение настроек: "+n.Name
	case "refresh":
		ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
		defer cancel()
		n, err := a.refreshStatus(ctx, n)
		if err != nil {
			apiError(w, 502, err.Error())
			return
		}
		writeJSON(w, 200, n)
		return
	case "remove":
		var body removeInput
		if r.ContentLength > 0 && !decode(w, r, &body) {
			return
		}
		kind, title, input = "node.remove", "Удаление сервера "+n.Name, body
	default:
		apiError(w, 404, "неизвестное действие")
		return
	}
	jid, err := a.Enqueue(kind, n.ID, title, s.Username, input)
	if err != nil {
		apiError(w, 500, err.Error())
		return
	}
	a.audit(r, s, kind, n.Name)
	writeJSON(w, 202, map[string]int64{"job_id": jid})
}

// nodePlan shows the planned spec without secrets, for transparency.
func (a *App) nodePlan(w http.ResponseWriter, r *http.Request, s auth.Session) {
	id, _ := pathID(r)
	plans, err := a.Plan()
	if err != nil {
		apiError(w, 409, err.Error())
		return
	}
	p, ok := plans[id]
	if !ok {
		apiError(w, 404, "нет плана")
		return
	}
	c := *p
	c.Mesh.Token = redacted(c.Mesh.Token)
	if c.Hop != nil {
		h := *c.Hop
		h.Decryption, h.UUID = redacted(h.Decryption), redacted(h.UUID)
		c.Hop = &h
	}
	if c.Entry != nil {
		e := *c.Entry
		e.SocksPass = redacted(e.SocksPass)
		e.WDTT.Password = redacted(e.WDTT.Password)
		e.WDTT.Keys = slices.Clone(e.WDTT.Keys)
		for i := range e.WDTT.Keys {
			e.WDTT.Keys[i].Password = redacted(e.WDTT.Keys[i].Password)
		}
		e.Chain = slices.Clone(e.Chain)
		for i := range e.Chain {
			e.Chain[i].UUID, e.Chain[i].Encryption = redacted(e.Chain[i].UUID), redacted(e.Chain[i].Encryption)
		}
		c.Entry = &e
	}
	writeJSON(w, 200, c)
}

func redacted(s string) string {
	if s == "" {
		return ""
	}
	return "•••"
}

// ---- chain -----------------------------------------------------------------

func (a *App) getChain(w http.ResponseWriter, r *http.Request, s auth.Session) {
	writeJSON(w, 200, map[string]any{"chain": a.chainIDs()})
}

func (a *App) putChain(w http.ResponseWriter, r *http.Request, s auth.Session) {
	var body struct {
		Chain []int64 `json:"chain"`
	}
	if !decode(w, r, &body) {
		return
	}
	nodes, _ := a.nodes()
	known := map[int64]Node{}
	for _, n := range nodes {
		known[n.ID] = n
	}
	seen := map[int64]bool{}
	for i, id := range body.Chain {
		n, ok := known[id]
		if !ok || seen[id] {
			apiError(w, 400, "сервер указан дважды или не существует")
			return
		}
		seen[id] = true
		if i == 0 && !n.Local {
			apiError(w, 400, "цепочка начинается с сервера панели")
			return
		}
		if i > 0 && n.Local {
			apiError(w, 400, "сервер панели может быть только первым")
			return
		}
		if n.CFNodeID == "" || n.MeshIP == "" {
			apiError(w, 400, n.Name+" не подключён к Mesh")
			return
		}
	}
	if len(body.Chain) == 1 {
		body.Chain = nil
	}
	if body.Chain == nil {
		body.Chain = []int64{}
	}
	b, _ := json.Marshal(body.Chain)
	if err := a.Store.SetSetting("chain", string(b)); err != nil {
		apiError(w, 500, err.Error())
		return
	}
	a.audit(r, s, "chain.update", string(b))
	writeJSON(w, 200, map[string]any{"chain": body.Chain})
}

func (a *App) applyAll(w http.ResponseWriter, r *http.Request, s auth.Session) {
	if _, err := a.Plan(); err != nil {
		apiError(w, 409, err.Error())
		return
	}
	id, err := a.Enqueue("apply.all", 0, "Применение конфигурации ко всем серверам", s.Username, nil)
	if err != nil {
		apiError(w, 500, err.Error())
		return
	}
	a.audit(r, s, "apply.all", "")
	writeJSON(w, 202, map[string]int64{"job_id": id})
}

func (a *App) queueProbe(w http.ResponseWriter, r *http.Request, s auth.Session) {
	id, err := a.Enqueue("chain.probe", 0, "Проверка цепочки", s.Username, nil)
	if err != nil {
		apiError(w, 500, err.Error())
		return
	}
	writeJSON(w, 202, map[string]int64{"job_id": id})
}

// ---- services --------------------------------------------------------------

func (a *App) getServices(w http.ResponseWriter, r *http.Request, s auth.Session) {
	n, _ := a.localNode()
	_, hasXUI := a.Store.Secret("xui:XUI_PASSWORD")
	writeJSON(w, 200, map[string]any{
		"settings": a.entrySettings(), "status": n.Status, "public_host": n.Host,
		"xui_credentials": hasXUI == nil,
	})
}

func (a *App) putWDTT(w http.ResponseWriter, r *http.Request, s auth.Session) {
	var body struct {
		Enabled  bool   `json:"enabled"`
		DTLSPort int    `json:"dtls_port"`
		DNS      string `json:"dns"`
		Rotate   bool   `json:"rotate_password"`
		// Password sets a chosen owner password, e.g. the one existing
		// clients of an earlier WDTT server already use.
		Password *string `json:"password"`
		VKHash   *string `json:"vk_hash"`
		MTU      int     `json:"mtu"`
	}
	if !decode(w, r, &body) {
		return
	}
	if body.DTLSPort == 0 {
		body.DTLSPort = 56000
	}
	if body.MTU == 0 {
		body.MTU = 1280
	}
	if body.MTU < 1200 || body.MTU > 1340 {
		apiError(w, 400, "MTU туннеля: от 1200 до 1340")
		return
	}
	if body.DTLSPort < 1024 || body.DTLSPort > 65534 || body.DTLSPort == a.PanelPort {
		apiError(w, 400, "порт DTLS должен быть в диапазоне 1024–65534 и не совпадать с портом панели")
		return
	}
	if body.DNS == "" {
		body.DNS = "1.1.1.1"
	}
	for _, d := range strings.Split(body.DNS, ",") {
		if net.ParseIP(strings.TrimSpace(d)) == nil {
			apiError(w, 400, "DNS: укажите IP-адреса через запятую")
			return
		}
	}
	var hash string
	if body.VKHash != nil {
		h, err := normalizeVKHashes(*body.VKHash)
		if err != nil {
			apiError(w, 400, err.Error())
			return
		}
		hash = h
	}
	if body.Password != nil && *body.Password != "" {
		if !rePassword.MatchString(*body.Password) {
			apiError(w, 400, "пароль владельца: 16–128 символов A–Z, a–z, 0–9, точка, дефис, подчёркивание")
			return
		}
		keys, _ := a.Store.WDTTKeys()
		for _, k := range keys {
			if k.Password == *body.Password {
				apiError(w, 400, "этот пароль уже выдан как ключ доступа")
				return
			}
		}
		_ = a.Store.PutSecret("wdtt_password", *body.Password)
	}
	if body.VKHash != nil {
		_ = a.Store.SetSetting("wdtt_vk_hash", hash)
	}
	_ = a.Store.SetSetting("wdtt_enabled", map[bool]string{true: "1", false: "0"}[body.Enabled])
	_ = a.Store.SetSetting("wdtt_dtls_port", strconv.Itoa(body.DTLSPort))
	_ = a.Store.SetSetting("wdtt_wg_port", strconv.Itoa(body.DTLSPort+1))
	_ = a.Store.SetSetting("wdtt_dns", strings.ReplaceAll(body.DNS, " ", ""))
	_ = a.Store.SetSetting("wdtt_mtu", strconv.Itoa(body.MTU))
	if body.Rotate {
		_ = a.Store.PutSecret("wdtt_password", spec.NewPassword(20))
	}
	a.queueEntry(w, r, s, "wdtt.update", fmt.Sprintf("enabled=%v port=%d", body.Enabled, body.DTLSPort))
}

func (a *App) putXUI(w http.ResponseWriter, r *http.Request, s auth.Session) {
	var body struct {
		Enabled bool `json:"enabled"`
		Route   bool `json:"route_via_chain"`
	}
	if !decode(w, r, &body) {
		return
	}
	_ = a.Store.SetSetting("xui_enabled", map[bool]string{true: "1", false: "0"}[body.Enabled])
	_ = a.Store.SetSetting("xui_route", map[bool]string{true: "1", false: "0"}[body.Route])
	if !body.Enabled {
		for _, k := range []string{"XUI_USERNAME", "XUI_PASSWORD", "XUI_PANEL_PORT", "XUI_WEB_BASE_PATH"} {
			_ = a.Store.DeleteSecret("xui:" + k)
		}
	}
	a.queueEntry(w, r, s, "xui.update", fmt.Sprintf("enabled=%v route=%v", body.Enabled, body.Route))
}

func (a *App) queueEntry(w http.ResponseWriter, r *http.Request, s auth.Session, action, detail string) {
	n, err := a.localNode()
	if err != nil {
		apiError(w, 500, err.Error())
		return
	}
	if _, err := a.Plan(); err != nil {
		apiError(w, 409, "настройки сохранены, но применить нельзя: "+err.Error())
		return
	}
	id, err := a.Enqueue("node.apply", n.ID, "Применение настроек: "+n.Name, s.Username, nil)
	if err != nil {
		apiError(w, 500, err.Error())
		return
	}
	a.audit(r, s, action, detail)
	writeJSON(w, 202, map[string]int64{"job_id": id})
}

func (a *App) serviceSecret(w http.ResponseWriter, r *http.Request, s auth.Session) {
	out := map[string]string{}
	switch r.PathValue("name") {
	case "wdtt":
		p, err := a.Store.Secret("wdtt_password")
		if err != nil {
			apiError(w, 404, "WDTT ещё не настроен")
			return
		}
		n, _ := a.localNode()
		es := a.entrySettings()
		out = map[string]string{"password": p, "host": n.Host, "port": strconv.Itoa(es.WDTTDTLSPort)}
	case "xui":
		for _, k := range []string{"XUI_USERNAME", "XUI_PASSWORD", "XUI_PANEL_PORT", "XUI_WEB_BASE_PATH"} {
			if v, err := a.Store.Secret("xui:" + k); err == nil {
				out[k] = v
			}
		}
		if out["XUI_PASSWORD"] == "" {
			apiError(w, 404, "учётные данные 3x-ui неизвестны — сбросьте их")
			return
		}
		n, _ := a.localNode()
		out["ssh_tunnel"] = fmt.Sprintf("ssh -N -L 127.0.0.1:%s:127.0.0.1:%s root@%s", out["XUI_PANEL_PORT"], out["XUI_PANEL_PORT"], n.Host)
		out["url"] = fmt.Sprintf("http://127.0.0.1:%s/%s/", out["XUI_PANEL_PORT"], strings.Trim(out["XUI_WEB_BASE_PATH"], "/"))
	default:
		apiError(w, 404, "неизвестный сервис")
		return
	}
	a.audit(r, s, "secret.view", r.PathValue("name"))
	writeJSON(w, 200, out)
}

func (a *App) resetXUI(w http.ResponseWriter, r *http.Request, s auth.Session) {
	id, err := a.Enqueue("xui.reset", 0, "Сброс учётных данных 3x-ui", s.Username, nil)
	if err != nil {
		apiError(w, 500, err.Error())
		return
	}
	a.audit(r, s, "xui.reset", "")
	writeJSON(w, 202, map[string]int64{"job_id": id})
}

// ---- Cloudflare ------------------------------------------------------------

func (a *App) getCloudflare(w http.ResponseWriter, r *http.Request, s auth.Session) {
	out := map[string]any{"account_id": a.Store.Setting("cf_account", ""), "team": a.Store.Setting("cf_team", ""), "configured": a.cfConfigured()}
	cf, err := a.cfClient()
	if err == nil {
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		conns, err := cf.Connectors(ctx)
		if err != nil {
			out["error"] = err.Error()
		} else {
			owned := map[string]bool{}
			rows, _ := a.Store.DB.Query(`SELECT id FROM cf_resources`)
			for rows != nil && rows.Next() {
				var id string
				_ = rows.Scan(&id)
				owned[id] = true
			}
			if rows != nil {
				rows.Close()
			}
			list := []map[string]any{}
			for _, c := range conns {
				list = append(list, map[string]any{"id": c.ID, "name": c.Name, "status": c.Status, "created_at": c.CreatedAt, "owned": owned[c.ID]})
			}
			out["connectors"] = list
		}
	}
	writeJSON(w, 200, out)
}

func (a *App) putCloudflare(w http.ResponseWriter, r *http.Request, s auth.Session) {
	var body struct {
		AccountID string `json:"account_id"`
		Team      string `json:"team"`
		Token     string `json:"token"`
	}
	if !decode(w, r, &body) {
		return
	}
	body.AccountID = strings.ToLower(strings.TrimSpace(body.AccountID))
	if body.Token == "" {
		if t, err := a.Store.Secret("cf_token"); err == nil {
			body.Token = t
		}
	}
	cf, err := cfapi.New(body.AccountID, strings.TrimSpace(body.Token), body.Team)
	if err != nil {
		apiError(w, 400, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if _, err := cf.Connectors(ctx); err != nil {
		apiError(w, 400, "токен не подходит (нужны права Cloudflare One Connectors Write и Zero Trust Write): "+err.Error())
		return
	}
	if _, err := cf.DeviceSettings(ctx); err != nil {
		apiError(w, 400, "токен не может читать настройки устройств (нужно Zero Trust Write): "+err.Error())
		return
	}
	if old := a.Store.Setting("cf_account", ""); old != "" && old != cf.Account {
		var n int
		_ = a.Store.DB.QueryRow(`SELECT COUNT(*) FROM nodes WHERE cf_node_id<>''`).Scan(&n)
		if n > 0 {
			apiError(w, 409, "к Mesh подключены серверы старого аккаунта; сначала отключите их")
			return
		}
	}
	if err := a.Store.PutSecret("cf_token", strings.TrimSpace(body.Token)); err != nil {
		apiError(w, 500, err.Error())
		return
	}
	_ = a.Store.SetSetting("cf_account", cf.Account)
	_ = a.Store.SetSetting("cf_team", cf.Team)
	a.audit(r, s, "cloudflare.update", cf.Account)
	writeJSON(w, 200, map[string]any{"account_id": cf.Account, "team": cf.Team, "configured": true})
}

func (a *App) cfPreflight(w http.ResponseWriter, r *http.Request, s auth.Session) {
	cf, err := a.cfClient()
	if err != nil {
		apiError(w, 400, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	checks, err := cf.Preflight(ctx)
	if err != nil {
		apiError(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"checks": checks})
}

func (a *App) cfFix(w http.ResponseWriter, r *http.Request, s auth.Session) {
	var body struct {
		Fix string `json:"fix"`
		Arg string `json:"arg"`
	}
	if !decode(w, r, &body) {
		return
	}
	cf, err := a.cfClient()
	if err != nil {
		apiError(w, 400, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	switch body.Fix {
	case "enable_settings":
		err = cf.EnableMeshSettings(ctx)
	case "create_profile":
		var list []cfapi.Profile
		if list, err = cf.Profiles(ctx); err == nil {
			var p cfapi.Profile
			p, err = cf.CreateMeshProfile(ctx, cfapi.FreePrecedence(list))
			if err == nil {
				_, _ = a.Store.DB.Exec(`INSERT OR REPLACE INTO cf_resources(id,kind,name,created_at) VALUES(?,?,?,?)`, p.ID, "profile", cfapi.ProfileName, now())
			}
		}
	case "disable_profile":
		// Disabling is reversible: the profile stays in the account.
		err = cf.SetProfileEnabled(ctx, body.Arg, false)
	default:
		err = errors.New("неизвестное исправление")
	}
	if err != nil {
		apiError(w, 502, err.Error())
		return
	}
	a.audit(r, s, "cloudflare.fix", body.Fix+" "+body.Arg)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// ---- settings, jobs, audit -------------------------------------------------

func (a *App) getSettings(w http.ResponseWriter, r *http.Request, s auth.Session) {
	writeJSON(w, 200, map[string]any{
		"panel_port": a.PanelPort, "panel_allow": a.entrySettings().PanelAllow, "your_ip": clientIP(r),
		"cert_fingerprint": a.CertFingerprint(), "version": agent.Version, "xray_version": agent.XrayVersion,
	})
}

func (a *App) putPanel(w http.ResponseWriter, r *http.Request, s auth.Session) {
	var body struct {
		Allow []string `json:"panel_allow"`
	}
	if !decode(w, r, &body) {
		return
	}
	clean := []string{}
	for _, c := range body.Allow {
		if c = strings.TrimSpace(c); c == "" {
			continue
		}
		if !spec.ValidCIDR(c) {
			apiError(w, 400, "некорректный адрес: "+c)
			return
		}
		clean = append(clean, c)
	}
	if len(clean) > 0 && !allowedBy(clientIP(r), clean) {
		apiError(w, 400, "ваш адрес "+clientIP(r)+" не входит в список — панель станет недоступна для вас")
		return
	}
	_ = a.Store.SetSetting("panel_allow", strings.Join(clean, ","))
	a.queueEntry(w, r, s, "panel.allow", strings.Join(clean, ","))
}

func (a *App) listJobs(w http.ResponseWriter, r *http.Request, s auth.Session) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit < 1 || limit > 500 {
		limit = 100
	}
	jobs, err := a.jobs(limit)
	if err != nil {
		apiError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, jobs)
}

func (a *App) getJob(w http.ResponseWriter, r *http.Request, s auth.Session) {
	id, _ := pathID(r)
	j, err := a.job(id)
	if err != nil {
		apiError(w, 404, "задача не найдена")
		return
	}
	writeJSON(w, 200, j)
}

func (a *App) listAudit(w http.ResponseWriter, r *http.Request, s auth.Session) {
	rows, err := a.Store.DB.Query(`SELECT id,username,action,detail,remote,at FROM audit ORDER BY id DESC LIMIT 300`)
	if err != nil {
		apiError(w, 500, err.Error())
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id int64
		var u, act, d, rem, at string
		if rows.Scan(&id, &u, &act, &d, &rem, &at) == nil {
			out = append(out, map[string]any{"id": id, "username": u, "action": act, "detail": d, "remote": rem, "at": at})
		}
	}
	writeJSON(w, 200, out)
}
