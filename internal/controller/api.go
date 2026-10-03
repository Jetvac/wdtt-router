package controller

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Jetvac/wdtt-router/internal/auth"
	"github.com/Jetvac/wdtt-router/internal/node"
	"github.com/Jetvac/wdtt-router/internal/transport"
)

type Server struct {
	ID           int64           `json:"id"`
	Name         string          `json:"name"`
	Host         string          `json:"host"`
	Port         int             `json:"port"`
	Role         string          `json:"role"`
	OS           string          `json:"os"`
	Fingerprint  string          `json:"fingerprint"`
	Transport    string          `json:"transport"`
	FirewallAuto bool            `json:"firewall_auto"`
	LastSeen     string          `json:"last_seen"`
	Observed     json.RawMessage `json:"observed"`
}

func scanServer(rows *sql.Rows) (Server, error) {
	var s Server
	var firewall int
	var observed string
	err := rows.Scan(&s.ID, &s.Name, &s.Host, &s.Port, &s.Role, &s.OS, &s.Fingerprint, &s.Transport, &firewall, &s.LastSeen, &observed)
	s.FirewallAuto = firewall != 0
	s.Observed = json.RawMessage(observed)
	return s, err
}
func (a *App) listServers() ([]Server, error) {
	rows, err := a.Store.DB.Query(`SELECT id,name,host,port,role,os,fingerprint,transport,firewall_auto,last_seen,observed_json FROM servers ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []Server{}
	for rows.Next() {
		s, err := scanServer(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, s)
	}
	return list, rows.Err()
}
func (a *App) getServer(id int64) (Server, error) {
	var s Server
	var firewall int
	var observed string
	err := a.Store.DB.QueryRow(`SELECT id,name,host,port,role,os,fingerprint,transport,firewall_auto,last_seen,observed_json FROM servers WHERE id=?`, id).Scan(&s.ID, &s.Name, &s.Host, &s.Port, &s.Role, &s.OS, &s.Fingerprint, &s.Transport, &firewall, &s.LastSeen, &observed)
	s.FirewallAuto = firewall != 0
	s.Observed = json.RawMessage(observed)
	return s, err
}
func serverID(r *http.Request) (int64, error) { return strconv.ParseInt(r.PathValue("id"), 10, 64) }
func (s Server) target() transport.Target {
	return transport.Target{Host: s.Host, Port: s.Port, User: "root", Fingerprint: s.Fingerprint}
}

func (a *App) servers(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	list, err := a.listServers()
	if err != nil {
		apiError(w, 500, "Could not load servers")
		return
	}
	writeJSON(w, 200, list)
}

func (a *App) addServer(w http.ResponseWriter, r *http.Request, user auth.Session) {
	var body struct {
		Name        string `json:"name"`
		Host        string `json:"host"`
		Port        int    `json:"port"`
		Role        string `json:"role"`
		Password    string `json:"password"`
		Fingerprint string `json:"fingerprint"`
	}
	if !decode(w, r, &body) {
		return
	}
	if body.Port == 0 {
		body.Port = 22
	}
	if body.Name == "" || len(body.Name) > 80 || net.ParseIP(body.Host) == nil || body.Port < 1 || body.Port > 65535 || body.Password == "" {
		apiError(w, 400, "Valid name, IP, port and SSH password required")
		return
	}
	if body.Role != "ingress" && body.Role != "egress" && body.Role != "intermediate" {
		apiError(w, 400, "Invalid server role")
		return
	}
	t := transport.Target{Host: body.Host, Port: body.Port, User: "root", Fingerprint: body.Fingerprint}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	fp, err := a.SSH.Bootstrap(ctx, t, body.Password)
	if err != nil {
		apiError(w, 502, "SSH bootstrap failed: "+err.Error())
		return
	}
	t.Fingerprint = fp
	bin, err := os.ReadFile(a.BinaryPath)
	if err != nil {
		apiError(w, 500, "Panel binary unavailable")
		return
	}
	if err := a.SSH.Upload(ctx, t, "/usr/local/bin/wdtt-panel", bin); err != nil {
		apiError(w, 502, "Node binary upload failed")
		return
	}
	out, err := a.SSH.Run(ctx, t, "/usr/local/bin/wdtt-panel node status", nil)
	if err != nil {
		apiError(w, 502, "Node status failed")
		return
	}
	var observed node.Status
	if err := json.Unmarshal(out, &observed); err != nil {
		apiError(w, 502, "Invalid node status")
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	result, err := a.Store.DB.Exec(`INSERT INTO servers(name,host,port,role,os,fingerprint,transport,created_at,last_seen,observed_json) VALUES(?,?,?,?,?,?,'ssh',?,?,?)`, body.Name, body.Host, body.Port, body.Role, observed.OS, fp, now, now, string(out))
	if err != nil {
		apiError(w, 409, "Server already exists or could not be saved")
		return
	}
	id, _ := result.LastInsertId()
	_, _ = a.Store.DB.Exec(`INSERT INTO audit_events(user_id,server_id,action,result,at) VALUES(?,?,?,?,?)`, user.UserID, id, "server.bootstrap", "success", now)
	writeJSON(w, 201, map[string]any{"id": id, "fingerprint": fp, "status": observed})
}

func (a *App) readStatus(ctx context.Context, s Server) (node.Status, error) {
	if s.Transport == "local" {
		return node.Inspect(ctx), nil
	}
	out, err := a.SSH.Run(ctx, s.target(), "/usr/local/bin/wdtt-panel node status", nil)
	if err != nil {
		return node.Status{}, err
	}
	var observed node.Status
	if err := json.Unmarshal(out, &observed); err != nil {
		return observed, err
	}
	return observed, nil
}

func (a *App) serverStatus(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	id, err := serverID(r)
	if err != nil {
		apiError(w, 400, "Invalid server ID")
		return
	}
	s, err := a.getServer(id)
	if err != nil {
		apiError(w, 404, "Server not found")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	observed, err := a.readStatus(ctx, s)
	if err != nil {
		apiError(w, 502, "Could not contact server")
		return
	}
	b, _ := json.Marshal(observed)
	_, _ = a.Store.DB.Exec(`UPDATE servers SET os=?,last_seen=?,observed_json=? WHERE id=?`, observed.OS, time.Now().UTC().Format(time.RFC3339), string(b), id)
	writeJSON(w, 200, observed)
}

func (a *App) serverSecret(w http.ResponseWriter, r *http.Request, user auth.Session) {
	id, err := serverID(r)
	if err != nil {
		apiError(w, 400, "Invalid server ID")
		return
	}
	if _, err := a.getServer(id); err != nil {
		apiError(w, 404, "Server not found")
		return
	}
	kind := r.PathValue("kind")
	if kind != "xui" && kind != "vless" && kind != "vless-client" && kind != "wdtt" {
		apiError(w, 400, "Invalid secret type")
		return
	}
	plain, err := a.Store.Secret("server:" + strconv.FormatInt(id, 10) + ":" + kind)
	if err != nil {
		apiError(w, 404, "Saved credentials not found")
		return
	}
	var data map[string]string
	if json.Unmarshal([]byte(plain), &data) != nil {
		apiError(w, 500, "Saved credentials are invalid")
		return
	}
	_, _ = a.Store.DB.Exec(`INSERT INTO audit_events(user_id,server_id,action,result,at) VALUES(?,?,?,?,?)`, user.UserID, id, "secret.reveal."+kind, "success", time.Now().UTC().Format(time.RFC3339))
	writeJSON(w, 200, data)
}

func (a *App) action(w http.ResponseWriter, r *http.Request, user auth.Session) {
	id, err := serverID(r)
	if err != nil {
		apiError(w, 400, "Invalid server ID")
		return
	}
	if _, err := a.getServer(id); err != nil {
		apiError(w, 404, "Server not found")
		return
	}
	var req node.Request
	if !decode(w, r, &req) {
		return
	}
	if !allowedAction(req.Action) {
		apiError(w, 400, "Unsupported action")
		return
	}
	if req.Action == "firewall.apply" && req.Firewall != nil && req.Firewall.RestrictSSH {
		_, allowed, err := net.ParseCIDR(req.Firewall.ManagementCIDR)
		peer, _, splitErr := net.SplitHostPort(r.RemoteAddr)
		if err != nil || splitErr != nil || !allowed.Contains(net.ParseIP(peer)) {
			apiError(w, 400, "Management CIDR must include your current address")
			return
		}
	}
	if req.Action == "recovery.restore" {
		if !regexp.MustCompile(`^[a-f0-9]{24}$`).MatchString(req.SnapshotID) {
			apiError(w, 400, "Invalid snapshot ID")
			return
		}
		var found int
		err := a.Store.DB.QueryRow(`SELECT 1 FROM jobs WHERE server_id=? AND snapshot_id=? AND status='success' AND action IN ('routing.apply','firewall.apply','recovery.restore') AND result LIKE '%(snapshot saved)' LIMIT 1`, id, req.SnapshotID).Scan(&found)
		if err != nil {
			apiError(w, 404, "Committed snapshot not found for this server")
			return
		}
		peer, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			apiError(w, 400, "Could not identify your address")
			return
		}
		req.ManagementIP = peer
	}
	data, _ := json.Marshal(req)
	enc, err := a.Store.Seal(string(data))
	if err != nil {
		apiError(w, 500, "Could not queue action")
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	result, err := a.Store.DB.Exec(`INSERT INTO jobs(server_id,action,status,progress,input_cipher,created_at,updated_at) VALUES(?,?,'queued','Waiting',?,?,?)`, id, req.Action, enc, now, now)
	if err != nil {
		apiError(w, 500, "Could not queue action")
		return
	}
	jobID, _ := result.LastInsertId()
	_, _ = a.Store.DB.Exec(`INSERT INTO audit_events(user_id,server_id,action,result,at) VALUES(?,?,?,?,?)`, user.UserID, id, req.Action, "queued", now)
	writeJSON(w, 202, map[string]any{"job_id": jobID, "status": "queued"})
}

func allowedAction(action string) bool {
	switch action {
	case "status", "wdtt.import", "wdtt.install", "wdtt.reconfigure", "wdtt.start", "wdtt.stop", "wdtt.restart", "wdtt.uninstall", "xui.install", "xui.credentials", "xui.start", "xui.stop", "xui.restart", "xui.warp.enable", "xui.warp.disable", "mesh.install", "mesh.uninstall", "routing.apply", "firewall.apply", "recovery.restore", "vless.enable", "vless.disable", "vless.repair", "vless.client.enable", "vless.client.disable":
		return true
	}
	return false
}

func (a *App) overview(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	servers, err := a.listServers()
	if err != nil {
		apiError(w, 500, "Could not load overview")
		return
	}
	jobs, _ := a.listJobs(8)
	writeJSON(w, 200, map[string]any{"servers": servers, "jobs": jobs})
}

func (a *App) chains(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	rows, err := a.Store.DB.Query(`SELECT id,name,desired_json,observed_json,applied_json,created_at FROM chains ORDER BY id DESC`)
	if err != nil {
		apiError(w, 500, "Could not load chains")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id int64
		var name, desired, observed, applied, created string
		if err := rows.Scan(&id, &name, &desired, &observed, &applied, &created); err != nil {
			apiError(w, 500, "Could not load chains")
			return
		}
		items = append(items, map[string]any{"id": id, "name": name, "desired": json.RawMessage(desired), "observed": json.RawMessage(observed), "applied": json.RawMessage(applied), "created_at": created})
	}
	writeJSON(w, 200, items)
}

func (a *App) addChain(w http.ResponseWriter, r *http.Request, user auth.Session) {
	var body struct {
		Name  string  `json:"name"`
		Nodes []int64 `json:"nodes"`
	}
	if !decode(w, r, &body) {
		return
	}
	if body.Name == "" || len(body.Name) > 80 || len(body.Nodes) < 2 {
		apiError(w, 400, "Chain needs a name and at least two nodes")
		return
	}
	seen := map[int64]bool{}
	for _, id := range body.Nodes {
		if seen[id] {
			apiError(w, 400, "Duplicate node")
			return
		}
		seen[id] = true
		if _, err := a.getServer(id); err != nil {
			apiError(w, 400, "Unknown node")
			return
		}
	}
	desired, _ := json.Marshal(map[string]any{"nodes": body.Nodes})
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := a.Store.DB.Exec(`INSERT INTO chains(name,desired_json,created_at) VALUES(?,?,?)`, body.Name, string(desired), now)
	if err != nil {
		apiError(w, 500, "Could not create chain")
		return
	}
	id, _ := res.LastInsertId()
	_, _ = a.Store.DB.Exec(`INSERT INTO audit_events(user_id,action,result,at) VALUES(?,?,?,?)`, user.UserID, "chain.create", "success", now)
	writeJSON(w, 201, map[string]any{"id": id, "name": body.Name, "nodes": body.Nodes})
}

func (a *App) events(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	rows, err := a.Store.DB.Query(`SELECT id,server_id,component,severity,message,at FROM events WHERE at >= ? ORDER BY id DESC LIMIT 200`, time.Now().UTC().Add(-24*time.Hour).Format(time.RFC3339))
	if err != nil {
		apiError(w, 500, "Could not load events")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id int64
		var serverID sql.NullInt64
		var component, severity, message, at string
		if err := rows.Scan(&id, &serverID, &component, &severity, &message, &at); err != nil {
			apiError(w, 500, "Could not load events")
			return
		}
		items = append(items, map[string]any{"id": id, "server_id": serverID.Int64, "component": component, "severity": severity, "message": message, "at": at})
	}
	writeJSON(w, 200, items)
}

func (a *App) diagnostics(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	servers, _ := a.listServers()
	jobs, _ := a.listJobs(50)
	// Only predefined, redacted fields enter this bundle. No tokens, private keys,
	// cookies, raw environment, or command output from third-party installers.
	bundle := map[string]any{"generated_at": time.Now().UTC().Format(time.RFC3339), "servers": servers, "jobs": jobs}
	w.Header().Set("Content-Disposition", `attachment; filename="wdtt-panel-diagnostics.json"`)
	writeJSON(w, 200, bundle)
}

func requireNonEmpty(v string) error {
	if strings.TrimSpace(v) == "" {
		return errors.New("empty value")
	}
	return nil
}
func internalErr(err error) string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf("%T", err)
}
