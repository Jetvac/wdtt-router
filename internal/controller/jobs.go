package controller

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Jetvac/wdtt-router/internal/auth"
	"github.com/Jetvac/wdtt-router/internal/node"
)

type Job struct {
	ID         int64  `json:"id"`
	ServerID   int64  `json:"server_id"`
	Action     string `json:"action"`
	Status     string `json:"status"`
	Progress   string `json:"progress"`
	Result     string `json:"result"`
	SnapshotID string `json:"snapshot_id"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
}

func (a *App) listJobs(limit int) ([]Job, error) {
	rows, err := a.Store.DB.Query(`SELECT id,server_id,action,status,progress,result,snapshot_id,created_at,updated_at FROM jobs ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []Job{}
	for rows.Next() {
		var j Job
		if err := rows.Scan(&j.ID, &j.ServerID, &j.Action, &j.Status, &j.Progress, &j.Result, &j.SnapshotID, &j.CreatedAt, &j.UpdatedAt); err != nil {
			return nil, err
		}
		list = append(list, j)
	}
	return list, rows.Err()
}

func (a *App) jobs(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	list, err := a.listJobs(100)
	if err != nil {
		apiError(w, 500, "Could not load jobs")
		return
	}
	writeJSON(w, 200, list)
}

func (a *App) work(ctx context.Context) {
	_, _ = a.Store.DB.Exec(`UPDATE jobs SET status='failed',result='Controller restarted during operation; check recovery status',input_cipher='',updated_at=? WHERE status IN ('running','rolling_back')`, time.Now().UTC().Format(time.RFC3339))
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.runNext(ctx)
		}
	}
}

func (a *App) runNext(ctx context.Context) {
	var id, serverID int64
	var action, cipherText string
	err := a.Store.DB.QueryRow(`SELECT id,server_id,action,input_cipher FROM jobs WHERE status='queued' ORDER BY id LIMIT 1`).Scan(&id, &serverID, &action, &cipherText)
	if errors.Is(err, sql.ErrNoRows) {
		return
	}
	if err != nil {
		a.loggerError(err)
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := a.Store.DB.Exec(`UPDATE jobs SET status='running',progress='Connecting to node',updated_at=? WHERE id=? AND status='queued'`, now, id)
	if err != nil {
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return
	}
	// One worker serializes changes across all nodes; a later worker pool can
	// preserve this per-server exclusion while allowing independent nodes.
	jobCtx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	result, err := a.execute(jobCtx, serverID, action, cipherText, id)
	cancel()
	status := "success"
	message := result
	if err != nil {
		status = "failed"
		message = redactError(err.Error())
		a.Store.Event(serverID, action, "error", message)
	} else {
		a.Store.Event(serverID, action, "info", result)
	}
	_, _ = a.Store.DB.Exec(`UPDATE jobs SET status=?,progress='',result=?,input_cipher='',updated_at=? WHERE id=?`, status, trim(message, 2000), time.Now().UTC().Format(time.RFC3339), id)
}

func redactError(s string) string {
	// Errors from the node are deliberately structured without secrets. Keep a
	// final guard against accidental URL/credential content from dependencies.
	if i := strings.Index(s, "wdtt://"); i >= 0 {
		s = s[:i] + "<redacted link>"
	}
	return trim(s, 1800)
}

func trim(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func (a *App) execute(ctx context.Context, serverID int64, action, cipherText string, jobID int64) (string, error) {
	plain, err := a.Store.OpenSecret(cipherText)
	if err != nil {
		return "", err
	}
	if action == "cloudflare.deploy" {
		return a.deployCloudflare(ctx, []byte(plain), jobID)
	}
	s, err := a.getServer(serverID)
	if err != nil {
		return "", err
	}
	var req node.Request
	if err := json.Unmarshal([]byte(plain), &req); err != nil {
		return "", err
	}
	var result node.Result
	if s.Transport == "local" {
		result, err = node.Apply(ctx, req)
	} else {
		out, runErr := a.SSH.Run(ctx, s.target(), "/usr/local/bin/wdtt-panel node apply", []byte(plain))
		if runErr != nil {
			return "", fmt.Errorf("node operation failed: %w: %s", runErr, trim(string(out), 800))
		}
		err = json.Unmarshal(out, &result)
	}
	if err != nil {
		return "", err
	}
	if action == "xui.warp.enable" {
		if err := a.verifyXUIWarp(ctx, s); err != nil {
			if rollbackErr := a.disableXUIWarp(ctx, s); rollbackErr != nil {
				return "", fmt.Errorf("WARP TCP/UDP verification failed and rollback failed: %w", rollbackErr)
			}
			return "", fmt.Errorf("WARP TCP/UDP verification failed; direct outbound restored: %w", err)
		}
	}
	if result.RecoveryID != "" {
		if !regexp.MustCompile(`^[A-Za-z0-9_-]{1,100}$`).MatchString(result.RecoveryID) {
			return "", errors.New("invalid recovery ID returned by node")
		}
		_, _ = a.Store.DB.Exec(`UPDATE jobs SET progress='Checking management connection and health',snapshot_id=?,updated_at=? WHERE id=?`, result.RecoveryID, time.Now().UTC().Format(time.RFC3339), jobID)
		observed, healthErr := a.readStatus(ctx, s)
		if healthErr == nil && action == "mesh.install" {
			if observed.MeshContainer != "running" || observed.MeshIP == "" || req.Mesh == nil {
				healthErr = errors.New("Mesh interface or container missing")
			} else {
				healthErr = a.waitCFMeshHealthy(ctx, req.Mesh.AccountID, req.Mesh.NodeID)
			}
		}
		if healthErr == nil && action == "vless.client.enable" && !observed.VLESSClientReady {
			healthErr = errors.New("transparent VLESS client is not listening")
		}
		if healthErr != nil {
			_, _ = a.Store.DB.Exec(`UPDATE jobs SET status='rolling_back',progress='Restoring previous state',updated_at=? WHERE id=?`, time.Now().UTC().Format(time.RFC3339), jobID)
			_ = a.recover(ctx, s, result.RecoveryID)
			return "", fmt.Errorf("post-apply verification failed; rollback requested: %w", healthErr)
		}
		if err := a.commit(ctx, s, result.RecoveryID); err != nil {
			return "", fmt.Errorf("could not cancel recovery timer: %w", err)
		}
	}
	if len(result.Secret) > 0 {
		b, _ := json.Marshal(result.Secret)
		kind := ""
		switch action {
		case "xui.install", "xui.credentials":
			kind = "xui"
		case "vless.enable":
			kind = "vless"
		case "vless.client.enable":
			kind = "vless-client"
		default:
			return "", errors.New("unexpected secret returned by node")
		}
		if err := a.Store.PutSecret("server:"+strconv.FormatInt(serverID, 10)+":"+kind, string(b)); err != nil {
			return "", err
		}
	}
	if action == "vless.disable" {
		_ = a.Store.DeleteSecret("server:" + strconv.FormatInt(serverID, 10) + ":vless")
	}
	if action == "vless.client.disable" {
		_ = a.Store.DeleteSecret("server:" + strconv.FormatInt(serverID, 10) + ":vless-client")
	}
	if action == "wdtt.install" || action == "wdtt.reconfigure" {
		b, _ := json.Marshal(map[string]string{"password": req.Password, "vk_link": req.VKLink, "public_host": req.PublicHost})
		if err := a.Store.PutSecret("server:"+strconv.FormatInt(serverID, 10)+":wdtt", string(b)); err != nil {
			return "", err
		}
	}
	if result.Status != nil {
		b, _ := json.Marshal(result.Status)
		_, _ = a.Store.DB.Exec(`UPDATE servers SET os=?,last_seen=?,observed_json=? WHERE id=?`, result.Status.OS, time.Now().UTC().Format(time.RFC3339), string(b), serverID)
	}
	if req.Firewall != nil {
		auto := 0
		if req.Firewall.Automatic {
			auto = 1
		}
		_, _ = a.Store.DB.Exec(`UPDATE servers SET firewall_auto=? WHERE id=?`, auto, serverID)
	}
	if result.Status == nil {
		if observed, statusErr := a.readStatus(ctx, s); statusErr == nil {
			b, _ := json.Marshal(observed)
			_, _ = a.Store.DB.Exec(`UPDATE servers SET os=?,last_seen=?,observed_json=? WHERE id=?`, observed.OS, time.Now().UTC().Format(time.RFC3339), string(b), serverID)
		}
	}
	return result.Message, nil
}

func (a *App) verifyXUIWarp(ctx context.Context, egress Server) error {
	servers, err := a.listServers()
	if err != nil {
		return err
	}
	for _, ingress := range servers {
		if ingress.Role != "ingress" {
			continue
		}
		observed, err := a.readStatus(ctx, ingress)
		if err != nil || !observed.VLESSClientEnabled {
			continue
		}
		for attempt := 0; attempt < 3; attempt++ {
			var probe node.TrafficProbe
			if ingress.Transport == "local" {
				probe, err = node.ProbeVLESSClientTraffic(ctx)
			} else {
				var out []byte
				out, err = a.SSH.Run(ctx, ingress.target(), "/usr/local/bin/wdtt-panel node probe-vless-client-json", nil)
				if err == nil {
					err = json.Unmarshal(out, &probe)
				}
			}
			if err == nil && probe.UDPOK && probe.IP != egress.Host {
				return nil
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(3 * time.Second):
			}
		}
		return errors.New("private VLESS still exits directly or UDP failed")
	}
	return nil // No active WDTT VLESS client to probe yet.
}

func (a *App) disableXUIWarp(ctx context.Context, s Server) error {
	req := node.Request{Action: "xui.warp.disable"}
	if s.Transport == "local" {
		_, err := node.Apply(ctx, req)
		return err
	}
	b, _ := json.Marshal(req)
	_, err := a.SSH.Run(ctx, s.target(), "/usr/local/bin/wdtt-panel node apply", b)
	return err
}

func (a *App) waitCFMeshHealthy(ctx context.Context, accountID, nodeID string) error {
	token, err := a.Store.Secret("cloudflare:" + accountID)
	if err != nil {
		return errors.New("Cloudflare token unavailable for Mesh verification")
	}
	client := cfClient{accountID: accountID, token: token, http: &http.Client{Timeout: 12 * time.Second}}
	deadline := time.Now().Add(90 * time.Second)
	for {
		var state cfMeshNode
		err := client.get(ctx, "warp_connector/"+nodeID, &state)
		if err == nil && state.Status == "healthy" {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("Cloudflare Mesh node did not become healthy")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

func (a *App) commit(ctx context.Context, s Server, id string) error {
	if s.Transport == "local" {
		return node.CommitRecovery(ctx, id)
	}
	_, err := a.SSH.Run(ctx, s.target(), "/usr/local/bin/wdtt-panel node commit "+id, nil)
	return err
}
func (a *App) recover(ctx context.Context, s Server, id string) error {
	if s.Transport == "local" {
		return node.Recover(ctx, id)
	}
	_, err := a.SSH.Run(ctx, s.target(), "/usr/local/bin/wdtt-panel node recover "+id, nil)
	return err
}
