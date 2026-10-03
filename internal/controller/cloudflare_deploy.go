package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/Jetvac/wdtt-router/internal/auth"
	"github.com/Jetvac/wdtt-router/internal/node"
)

type cloudflareDeployRequest struct {
	AccountID   string `json:"account_id"`
	Team        string `json:"team"`
	IngressID   int64  `json:"ingress_id"`
	EgressID    int64  `json:"egress_id"`
	IngressName string `json:"ingress_name"`
	EgressName  string `json:"egress_name"`
	WDTTNet     string `json:"wdtt_net"`
}

type cfOwnedResource struct {
	ID   string
	Kind string
	Name string
}

func protectedCloudflareAccount(id string) bool {
	data, err := os.ReadFile("/etc/wdtt-panel/protected-accounts")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == id {
			return true
		}
	}
	return false
}

func validateCFDeploy(r cloudflareDeployRequest) error {
	if !regexp.MustCompile(`^[a-fA-F0-9]{32}$`).MatchString(r.AccountID) {
		return errors.New("invalid Account ID")
	}
	if !regexp.MustCompile(`^[A-Za-z0-9-]{1,100}$`).MatchString(r.Team) {
		return errors.New("invalid Team")
	}
	if !regexp.MustCompile(`^[A-Za-z0-9._-]{1,80}$`).MatchString(r.IngressName) || !regexp.MustCompile(`^[A-Za-z0-9._-]{1,80}$`).MatchString(r.EgressName) || r.IngressName == r.EgressName {
		return errors.New("invalid or duplicate Mesh node names")
	}
	if r.IngressID == r.EgressID || r.IngressID < 1 || r.EgressID < 1 {
		return errors.New("two distinct servers required")
	}
	if r.WDTTNet != "10.66.66.0/24" {
		return errors.New("current WDTT installer requires 10.66.66.0/24")
	}
	if protectedCloudflareAccount(r.AccountID) {
		return errors.New("this Cloudflare account is protected from changes")
	}
	return nil
}

func (a *App) queueCloudflareDeploy(w http.ResponseWriter, r *http.Request, user auth.Session) {
	var body cloudflareDeployRequest
	if !decode(w, r, &body) {
		return
	}
	if body.WDTTNet == "" {
		body.WDTTNet = "10.66.66.0/24"
	}
	if err := validateCFDeploy(body); err != nil {
		apiError(w, 400, err.Error())
		return
	}
	ingress, err := a.getServer(body.IngressID)
	if err != nil || ingress.Role != "ingress" {
		apiError(w, 400, "valid ingress server required")
		return
	}
	egress, err := a.getServer(body.EgressID)
	if err != nil || egress.Role != "egress" {
		apiError(w, 400, "valid egress server required")
		return
	}
	var savedAccount, savedTeam string
	_ = a.Store.DB.QueryRow(`SELECT value FROM settings WHERE name='cloudflare_account_id'`).Scan(&savedAccount)
	_ = a.Store.DB.QueryRow(`SELECT value FROM settings WHERE name='cloudflare_team'`).Scan(&savedTeam)
	if body.AccountID != savedAccount || body.Team != savedTeam {
		apiError(w, 400, "save this Cloudflare account and team first")
		return
	}
	if _, err := a.Store.Secret("cloudflare:" + body.AccountID); err != nil {
		apiError(w, 400, "Cloudflare token missing")
		return
	}
	b, _ := json.Marshal(body)
	sealed, err := a.Store.Seal(string(b))
	if err != nil {
		apiError(w, 500, "could not queue deployment")
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := a.Store.DB.Exec(`INSERT INTO jobs(server_id,action,status,progress,input_cipher,created_at,updated_at) VALUES(?,'cloudflare.deploy','queued','Waiting',?,?,?)`, body.IngressID, sealed, now, now)
	if err != nil {
		apiError(w, 500, "could not queue deployment")
		return
	}
	id, _ := res.LastInsertId()
	_, _ = a.Store.DB.Exec(`INSERT INTO audit_events(user_id,server_id,action,result,at) VALUES(?,?,?,'queued',?)`, user.UserID, body.IngressID, "cloudflare.deploy", now)
	writeJSON(w, 202, map[string]any{"job_id": id, "status": "queued"})
}

func (a *App) cloudflareResources(w http.ResponseWriter, _ *http.Request, _ auth.Session) {
	rows, err := a.Store.DB.Query(`SELECT id,account_id,vnet_id,kind,name,owner,created_at FROM cloudflare_resources ORDER BY created_at,id`)
	if err != nil {
		apiError(w, 500, "could not read Cloudflare resources")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, account, vnet, kind, name, owner, created string
		if err := rows.Scan(&id, &account, &vnet, &kind, &name, &owner, &created); err != nil {
			apiError(w, 500, "could not read Cloudflare resources")
			return
		}
		items = append(items, map[string]any{"id": id, "account_id": account, "vnet_id": vnet, "kind": kind, "name": name, "owner": owner, "created_at": created})
	}
	writeJSON(w, 200, items)
}

func (c cfClient) call(ctx context.Context, method, path string, body any, target any) error {
	var input io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		input = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://api.cloudflare.com/client/v4/accounts/"+c.accountID+"/"+path, input)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return err
	}
	var envelope cfEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return fmt.Errorf("Cloudflare HTTP %d: invalid response", resp.StatusCode)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || !envelope.Success {
		if len(envelope.Errors) > 0 {
			return fmt.Errorf("Cloudflare HTTP %d, code %d: %s", resp.StatusCode, envelope.Errors[0].Code, trim(envelope.Errors[0].Message, 250))
		}
		return fmt.Errorf("Cloudflare HTTP %d", resp.StatusCode)
	}
	if target != nil {
		return json.Unmarshal(envelope.Result, target)
	}
	return nil
}

func (a *App) markCFResource(account, vnet string, resource cfOwnedResource) error {
	_, err := a.Store.DB.Exec(`INSERT INTO cloudflare_resources(id,account_id,vnet_id,kind,name,owner,created_at) VALUES(?,?,?,?,?,'created',?)`, resource.ID, account, vnet, resource.Kind, resource.Name, time.Now().UTC().Format(time.RFC3339))
	return err
}

func (a *App) unmarkCFResource(ctx context.Context, c cfClient, resource cfOwnedResource) error {
	var owner, kind string
	if err := a.Store.DB.QueryRow(`SELECT owner,kind FROM cloudflare_resources WHERE id=? AND account_id=?`, resource.ID, c.accountID).Scan(&owner, &kind); err != nil {
		return err
	}
	if owner != "created" || kind != resource.Kind {
		return errors.New("Cloudflare resource is not panel-owned")
	}
	var path string
	switch kind {
	case "route":
		path = "teamnet/routes/" + resource.ID
	case "node":
		path = "warp_connector/" + resource.ID
	case "profile":
		path = "devices/policy/" + resource.ID
	default:
		return errors.New("unknown Cloudflare resource kind")
	}
	if err := c.call(ctx, http.MethodDelete, path, nil, nil); err != nil {
		return err
	}
	_, err := a.Store.DB.Exec(`DELETE FROM cloudflare_resources WHERE id=? AND account_id=? AND owner='created'`, resource.ID, c.accountID)
	return err
}

func (a *App) cloudflareProgress(jobID int64, message string) {
	_, _ = a.Store.DB.Exec(`UPDATE jobs SET progress=?,updated_at=? WHERE id=?`, message, time.Now().UTC().Format(time.RFC3339), jobID)
}

func (a *App) deployCloudflare(ctx context.Context, data []byte, jobID int64) (message string, returnErr error) {
	var req cloudflareDeployRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return "", err
	}
	if err := validateCFDeploy(req); err != nil {
		return "", err
	}
	ingress, err := a.getServer(req.IngressID)
	if err != nil {
		return "", err
	}
	egress, err := a.getServer(req.EgressID)
	if err != nil {
		return "", err
	}
	if ingress.Role != "ingress" || egress.Role != "egress" {
		return "", errors.New("server roles changed")
	}
	token, err := a.Store.Secret("cloudflare:" + req.AccountID)
	if err != nil {
		return "", err
	}
	c := cfClient{accountID: req.AccountID, token: token, http: &http.Client{Timeout: 25 * time.Second}}
	a.cloudflareProgress(jobID, "Checking account routes, nodes and settings")
	routes, err := c.routes(ctx)
	if err != nil {
		return "", err
	}
	for _, route := range routes {
		if route.DeletedAt == nil || *route.DeletedAt == "" {
			for _, want := range []string{"0.0.0.0/1", "128.0.0.0/1", req.WDTTNet} {
				if overlap(want, route.Network) {
					return "", fmt.Errorf("existing Cloudflare route %s overlaps %s", route.Network, want)
				}
			}
		}
	}
	var nodes []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := c.get(ctx, "warp_connector?per_page=100&page=1", &nodes); err != nil {
		return "", err
	}
	if len(nodes) > 0 {
		return "", errors.New("account already has Mesh nodes; dedicated empty account required for full-tunnel profile")
	}
	var settings struct {
		VirtualIP bool `json:"use_zt_virtual_ip"`
		TCP       bool `json:"gateway_proxy_enabled"`
		UDP       bool `json:"gateway_udp_proxy_enabled"`
	}
	if err := c.get(ctx, "devices/settings", &settings); err != nil {
		return "", err
	}
	if !settings.VirtualIP || !settings.TCP || !settings.UDP {
		return "", errors.New("Cloudflare Mesh IP and TCP/UDP Gateway proxy settings must be enabled")
	}
	var vnets []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := c.get(ctx, "teamnet/virtual_networks", &vnets); err != nil {
		return "", err
	}
	var vnetID string
	for _, v := range vnets {
		if v.Name == "default" {
			vnetID = v.ID
			break
		}
	}
	if !regexp.MustCompile(`^[a-fA-F0-9-]{36}$`).MatchString(vnetID) {
		return "", errors.New("default Cloudflare virtual network not found")
	}
	var policies []struct {
		ID         string `json:"policy_id"`
		Name       string `json:"name"`
		Match      string `json:"match"`
		Precedence int    `json:"precedence"`
	}
	if err := c.get(ctx, "devices/policies?per_page=100&page=1", &policies); err != nil {
		return "", err
	}
	identity := "warp_connector@" + req.Team + ".cloudflareaccess.com"
	for _, p := range policies {
		if strings.Contains(p.Match, identity) && p.Precedence <= 900 {
			return "", errors.New("another Mesh profile has priority at or before 900")
		}
	}
	created := []cfOwnedResource{}
	installed := []Server{}
	defer func() {
		if returnErr == nil {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		for i := len(installed) - 1; i >= 0; i-- {
			_ = a.uninstallOwnedMesh(cleanupCtx, installed[i])
		}
		for i := len(created) - 1; i >= 0; i-- {
			if err := a.unmarkCFResource(cleanupCtx, c, created[i]); err != nil {
				a.Store.Event(req.IngressID, "cloudflare.deploy", "error", "Cleanup failed for "+created[i].Kind+" "+created[i].ID)
			}
		}
	}()
	profileName := "WDTT Panel full tunnel " + time.Now().UTC().Format("20060102-150405")
	a.cloudflareProgress(jobID, "Creating dedicated Mesh profile")
	profileBody := map[string]any{"name": profileName, "description": "Panel-owned full tunnel for WDTT test nodes", "enabled": true, "precedence": 900, "match": "identity.email == \"" + identity + "\"", "service_mode_v2": map[string]string{"mode": "warp"}, "tunnel_protocol": "masque", "exclude": []map[string]string{{"address": "172.31.255.0/29", "description": "Local Mesh Docker bridge"}}}
	var profile struct {
		ID       string `json:"id"`
		PolicyID string `json:"policy_id"`
	}
	if err := c.call(ctx, http.MethodPost, "devices/policy", profileBody, &profile); err != nil {
		return "", err
	}
	if profile.ID == "" {
		profile.ID = profile.PolicyID
	}
	if !validCFUUID(profile.ID) {
		return "", errors.New("invalid profile ID returned by Cloudflare")
	}
	resource := cfOwnedResource{profile.ID, "profile", profileName}
	if err := a.markCFResource(req.AccountID, vnetID, resource); err != nil {
		_ = c.call(ctx, http.MethodDelete, "devices/policy/"+profile.ID, nil, nil)
		return "", err
	}
	created = append(created, resource)
	for _, item := range []struct {
		server     Server
		name, role string
	}{{ingress, req.IngressName, "ingress"}, {egress, req.EgressName, "egress"}} {
		a.cloudflareProgress(jobID, "Creating Mesh node "+item.name)
		var createdNode struct {
			ID string `json:"id"`
		}
		if err := c.call(ctx, http.MethodPost, "warp_connector", map[string]string{"name": item.name}, &createdNode); err != nil {
			return "", err
		}
		if !validCFUUID(createdNode.ID) {
			return "", errors.New("invalid Mesh node ID returned by Cloudflare")
		}
		resource = cfOwnedResource{createdNode.ID, "node", item.name}
		if err := a.markCFResource(req.AccountID, vnetID, resource); err != nil {
			_ = c.call(ctx, http.MethodDelete, "warp_connector/"+createdNode.ID, nil, nil)
			return "", err
		}
		created = append(created, resource)
		var meshToken string
		if err := c.get(ctx, "warp_connector/"+createdNode.ID+"/token", &meshToken); err != nil {
			return "", err
		}
		if len(meshToken) < 20 {
			return "", errors.New("invalid Mesh token returned by Cloudflare")
		}
		if err := a.Store.PutSecret("cloudflare:"+req.AccountID+":node:"+createdNode.ID, meshToken); err != nil {
			return "", err
		}
		m := node.MeshConfig{Role: item.role, AccountID: req.AccountID, VNetID: vnetID, NodeID: createdNode.ID, NodeName: item.name, MeshToken: meshToken, WDTTNet: req.WDTTNet}
		a.cloudflareProgress(jobID, "Connecting Mesh node "+item.name)
		if err := a.installOwnedMesh(ctx, item.server, m); err != nil {
			return "", fmt.Errorf("%s: %w", item.name, err)
		}
		installed = append(installed, item.server)
	}
	for _, entry := range []struct{ network, id string }{{"0.0.0.0/1", created[len(created)-1].ID}, {"128.0.0.0/1", created[len(created)-1].ID}, {req.WDTTNet, created[len(created)-2].ID}} {
		a.cloudflareProgress(jobID, "Creating route "+entry.network)
		var route struct {
			ID string `json:"id"`
		}
		body := map[string]string{"network": entry.network, "tunnel_id": entry.id, "virtual_network_id": vnetID, "comment": "wdtt-panel: managed test route"}
		if err := c.call(ctx, http.MethodPost, "teamnet/routes", body, &route); err != nil {
			return "", err
		}
		if !validCFUUID(route.ID) {
			return "", errors.New("invalid route ID returned by Cloudflare")
		}
		resource = cfOwnedResource{route.ID, "route", entry.network}
		if err := a.markCFResource(req.AccountID, vnetID, resource); err != nil {
			_ = c.call(ctx, http.MethodDelete, "teamnet/routes/"+route.ID, nil, nil)
			return "", err
		}
		created = append(created, resource)
	}
	return fmt.Sprintf("Cloudflare Mesh connected on %s and %s; three routes created in test account", req.IngressName, req.EgressName), nil
}

func validCFUUID(id string) bool {
	return regexp.MustCompile(`^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$`).MatchString(id)
}

func (a *App) installOwnedMesh(ctx context.Context, s Server, m node.MeshConfig) error {
	req := node.Request{Action: "mesh.install", Mesh: &m}
	var result node.Result
	if s.Transport == "local" {
		var err error
		result, err = node.Apply(ctx, req)
		if err != nil {
			return err
		}
	} else {
		payload, _ := json.Marshal(req)
		out, err := a.SSH.Run(ctx, s.target(), "/usr/local/bin/wdtt-panel node apply", payload)
		if err != nil {
			return fmt.Errorf("remote Mesh install failed: %w: %s", err, trim(string(out), 500))
		}
		if err := json.Unmarshal(out, &result); err != nil {
			return err
		}
	}
	observed, err := a.readStatus(ctx, s)
	if err == nil && (observed.MeshContainer != "running" || !strings.Contains(observed.MeshStatus, "Connected")) {
		err = errors.New("Mesh did not connect")
	}
	if err != nil {
		if result.RecoveryID != "" {
			_ = a.recover(ctx, s, result.RecoveryID)
		}
		return err
	}
	if result.RecoveryID != "" {
		if err := a.commit(ctx, s, result.RecoveryID); err != nil {
			return err
		}
	}
	return nil
}

func (a *App) uninstallOwnedMesh(ctx context.Context, s Server) error {
	if s.Transport == "local" {
		_, err := node.Apply(ctx, node.Request{Action: "mesh.uninstall"})
		return err
	}
	payload, _ := json.Marshal(node.Request{Action: "mesh.uninstall"})
	_, err := a.SSH.Run(ctx, s.target(), "/usr/local/bin/wdtt-panel node apply", payload)
	return err
}
