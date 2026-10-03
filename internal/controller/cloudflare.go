package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/Jetvac/wdtt-router/internal/auth"
)

type cfClient struct {
	accountID, token string
	http             *http.Client
}
type cfEnvelope struct {
	Success bool            `json:"success"`
	Result  json.RawMessage `json:"result"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	ResultInfo struct {
		TotalPages int `json:"total_pages"`
	} `json:"result_info"`
}
type cfRoute struct {
	ID        string  `json:"id"`
	Network   string  `json:"network"`
	TunnelID  string  `json:"tunnel_id"`
	VNetID    string  `json:"virtual_network_id"`
	DeletedAt *string `json:"deleted_at"`
}

type cfMeshNode struct {
	ID              string  `json:"id"`
	Name            string  `json:"name"`
	Status          string  `json:"status"`
	ConnsActiveAt   *string `json:"conns_active_at"`
	ConnsInactiveAt *string `json:"conns_inactive_at"`
}

func (a *App) cloudflareLive(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	var account string
	if err := a.Store.DB.QueryRow(`SELECT value FROM settings WHERE name='cloudflare_account_id'`).Scan(&account); err != nil {
		apiError(w, 400, "Cloudflare account not configured")
		return
	}
	token, err := a.Store.Secret("cloudflare:" + account)
	if err != nil {
		apiError(w, 400, "Cloudflare token not configured")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	client := cfClient{accountID: account, token: token, http: &http.Client{Timeout: 15 * time.Second}}
	var nodes []cfMeshNode
	if err := client.get(ctx, "warp_connector?per_page=100", &nodes); err != nil {
		apiError(w, 502, "Could not list Mesh nodes: "+err.Error())
		return
	}
	routes, err := client.routes(ctx)
	if err != nil {
		apiError(w, 502, "Could not list Mesh routes: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"account_id": account, "nodes": nodes, "routes": routes})
}

func (c cfClient) get(ctx context.Context, path string, target any) error {
	url := "https://api.cloudflare.com/client/v4/accounts/" + c.accountID + "/" + path
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Cloudflare HTTP %d", resp.StatusCode)
	}
	var envelope cfEnvelope
	if err := json.Unmarshal(b, &envelope); err != nil {
		return err
	}
	if !envelope.Success {
		if len(envelope.Errors) > 0 {
			return fmt.Errorf("Cloudflare API %d: %s", envelope.Errors[0].Code, envelope.Errors[0].Message)
		}
		return errors.New("Cloudflare API returned failure")
	}
	return json.Unmarshal(envelope.Result, target)
}

func (c cfClient) routes(ctx context.Context) ([]cfRoute, error) {
	var routes []cfRoute
	for page := 1; page <= 20; page++ {
		var batch []cfRoute
		if err := c.get(ctx, fmt.Sprintf("teamnet/routes?per_page=100&page=%d", page), &batch); err != nil {
			return nil, err
		}
		routes = append(routes, batch...)
		if len(batch) < 100 {
			break
		}
	}
	return routes, nil
}

func (a *App) saveCloudflare(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	var body struct {
		AccountID string `json:"account_id"`
		Team      string `json:"team"`
		Token     string `json:"token"`
	}
	if !decode(w, r, &body) {
		return
	}
	if !regexp.MustCompile(`^[a-fA-F0-9]{32}$`).MatchString(body.AccountID) || !regexp.MustCompile(`^[A-Za-z0-9-]{1,100}(\.cloudflareaccess\.com)?$`).MatchString(body.Team) || len(body.Token) < 20 || len(body.Token) > 512 {
		apiError(w, 400, "Invalid Cloudflare settings")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	client := cfClient{accountID: body.AccountID, token: body.Token, http: &http.Client{Timeout: 12 * time.Second}}
	if _, err := client.routes(ctx); err != nil {
		apiError(w, 400, "Cloudflare token could not list network routes: "+err.Error())
		return
	}
	if err := a.Store.PutSecret("cloudflare:"+body.AccountID, body.Token); err != nil {
		apiError(w, 500, "Could not store token")
		return
	}
	team := strings.TrimSuffix(body.Team, ".cloudflareaccess.com")
	_, err := a.Store.DB.Exec(`INSERT INTO settings(name,value) VALUES('cloudflare_account_id',?) ON CONFLICT(name) DO UPDATE SET value=excluded.value`, body.AccountID)
	if err == nil {
		_, err = a.Store.DB.Exec(`INSERT INTO settings(name,value) VALUES('cloudflare_team',?) ON CONFLICT(name) DO UPDATE SET value=excluded.value`, team)
	}
	if err != nil {
		apiError(w, 500, "Could not save Cloudflare settings")
		return
	}
	writeJSON(w, 200, map[string]any{"account_id": body.AccountID, "team": team, "token_saved": true})
}

func (a *App) cloudflareSettings(w http.ResponseWriter, _ *http.Request, _ auth.Session) {
	var account, team string
	_ = a.Store.DB.QueryRow(`SELECT value FROM settings WHERE name='cloudflare_account_id'`).Scan(&account)
	_ = a.Store.DB.QueryRow(`SELECT value FROM settings WHERE name='cloudflare_team'`).Scan(&team)
	writeJSON(w, 200, map[string]any{"account_id": account, "team": team, "token_saved": account != ""})
}

type routeConflict struct {
	Requested string  `json:"requested"`
	Existing  cfRoute `json:"existing"`
}

func overlap(a, b string) bool {
	ipA, netA, e1 := net.ParseCIDR(a)
	ipB, netB, e2 := net.ParseCIDR(b)
	return e1 == nil && e2 == nil && (netA.Contains(ipB) || netB.Contains(ipA))
}

func (a *App) meshPreflight(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	var body struct {
		AccountID string `json:"account_id"`
		WDTTNet   string `json:"wdtt_net"`
		VNetID    string `json:"vnet_id"`
	}
	if !decode(w, r, &body) {
		return
	}
	if body.AccountID == "" {
		_ = a.Store.DB.QueryRow(`SELECT value FROM settings WHERE name='cloudflare_account_id'`).Scan(&body.AccountID)
	}
	if !regexp.MustCompile(`^[a-fA-F0-9]{32}$`).MatchString(body.AccountID) {
		apiError(w, 400, "Cloudflare Account ID required")
		return
	}
	if body.WDTTNet == "" {
		body.WDTTNet = "10.66.66.0/24"
	}
	if _, _, err := net.ParseCIDR(body.WDTTNet); err != nil {
		apiError(w, 400, "Invalid WDTT subnet")
		return
	}
	token, err := a.Store.Secret("cloudflare:" + body.AccountID)
	if err != nil {
		apiError(w, 400, "Cloudflare token not configured")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	client := cfClient{accountID: body.AccountID, token: token, http: &http.Client{Timeout: 15 * time.Second}}
	routes, err := client.routes(ctx)
	if err != nil {
		apiError(w, 502, "Could not list Cloudflare routes: "+err.Error())
		return
	}
	requested := []string{"0.0.0.0/1", "128.0.0.0/1", body.WDTTNet}
	conflicts := []routeConflict{}
	for _, want := range requested {
		for _, route := range routes {
			if route.DeletedAt != nil && *route.DeletedAt != "" {
				continue
			}
			if body.VNetID != "" && route.VNetID != body.VNetID {
				continue
			}
			if overlap(want, route.Network) {
				conflicts = append(conflicts, routeConflict{Requested: want, Existing: route})
			}
		}
	}
	blockers := []string{}
	if body.VNetID != "" {
		blockers = append(blockers, "Cloudflare Mesh participants cannot currently select an isolated virtual network; routes there do not provide a verified Mesh datapath")
	}
	if len(conflicts) > 0 {
		blockers = append(blockers, "Overlapping routes already exist; panel will not alter or adopt them")
	}
	writeJSON(w, 200, map[string]any{"safe_to_create": len(blockers) == 0, "requested": requested, "conflicts": conflicts, "blockers": blockers, "existing_routes": len(routes)})
}
