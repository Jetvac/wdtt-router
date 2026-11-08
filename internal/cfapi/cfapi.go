// Package cfapi is a small Cloudflare API client for the Mesh resources the
// panel manages: connector nodes, their tokens and the Mesh device profile.
package cfapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	reAccount = regexp.MustCompile(`^[a-f0-9]{32}$`)
	reTeam    = regexp.MustCompile(`^[a-z0-9-]{1,63}$`)
	reID      = regexp.MustCompile(`^[a-f0-9-]{32,36}$`)
)

// NormalizeTeam accepts "team", "team.cloudflareaccess.com" or a URL.
func NormalizeTeam(t string) string {
	t = strings.ToLower(strings.TrimSpace(t))
	t = strings.TrimPrefix(strings.TrimPrefix(t, "https://"), "http://")
	t, _, _ = strings.Cut(t, "/")
	return strings.TrimSuffix(t, ".cloudflareaccess.com")
}

// Client talks to one Cloudflare account.
type Client struct {
	Account, Token, Team string
	HTTP                 *http.Client
}

func New(account, token, team string) (*Client, error) {
	team = NormalizeTeam(team)
	if !reAccount.MatchString(account) {
		return nil, errors.New("Account ID must be 32 hex characters")
	}
	if !reTeam.MatchString(team) {
		return nil, errors.New("invalid Zero Trust team name")
	}
	if len(token) < 20 || len(token) > 512 || strings.ContainsAny(token, " \r\n") {
		return nil, errors.New("invalid API token")
	}
	return &Client{Account: account, Token: token, Team: team, HTTP: &http.Client{Timeout: 25 * time.Second}}, nil
}

type envelope struct {
	Success bool            `json:"success"`
	Result  json.RawMessage `json:"result"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
}

// APIError is a failed Cloudflare call.
type APIError struct {
	Status int
	Code   int
	Msg    string
}

func (e *APIError) Error() string {
	if e.Code != 0 {
		return fmt.Sprintf("Cloudflare API: %s (code %d, HTTP %d)", e.Msg, e.Code, e.Status)
	}
	return fmt.Sprintf("Cloudflare API: HTTP %d", e.Status)
}

func (c *Client) call(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://api.cloudflare.com/client/v4/accounts/"+c.Account+"/"+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("Cloudflare API unreachable: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return &APIError{Status: resp.StatusCode, Msg: "invalid response"}
	}
	if resp.StatusCode >= 300 || !env.Success {
		e := &APIError{Status: resp.StatusCode}
		if len(env.Errors) > 0 {
			e.Code, e.Msg = env.Errors[0].Code, env.Errors[0].Message
		}
		return e
	}
	if out != nil && len(env.Result) > 0 && string(env.Result) != "null" {
		return json.Unmarshal(env.Result, out)
	}
	return nil
}

// DeviceSettings are the account-wide client settings Mesh relies on.
type DeviceSettings struct {
	VirtualIP bool `json:"use_zt_virtual_ip"`
	TCPProxy  bool `json:"gateway_proxy_enabled"`
	UDPProxy  bool `json:"gateway_udp_proxy_enabled"`
}

func (c *Client) DeviceSettings(ctx context.Context) (DeviceSettings, error) {
	var s DeviceSettings
	err := c.call(ctx, http.MethodGet, "devices/settings", nil, &s)
	return s, err
}

func (c *Client) EnableMeshSettings(ctx context.Context) error {
	return c.call(ctx, http.MethodPatch, "devices/settings", map[string]bool{"use_zt_virtual_ip": true, "gateway_proxy_enabled": true, "gateway_udp_proxy_enabled": true}, nil)
}

// Connector is a Mesh node.
type Connector struct {
	ID              string  `json:"id"`
	Name            string  `json:"name"`
	Status          string  `json:"status"`
	CreatedAt       string  `json:"created_at"`
	DeletedAt       *string `json:"deleted_at"`
	ConnsActiveAt   *string `json:"conns_active_at"`
	ConnsInactiveAt *string `json:"conns_inactive_at"`
}

func (c *Client) Connectors(ctx context.Context) ([]Connector, error) {
	var list []Connector
	if err := c.call(ctx, http.MethodGet, "warp_connector?per_page=1000&is_deleted=false", nil, &list); err != nil {
		return nil, err
	}
	out := list[:0]
	for _, x := range list {
		if x.DeletedAt == nil || *x.DeletedAt == "" {
			out = append(out, x)
		}
	}
	return out, nil
}

func (c *Client) CreateConnector(ctx context.Context, name string) (Connector, error) {
	var n Connector
	err := c.call(ctx, http.MethodPost, "warp_connector", map[string]any{"name": name}, &n)
	if err == nil && !reID.MatchString(n.ID) {
		err = errors.New("Cloudflare returned an invalid node ID")
	}
	return n, err
}

func (c *Client) ConnectorToken(ctx context.Context, id string) (string, error) {
	if !reID.MatchString(id) {
		return "", errors.New("invalid node ID")
	}
	var tok string
	err := c.call(ctx, http.MethodGet, "warp_connector/"+id+"/token", nil, &tok)
	if err == nil && len(tok) < 20 {
		err = errors.New("Cloudflare returned an empty node token")
	}
	return tok, err
}

func (c *Client) DeleteConnector(ctx context.Context, id string) error {
	if !reID.MatchString(id) {
		return errors.New("invalid node ID")
	}
	err := c.call(ctx, http.MethodDelete, "warp_connector/"+id, nil, nil)
	var ae *APIError
	if errors.As(err, &ae) && ae.Status == http.StatusNotFound {
		return nil
	}
	return err
}

// Profile is a device profile (policy).
type Profile struct {
	ID         string `json:"policy_id"`
	Name       string `json:"name"`
	Enabled    bool   `json:"enabled"`
	Default    bool   `json:"default"`
	Match      string `json:"match"`
	Precedence int    `json:"precedence"`
	Mode       struct {
		Mode string `json:"mode"`
	} `json:"service_mode_v2"`
	Tunnel  string `json:"tunnel_protocol"`
	Include []struct {
		Address string `json:"address"`
	} `json:"include"`
	Exclude []struct {
		Address string `json:"address"`
	} `json:"exclude"`
}

func (c *Client) Profiles(ctx context.Context) ([]Profile, error) {
	var list []Profile
	err := c.call(ctx, http.MethodGet, "devices/policies", nil, &list)
	return list, err
}

func (c *Client) SetProfileEnabled(ctx context.Context, id string, enabled bool) error {
	if !reID.MatchString(id) {
		return errors.New("invalid profile ID")
	}
	return c.call(ctx, http.MethodPatch, "devices/policy/"+id, map[string]bool{"enabled": enabled}, nil)
}

// ProfileName is the profile the panel creates when the account has none.
const ProfileName = "WDTT Router Mesh"

func (c *Client) CreateMeshProfile(ctx context.Context, precedence int) (Profile, error) {
	var p Profile
	body := map[string]any{
		"name": ProfileName, "description": "Mesh nodes of WDTT Router: only the Mesh range goes through Cloudflare",
		"enabled": true, "precedence": precedence,
		"match":           `identity.email == "warp_connector@` + c.Team + `.cloudflareaccess.com"`,
		"service_mode_v2": map[string]string{"mode": "warp"}, "tunnel_protocol": "masque",
		"include": []map[string]string{
			{"address": "100.96.0.0/12", "description": "Mesh virtual IP range"},
			{"address": "2606:4700:cf1:1000::/64", "description": "Mesh virtual IPv6 range"},
		},
	}
	err := c.call(ctx, http.MethodPost, "devices/policy", body, &p)
	return p, err
}

// Check is one preflight result.
type Check struct {
	Key    string `json:"key"`
	OK     bool   `json:"ok"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
	Fix    string `json:"fix,omitempty"` // action the panel can perform
	FixArg string `json:"fix_arg,omitempty"`
}

// MatchesConnectors reports whether a profile applies to Mesh nodes.
func (p Profile) MatchesConnectors(team string) bool {
	return strings.Contains(p.Match, "warp_connector@"+team+".cloudflareaccess.com")
}

// SafeForMesh reports whether the profile routes only Mesh ranges through
// Cloudflare (Include mode). Full-tunnel profiles would send the whole host
// traffic of every node through Cloudflare and are rejected.
func (p Profile) SafeForMesh() bool {
	if len(p.Exclude) > 0 || len(p.Include) == 0 {
		return false
	}
	hasMesh := false
	for _, i := range p.Include {
		switch i.Address {
		case "0.0.0.0/0", "0.0.0.0/1", "128.0.0.0/1", "::/0":
			return false
		case "100.96.0.0/12":
			hasMesh = true
		}
	}
	return hasMesh && (p.Tunnel == "" || p.Tunnel == "masque") && p.Mode.Mode == "warp"
}

// EffectiveProfile returns the enabled profile with the lowest precedence
// that applies to Mesh nodes.
func EffectiveProfile(list []Profile, team string) *Profile {
	cand := []Profile{}
	for _, p := range list {
		if p.Enabled && !p.Default && p.MatchesConnectors(team) {
			cand = append(cand, p)
		}
	}
	sort.Slice(cand, func(i, j int) bool { return cand[i].Precedence < cand[j].Precedence })
	if len(cand) == 0 {
		return nil
	}
	return &cand[0]
}

// Preflight verifies everything Mesh needs in the account.
func (c *Client) Preflight(ctx context.Context) ([]Check, error) {
	checks := []Check{}
	s, err := c.DeviceSettings(ctx)
	if err != nil {
		return nil, err
	}
	ok := s.VirtualIP && s.TCPProxy && s.UDPProxy
	ch := Check{Key: "settings", OK: ok, Title: "Уникальные IP устройств и TCP/UDP-прокси Gateway"}
	if ok {
		ch.Detail = "Включены"
	} else {
		ch.Detail = "Нужны для Mesh: «Assign a unique IP address to each device» и прокси TCP/UDP."
		ch.Fix = "enable_settings"
	}
	checks = append(checks, ch)

	profiles, err := c.Profiles(ctx)
	if err != nil {
		return nil, err
	}
	eff := EffectiveProfile(profiles, c.Team)
	ch = Check{Key: "profile", Title: "Профиль устройств для узлов Mesh"}
	switch {
	case eff == nil:
		ch.Detail = "Профиль для узлов Mesh не найден. Панель создаст профиль «" + ProfileName + "» (только диапазон 100.96.0.0/12)."
		ch.Fix = "create_profile"
	case eff.SafeForMesh():
		ch.OK = true
		ch.Detail = fmt.Sprintf("«%s» (приоритет %d): через Cloudflare идёт только диапазон Mesh.", eff.Name, eff.Precedence)
	default:
		ch.Detail = fmt.Sprintf("Действует профиль «%s» (приоритет %d), который направляет через Cloudflare весь трафик сервера (full tunnel). Его нужно отключить.", eff.Name, eff.Precedence)
		ch.Fix = "disable_profile"
		ch.FixArg = eff.ID
	}
	checks = append(checks, ch)
	checks = append(checks, Check{Key: "reach", OK: true, Title: "Связь между устройствами (Allow all Cloudflare One traffic to reach enrolled devices)",
		Detail: "Этот параметр меняется только в панели Cloudflare. Панель проверит его фактически: TCP-соединением между узлами после подключения."})
	return checks, nil
}

// FreePrecedence finds an unused precedence below the account's Mesh profile.
func FreePrecedence(list []Profile) int {
	used := map[int]bool{}
	for _, p := range list {
		used[p.Precedence] = true
	}
	for p := 500; p < 10000; p++ {
		if !used[p] {
			return p
		}
	}
	return 9999
}
