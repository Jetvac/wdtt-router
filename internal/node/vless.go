package node

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const vlessPath = "/etc/wdtt-panel/vless.json"
const vlessUnit = "/etc/systemd/system/wdtt-panel-vless-relay.service"
const xuiMeshDropin = "/etc/systemd/system/x-ui.service.d/wdtt-panel-mesh.conf"
const vlessRemark = "WDTT Panel Mesh Private"

type VLESSConfig struct {
	Profile   string `json:"profile,omitempty"`
	Port      int    `json:"port,omitempty"`
	MeshIP    string `json:"mesh_ip,omitempty"`
	UUID      string `json:"uuid,omitempty"`
	Gateway   string `json:"gateway,omitempty"`
	Bridge    string `json:"bridge,omitempty"`
	SourceIP  string `json:"source_ip,omitempty"`
	InboundID int64  `json:"inbound_id,omitempty"`
}

func newUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	s := hex.EncodeToString(b)
	return s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:], nil
}

var uuidPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// parsePrivateProfile accepts only the transport that the private Mesh relay
// actually implements. Rejecting extra parameters prevents a pasted profile
// from appearing to work while silently losing TLS, flow, or transport options.
func parsePrivateProfile(raw, meshIP string) (string, int, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u == nil || u.Scheme != "vless" || u.User == nil {
		return "", 0, errors.New("invalid VLESS link")
	}
	if u.User.Username() == "" || !uuidPattern.MatchString(u.User.Username()) {
		return "", 0, errors.New("invalid VLESS UUID")
	}
	if _, passwordSet := u.User.Password(); passwordSet {
		return "", 0, errors.New("VLESS link contains unsupported user password")
	}
	if net.ParseIP(u.Hostname()).To4() == nil || u.Hostname() != meshIP {
		return "", 0, errors.New("VLESS link must use this node's private Mesh IPv4")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return "", 0, errors.New("invalid VLESS port")
	}
	q := u.Query()
	for key := range q {
		if key != "encryption" && key != "security" && key != "type" {
			return "", 0, fmt.Errorf("unsupported VLESS option: %s", key)
		}
		if len(q[key]) != 1 {
			return "", 0, fmt.Errorf("duplicate VLESS option: %s", key)
		}
	}
	if q.Get("encryption") != "none" || q.Get("security") != "none" || q.Get("type") != "tcp" {
		return "", 0, errors.New("private Mesh VLESS requires encryption=none, security=none, type=tcp")
	}
	return strings.ToLower(u.User.Username()), port, nil
}

func (c VLESSConfig) shareLink() string {
	return fmt.Sprintf("vless://%s@%s:%d?encryption=none&security=none&type=tcp#WDTT-Mesh-Private", c.UUID, c.MeshIP, c.Port)
}

func readVLESS() (VLESSConfig, error) {
	var c VLESSConfig
	b, err := os.ReadFile(vlessPath)
	if err != nil {
		return c, err
	}
	err = json.Unmarshal(b, &c)
	return c, err
}

func meshForVLESS(ctx context.Context) (MeshConfig, string, error) {
	var m MeshConfig
	b, err := os.ReadFile("/etc/wdtt-panel/mesh.json")
	if err != nil {
		return m, "", errors.New("panel-managed Mesh is required")
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return m, "", err
	}
	m.defaults()
	if m.Role != "egress" {
		return m, "", errors.New("private VLESS endpoint must run on the egress node")
	}
	s := Inspect(ctx)
	if s.MeshContainer != "running" || net.ParseIP(s.MeshIP).To4() == nil {
		return m, "", errors.New("Mesh interface is not ready")
	}
	return m, s.MeshIP, nil
}

type xuiAPI struct {
	base   string
	token  string
	client *http.Client
}

func localXUI(ctx context.Context) (*xuiAPI, error) {
	if _, err := os.Stat("/etc/wdtt-panel/xui-owned.json"); err != nil {
		return nil, errors.New("3x-ui is not panel-owned")
	}
	settings, err := command(ctx, "/usr/local/x-ui/x-ui", "setting", "-show")
	if err != nil {
		return nil, errors.New("3x-ui settings unavailable")
	}
	port, path := "", "/"
	for _, line := range strings.Split(settings, "\n") {
		if strings.HasPrefix(line, "port:") {
			port = strings.TrimSpace(strings.TrimPrefix(line, "port:"))
		}
		if strings.HasPrefix(line, "webBasePath:") {
			path = strings.TrimSpace(strings.TrimPrefix(line, "webBasePath:"))
		}
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 || !regexp.MustCompile(`^/[A-Za-z0-9/_-]*$`).MatchString(path) {
		return nil, errors.New("invalid local 3x-ui API address")
	}
	tokenPath := "/etc/wdtt-panel/xui-api-token"
	tokenBytes, err := os.ReadFile(tokenPath)
	if errors.Is(err, os.ErrNotExist) {
		out, getErr := command(ctx, "/usr/local/x-ui/x-ui", "setting", "-tokenName", "wdtt-panel", "-getApiToken")
		if getErr != nil {
			return nil, errors.New("could not create 3x-ui API token")
		}
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(line, "apiToken:") {
				tokenBytes = []byte(strings.TrimSpace(strings.TrimPrefix(line, "apiToken:")))
			}
		}
		if len(tokenBytes) < 20 || len(tokenBytes) > 4096 {
			return nil, errors.New("3x-ui returned an invalid API token")
		}
		if err := os.WriteFile(tokenPath, tokenBytes, 0600); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	token := strings.TrimSpace(string(tokenBytes))
	if token == "" || strings.ContainsAny(token, "\r\n") {
		return nil, errors.New("invalid stored 3x-ui token")
	}
	return &xuiAPI{base: fmt.Sprintf("http://127.0.0.1:%d%s", p, strings.TrimSuffix(path, "/")), token: token, client: &http.Client{Timeout: 10 * time.Second}}, nil
}

type xuiReply struct {
	Success bool            `json:"success"`
	Obj     json.RawMessage `json:"obj"`
}

func (a *xuiAPI) request(ctx context.Context, method, path string, payload any) (xuiReply, error) {
	var body io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return xuiReply{}, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.base+path, body)
	if err != nil {
		return xuiReply{}, err
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return xuiReply{}, errors.New("local 3x-ui API unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return xuiReply{}, fmt.Errorf("3x-ui API returned HTTP %d", resp.StatusCode)
	}
	var reply xuiReply
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&reply); err != nil {
		return reply, errors.New("invalid 3x-ui API response")
	}
	if !reply.Success {
		return reply, errors.New("3x-ui API rejected operation")
	}
	return reply, nil
}

type xuiInbound struct {
	ID             int64           `json:"id"`
	Tag            string          `json:"tag"`
	Remark         string          `json:"remark"`
	Listen         string          `json:"listen"`
	Port           int             `json:"port"`
	Protocol       string          `json:"protocol"`
	Enable         bool            `json:"enable"`
	Settings       json.RawMessage `json:"settings"`
	StreamSettings json.RawMessage `json:"streamSettings"`
}

func xuiInboundMatches(inbound xuiInbound, c VLESSConfig) bool {
	if inbound.Remark != vlessRemark || inbound.Listen != c.Gateway || inbound.Port != c.Port || inbound.Protocol != "vless" {
		return false
	}
	var settings struct {
		Clients []struct {
			ID string `json:"id"`
		} `json:"clients"`
		Decryption string `json:"decryption"`
	}
	if err := json.Unmarshal(inbound.Settings, &settings); err != nil {
		var escaped string
		if json.Unmarshal(inbound.Settings, &escaped) != nil || json.Unmarshal([]byte(escaped), &settings) != nil {
			return false
		}
	}
	if settings.Decryption != "none" {
		return false
	}
	for _, client := range settings.Clients {
		if strings.EqualFold(client.ID, c.UUID) {
			return true
		}
	}
	return false
}

func xuiClientEnabled(inbound xuiInbound, c VLESSConfig) bool {
	var settings struct {
		Clients []struct {
			ID     string `json:"id"`
			Enable bool   `json:"enable"`
		} `json:"clients"`
	}
	if err := json.Unmarshal(inbound.Settings, &settings); err != nil {
		var escaped string
		if json.Unmarshal(inbound.Settings, &escaped) != nil || json.Unmarshal([]byte(escaped), &settings) != nil {
			return false
		}
	}
	for _, client := range settings.Clients {
		if strings.EqualFold(client.ID, c.UUID) {
			return client.Enable
		}
	}
	return false
}

func (a *xuiAPI) inbounds(ctx context.Context) ([]xuiInbound, error) {
	r, err := a.request(ctx, http.MethodGet, "/panel/api/inbounds/list", nil)
	if err != nil {
		return nil, err
	}
	var inbounds []xuiInbound
	if err := json.Unmarshal(r.Obj, &inbounds); err != nil {
		return nil, errors.New("invalid 3x-ui inbound list")
	}
	return inbounds, nil
}

func (a *xuiAPI) deleteInbound(ctx context.Context, id int64) error {
	_, err := a.request(ctx, http.MethodPost, "/panel/api/inbounds/del/"+strconv.FormatInt(id, 10), nil)
	return err
}

func xuiInboundPayload(c VLESSConfig) map[string]any {
	return map[string]any{
		"enable": true, "remark": vlessRemark, "listen": c.Gateway, "port": c.Port,
		"protocol": "vless", "expiryTime": 0, "total": 0,
		"settings":       map[string]any{"clients": []any{map[string]any{"id": c.UUID, "email": "wdtt-panel-mesh", "enable": true, "expiryTime": 0, "totalGB": 0, "flow": "", "level": 0}}, "decryption": "none", "fallbacks": []any{}},
		"streamSettings": map[string]any{"network": "tcp", "security": "none", "tcpSettings": map[string]any{"header": map[string]any{"type": "none"}}},
		"sniffing":       map[string]any{"enabled": true, "destOverride": []string{"http", "tls", "quic"}, "routeOnly": false},
	}
}

func EnableVLESS(ctx context.Context, requested VLESSConfig) (Result, error) {
	if _, err := os.Stat(vlessPath); err == nil {
		return Result{}, errors.New("private VLESS is already managed; disable it before changing the profile")
	} else if !errors.Is(err, os.ErrNotExist) {
		return Result{}, err
	}
	m, meshIP, err := meshForVLESS(ctx)
	if err != nil {
		return Result{}, err
	}
	c := VLESSConfig{MeshIP: meshIP, Gateway: m.Gateway, Bridge: m.Bridge, SourceIP: m.ContainerIP}
	if requested.Profile != "" {
		c.UUID, c.Port, err = parsePrivateProfile(requested.Profile, meshIP)
		if err != nil {
			return Result{}, err
		}
	} else {
		c.UUID, err = newUUID()
		if err != nil {
			return Result{}, err
		}
		c.Port = requested.Port
		if c.Port == 0 {
			c.Port = 24443
		}
	}
	if c.Port < 1024 || c.Port > 65535 || c.Port == 33553 || c.Port == 2096 {
		return Result{}, errors.New("invalid private VLESS port")
	}
	if _, err := exec.LookPath("socat"); err != nil {
		if err := run(ctx, "apt-get", "update", "-qq"); err != nil {
			return Result{}, err
		}
		if err := run(ctx, "apt-get", "install", "-y", "-qq", "socat"); err != nil {
			return Result{}, err
		}
	}
	api, err := localXUI(ctx)
	if err != nil {
		return Result{}, err
	}
	list, err := api.inbounds(ctx)
	if err != nil {
		return Result{}, err
	}
	for _, inbound := range list {
		if inbound.Remark == vlessRemark || inbound.Port == c.Port {
			return Result{}, errors.New("3x-ui inbound remark or port is already in use")
		}
	}
	if _, err := api.request(ctx, http.MethodPost, "/panel/api/inbounds/add", xuiInboundPayload(c)); err != nil {
		return Result{}, err
	}
	created := false
	defer func() {
		if !created {
			_ = removeVLESSRelay(context.Background(), c)
			if c.InboundID == 0 {
				if possible, err := api.inbounds(context.Background()); err == nil {
					for _, inbound := range possible {
						if xuiInboundMatches(inbound, c) {
							c.InboundID = inbound.ID
							break
						}
					}
				}
			}
			if c.InboundID != 0 {
				_ = api.deleteInbound(context.Background(), c.InboundID)
			}
		}
	}()
	for i := 0; i < 15; i++ {
		list, err = api.inbounds(ctx)
		if err == nil {
			for _, inbound := range list {
				if xuiInboundMatches(inbound, c) && inbound.Enable && xuiClientEnabled(inbound, c) {
					c.InboundID = inbound.ID
				}
			}
		}
		if c.InboundID != 0 && hostVLESSListener(ctx, c) {
			break
		}
		select {
		case <-ctx.Done():
			return Result{}, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	if c.InboundID == 0 || !hostVLESSListener(ctx, c) {
		return Result{}, errors.New("3x-ui private inbound did not become ready")
	}
	if err := os.WriteFile(vlessPath, Encode(c), 0600); err != nil {
		return Result{}, err
	}
	if err := installVLESSRelay(ctx, c); err != nil {
		return Result{}, err
	}
	if err := installXUIMeshOrdering(ctx); err != nil {
		return Result{}, err
	}
	ready := false
	for i := 0; i < 20; i++ {
		pid, pidErr := meshNamespacePID(ctx)
		if pidErr == nil {
			listeners, _ := command(ctx, "nsenter", "-t", pid, "-n", "ss", "-H", "-lnt")
			if strings.Contains(listeners, net.JoinHostPort(c.MeshIP, strconv.Itoa(c.Port))) {
				ready = true
				break
			}
		}
		select {
		case <-ctx.Done():
			return Result{}, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	if !ready {
		return Result{}, errors.New("private Mesh VLESS relay did not become ready")
	}
	userReady := false
	for i := 0; i < 10; i++ {
		if privateVLESSUserActive(c) {
			userReady = true
			break
		}
		select {
		case <-ctx.Done():
			return Result{}, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	if !userReady {
		return Result{}, errors.New("3x-ui VLESS user is not active")
	}
	created = true
	return Result{Message: "Private VLESS endpoint is listening only on the Mesh IP and relays to panel-owned 3x-ui", Secret: map[string]string{"profile": c.shareLink()}}, nil
}

func hostVLESSListener(ctx context.Context, c VLESSConfig) bool {
	listeners, err := command(ctx, "ss", "-H", "-lnt")
	return err == nil && strings.Contains(listeners, net.JoinHostPort(c.Gateway, strconv.Itoa(c.Port)))
}

func vlessFirewallArgs(c VLESSConfig) []string {
	return []string{"-i", c.Bridge, "-s", c.SourceIP + "/32", "-d", c.Gateway + "/32", "-p", "tcp", "--dport", strconv.Itoa(c.Port), "-m", "comment", "--comment", "wdtt-panel:vless-relay", "-j", "ACCEPT"}
}

func installVLESSRelay(ctx context.Context, c VLESSConfig) error {
	rule := vlessFirewallArgs(c)
	if err := run(ctx, "iptables", append([]string{"-C", "INPUT"}, rule...)...); err != nil {
		if err := run(ctx, "iptables", append([]string{"-I", "INPUT", "1"}, rule...)...); err != nil {
			return err
		}
	}
	unit := "[Unit]\nDescription=WDTT private Mesh VLESS relay\nAfter=docker.service x-ui.service\nWants=docker.service x-ui.service\n\n[Service]\nType=simple\nExecStart=/usr/local/bin/wdtt-panel node vless-relay\nRestart=always\nRestartSec=2\n\n[Install]\nWantedBy=multi-user.target\n"
	if err := os.WriteFile(vlessUnit, []byte(unit), 0644); err != nil {
		return err
	}
	if err := run(ctx, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	return run(ctx, "systemctl", "enable", "--now", filepath.Base(vlessUnit))
}

func installXUIMeshOrdering(ctx context.Context) error {
	if err := os.MkdirAll(filepath.Dir(xuiMeshDropin), 0755); err != nil {
		return err
	}
	content := "[Unit]\nAfter=docker.service\nWants=docker.service\n\n[Service]\nExecStartPre=/usr/local/bin/wdtt-panel node wait-mesh-bridge\nTimeoutStartSec=100\n"
	if err := os.WriteFile(xuiMeshDropin, []byte(content), 0644); err != nil {
		return err
	}
	return run(ctx, "systemctl", "daemon-reload")
}

func WaitMeshBridge(ctx context.Context) error {
	c, err := readVLESS()
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for i := 0; i < 40; i++ {
		addr, _ := command(ctx, "ip", "-4", "-o", "addr", "show", "dev", c.Bridge)
		if strings.Contains(addr, c.Gateway+"/") {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return errors.New("private Mesh bridge did not become ready for 3x-ui")
}

func removeVLESSRelay(ctx context.Context, c VLESSConfig) error {
	_ = run(ctx, "systemctl", "disable", "--now", filepath.Base(vlessUnit))
	_ = os.Remove(vlessUnit)
	_ = os.Remove(xuiMeshDropin)
	_ = run(ctx, "systemctl", "daemon-reload")
	rule := vlessFirewallArgs(c)
	for i := 0; i < 4; i++ {
		if run(ctx, "iptables", append([]string{"-C", "INPUT"}, rule...)...) != nil {
			break
		}
		if err := run(ctx, "iptables", append([]string{"-D", "INPUT"}, rule...)...); err != nil {
			return err
		}
	}
	return os.Remove(vlessPath)
}

func DisableVLESS(ctx context.Context) (Result, error) {
	c, err := readVLESS()
	if errors.Is(err, os.ErrNotExist) {
		return Result{Message: "Private VLESS is already disabled"}, nil
	}
	if err != nil {
		return Result{}, err
	}
	api, err := localXUI(ctx)
	if err != nil {
		return Result{}, err
	}
	list, err := api.inbounds(ctx)
	if err != nil {
		return Result{}, err
	}
	owned := false
	for _, inbound := range list {
		if inbound.ID == c.InboundID && xuiInboundMatches(inbound, c) {
			owned = true
		}
	}
	if !owned {
		return Result{}, errors.New("3x-ui inbound changed; manual review required before removal")
	}
	if err := api.deleteInbound(ctx, c.InboundID); err != nil {
		return Result{}, err
	}
	if err := removeVLESSRelay(ctx, c); err != nil && !errors.Is(err, os.ErrNotExist) {
		return Result{}, err
	}
	return Result{Message: "Private VLESS relay and panel-owned 3x-ui inbound removed"}, nil
}

func RepairVLESS(ctx context.Context) (Result, error) {
	c, err := readVLESS()
	if err != nil {
		return Result{}, errors.New("panel-owned private VLESS is not installed")
	}
	api, err := localXUI(ctx)
	if err != nil {
		return Result{}, err
	}
	list, err := api.inbounds(ctx)
	if err != nil {
		return Result{}, err
	}
	owned, active := false, false
	for _, inbound := range list {
		if inbound.ID == c.InboundID && xuiInboundMatches(inbound, c) && inbound.Enable {
			owned, active = true, xuiClientEnabled(inbound, c)
		}
	}
	if !owned {
		return Result{}, errors.New("private 3x-ui inbound changed; no repair performed")
	}
	if err := installXUIMeshOrdering(ctx); err != nil {
		return Result{}, err
	}
	if !active {
		if _, err := api.request(ctx, http.MethodPost, "/panel/api/clients/bulkEnable", map[string]any{"emails": []string{"wdtt-panel-mesh"}}); err != nil {
			return Result{}, err
		}
	}
	if !privateVLESSUserActive(c) {
		if err := WaitMeshBridge(ctx); err != nil {
			return Result{}, err
		}
		if err := run(ctx, "systemctl", "restart", "x-ui.service"); err != nil {
			return Result{}, err
		}
	}
	list, err = api.inbounds(ctx)
	if err != nil {
		return Result{}, err
	}
	for _, inbound := range list {
		if inbound.ID == c.InboundID && xuiInboundMatches(inbound, c) && inbound.Enable && xuiClientEnabled(inbound, c) {
			for i := 0; i < 10; i++ {
				if privateVLESSUserActive(c) {
					return Result{Message: "Panel-owned private VLESS user is active"}, nil
				}
				select {
				case <-ctx.Done():
					return Result{}, ctx.Err()
				case <-time.After(time.Second):
				}
			}
			return Result{}, errors.New("3x-ui user is enabled but Xray has not loaded it")
		}
	}
	return Result{}, errors.New("3x-ui VLESS user did not become active")
}

// VLESSRelay is the supervised process that follows Mesh container restarts.
// socat is placed in the Mesh network namespace and binds only its private IP.
func VLESSRelay(ctx context.Context) error {
	c, err := readVLESS()
	if err != nil {
		return err
	}
	if net.ParseIP(c.MeshIP).To4() == nil || c.Port < 1 || c.Port > 65535 {
		return errors.New("invalid private VLESS relay state")
	}
	for ctx.Err() == nil {
		pid, err := meshNamespacePID(ctx)
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(2 * time.Second):
			}
			continue
		}
		childCtx, stop := context.WithCancel(ctx)
		cmd := exec.CommandContext(childCtx, "nsenter", "-t", pid, "-n", "socat", fmt.Sprintf("TCP4-LISTEN:%d,bind=%s,reuseaddr,fork", c.Port, c.MeshIP), fmt.Sprintf("TCP4:%s:%d", c.Gateway, c.Port))
		if err := cmd.Start(); err != nil {
			stop()
			return err
		}
		finished := make(chan error, 1)
		go func() { finished <- cmd.Wait() }()
		ticker := time.NewTicker(2 * time.Second)
		loop := true
		for loop {
			select {
			case <-ctx.Done():
				loop = false
			case <-finished:
				loop = false
			case <-ticker.C:
				current, e := meshNamespacePID(ctx)
				if e != nil || current != pid {
					loop = false
				}
			}
		}
		ticker.Stop()
		stop()
		select {
		case <-finished:
		case <-time.After(2 * time.Second):
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(time.Second):
		}
	}
	return nil
}
