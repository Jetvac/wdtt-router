package node

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type MeshConfig struct {
	Role        string `json:"role"`
	AccountID   string `json:"account_id"`
	VNetID      string `json:"vnet_id"`
	NodeID      string `json:"node_id"`
	NodeName    string `json:"node_name"`
	MeshToken   string `json:"mesh_token,omitempty"`
	WDTTIf      string `json:"wdtt_if"`
	WDTTNet     string `json:"wdtt_net"`
	Bridge      string `json:"bridge"`
	DockerNet   string `json:"docker_net"`
	Gateway     string `json:"gateway"`
	ContainerIP string `json:"container_ip"`
	Volume      string `json:"volume,omitempty"`
	ProbeHost   string `json:"probe_host,omitempty"`
	ProbePort   int    `json:"probe_port,omitempty"`
	ExternalIf  string `json:"external_if"`
	RouteTable  int    `json:"route_table"`
	RulePref    int    `json:"rule_pref"`
}

func (m *MeshConfig) defaults() {
	if m.WDTTIf == "" {
		m.WDTTIf = "wdtt0"
	}
	if m.WDTTNet == "" {
		m.WDTTNet = "10.66.66.0/24"
	}
	if m.Bridge == "" {
		m.Bridge = "wdttmesh0"
	}
	if m.DockerNet == "" {
		m.DockerNet = "172.31.255.0/29"
	}
	if m.Gateway == "" {
		m.Gateway = "172.31.255.1"
	}
	if m.ContainerIP == "" {
		m.ContainerIP = "172.31.255.2"
	}
	if m.Volume == "" {
		m.Volume = "wdtt_panel_mesh_data"
	}
	if m.ProbeHost == "" && m.Role == "egress" {
		if _, subnet, err := net.ParseCIDR(m.WDTTNet); err == nil {
			if ip := subnet.IP.To4(); ip != nil {
				ip[3]++
				m.ProbeHost = ip.String()
			}
		}
	}
	if m.ProbePort == 0 {
		m.ProbePort = 8443
	}
	if m.RouteTable == 0 {
		m.RouteTable = 51889
	}
	if m.RulePref == 0 {
		m.RulePref = 10667
	}
}

func (m MeshConfig) validate() error {
	if m.Role != "ingress" && m.Role != "egress" {
		return errors.New("invalid Mesh role")
	}
	if _, _, err := net.ParseCIDR(m.WDTTNet); err != nil {
		return errors.New("invalid WDTT subnet")
	}
	if _, _, err := net.ParseCIDR(m.DockerNet); err != nil {
		return errors.New("invalid Docker subnet")
	}
	for _, ip := range []string{m.Gateway, m.ContainerIP} {
		if net.ParseIP(ip) == nil {
			return errors.New("invalid Mesh address")
		}
	}
	if m.RouteTable < 1 || m.RouteTable == 253 || m.RouteTable == 254 || m.RouteTable == 255 || m.RulePref < 1 {
		return errors.New("invalid routing table or priority")
	}
	iface := regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,14}$`)
	if !iface.MatchString(m.WDTTIf) || !iface.MatchString(m.Bridge) {
		return errors.New("invalid interface name")
	}
	if m.ExternalIf != "" && !iface.MatchString(m.ExternalIf) {
		return errors.New("invalid external interface")
	}
	if m.ProbeHost != "" && net.ParseIP(m.ProbeHost).To4() == nil {
		return errors.New("invalid peer probe address")
	}
	if m.ProbePort < 1 || m.ProbePort > 65535 {
		return errors.New("invalid peer probe port")
	}
	return nil
}

func InstallMesh(ctx context.Context, m MeshConfig) (Result, error) {
	m.defaults()
	if err := m.validate(); err != nil {
		return Result{}, err
	}
	if m.NodeID == "" || m.AccountID == "" || m.VNetID == "" || m.NodeName == "" || m.MeshToken == "" {
		return Result{}, errors.New("Cloudflare IDs, name and connector token required")
	}
	if strings.ContainsAny(m.MeshToken, "\r\n") {
		return Result{}, errors.New("invalid Mesh token")
	}
	if _, err := os.Stat("/etc/wdtt-mesh-egress.conf"); err == nil {
		return Result{}, errors.New("legacy Mesh deployment detected; import before changing it")
	}
	if _, err := os.Stat("/etc/wdtt-panel/mesh.json"); err == nil {
		return Result{}, errors.New("panel Mesh deployment already exists")
	}
	if _, err := command(ctx, "docker", "inspect", "cloudflare-mesh"); err == nil {
		return Result{}, errors.New("unowned cloudflare-mesh container already exists")
	}
	if _, err := command(ctx, "docker", "network", "inspect", "wdtt-mesh-net"); err == nil {
		return Result{}, errors.New("unowned wdtt-mesh-net network already exists")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		if err := run(ctx, "apt-get", "update", "-qq"); err != nil {
			return Result{}, err
		}
		if err := run(ctx, "apt-get", "install", "-y", "-qq", "docker.io"); err != nil {
			return Result{}, err
		}
	}
	if err := run(ctx, "systemctl", "enable", "--now", "docker.service"); err != nil {
		return Result{}, err
	}
	if err := run(ctx, "docker", "pull", "cloudflare/mesh:latest"); err != nil {
		return Result{}, err
	}
	id, err := beginRecovery(ctx, "mesh", nil)
	if err != nil {
		return Result{}, err
	}
	if err := os.MkdirAll("/etc/wdtt-panel", 0700); err != nil {
		_ = Recover(ctx, id)
		return Result{}, err
	}
	if err := os.WriteFile("/etc/wdtt-panel/mesh.pending", []byte(m.NodeID), 0600); err != nil {
		_ = Recover(ctx, id)
		return Result{}, err
	}
	if err := os.WriteFile("/etc/wdtt-panel/mesh.env", []byte("MESH_NODE_TOKEN="+m.MeshToken+"\nSRCNAT_ENABLED="+strconv.FormatBool(m.Role == "egress")+"\n"), 0600); err != nil {
		_ = Recover(ctx, id)
		return Result{}, err
	}
	if err := run(ctx, "docker", "network", "create", "--driver", "bridge", "--subnet", m.DockerNet, "--gateway", m.Gateway, "--opt", "com.docker.network.bridge.name="+m.Bridge, "wdtt-mesh-net"); err != nil {
		_ = Recover(ctx, id)
		return Result{}, err
	}
	if err := run(ctx, "docker", "volume", "create", m.Volume); err != nil {
		_ = Recover(ctx, id)
		return Result{}, err
	}
	args := []string{"run", "-d", "--name", "cloudflare-mesh", "--restart", "unless-stopped", "--network", "wdtt-mesh-net", "--ip", m.ContainerIP, "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW", "--device", "/dev/net/tun:/dev/net/tun", "--sysctl", "net.ipv4.ip_forward=1", "--sysctl", "net.ipv6.conf.all.forwarding=1", "--sysctl", "net.ipv6.conf.default.forwarding=1", "--env-file", "/etc/wdtt-panel/mesh.env", "-v", m.Volume + ":/var/lib/cloudflare-warp", "cloudflare/mesh:latest"}
	if err := run(ctx, "docker", args...); err != nil {
		_ = Recover(ctx, id)
		return Result{}, err
	}
	_ = run(ctx, "docker", "exec", "cloudflare-mesh", "warp-cli", "--accept-tos", "connect")
	connected := false
	interfaceReady := false
	for i := 0; i < 30; i++ {
		v, _ := command(ctx, "docker", "exec", "cloudflare-mesh", "warp-cli", "--accept-tos", "status")
		if strings.Contains(v, "Connected") {
			connected = true
			break
		}
		if s := Inspect(ctx); s.MeshIP != "" {
			interfaceReady = true
		}
		select {
		case <-ctx.Done():
			return Result{}, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	if !connected && !interfaceReady {
		_ = Recover(ctx, id)
		return Result{}, errors.New("Mesh interface did not become ready; owned container rolled back")
	}
	m.MeshToken = ""
	b, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile("/etc/wdtt-panel/mesh.json", b, 0600); err != nil {
		_ = Recover(ctx, id)
		return Result{}, err
	}
	_ = os.Remove("/etc/wdtt-panel/mesh.pending")
	s := Inspect(ctx)
	return Result{Message: fmt.Sprintf("Mesh %s registered as %s; Cloudflare status awaiting controller verification", m.Role, m.NodeName), Status: &s, RecoveryID: id}, nil
}

func removeOwnedMesh(ctx context.Context) error {
	data, existing := os.ReadFile("/etc/wdtt-panel/mesh.json")
	_, pending := os.Stat("/etc/wdtt-panel/mesh.pending")
	if existing != nil && pending != nil {
		return nil
	}
	var m MeshConfig
	_ = json.Unmarshal(data, &m)
	m.defaults()
	_ = run(ctx, "docker", "rm", "-f", "cloudflare-mesh")
	_ = run(ctx, "docker", "network", "rm", "wdtt-mesh-net")
	_ = run(ctx, "docker", "volume", "rm", m.Volume)
	_ = os.Remove("/etc/wdtt-panel/mesh.json")
	_ = os.Remove("/etc/wdtt-panel/mesh.pending")
	_ = os.Remove("/etc/wdtt-panel/mesh.env")
	return nil
}

// RestartMesh recovers an unresponsive panel-owned connector without changing
// its Cloudflare registration, Docker volume, or routing configuration.
func RestartMesh(ctx context.Context) (Result, error) {
	if _, err := os.Stat("/etc/wdtt-panel/mesh.json"); err != nil {
		return Result{}, errors.New("Mesh is not panel-owned")
	}
	image, err := command(ctx, "docker", "inspect", "-f", "{{.Config.Image}}", "cloudflare-mesh")
	if err != nil || image != "cloudflare/mesh:latest" {
		return Result{}, errors.New("panel-owned Mesh container not found")
	}
	checkCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if err := run(checkCtx, "docker", "restart", "cloudflare-mesh"); err != nil {
		return Result{}, err
	}
	for checkCtx.Err() == nil {
		if report := Selftest(checkCtx); report.Passed {
			s := Inspect(checkCtx)
			return Result{Message: "Panel-owned Mesh container restarted; selftest passed", Status: &s}, nil
		}
		select {
		case <-checkCtx.Done():
			break
		case <-time.After(3 * time.Second):
		}
	}
	return Result{}, errors.New("Mesh did not pass selftest after restart; inspect node diagnostics")
}
