package node

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const routingPath = "/etc/wdtt-panel/routing.json"

func readRouting() (MeshConfig, bool) {
	var m MeshConfig
	b, err := os.ReadFile(routingPath)
	if err != nil {
		return m, false
	}
	if json.Unmarshal(b, &m) != nil {
		return MeshConfig{}, false
	}
	return m, true
}

func ApplyRouting(ctx context.Context, m MeshConfig) (Result, error) {
	b, err := os.ReadFile("/etc/wdtt-panel/mesh.json")
	if err != nil {
		return Result{}, errors.New("panel-managed Mesh is not installed")
	}
	var installed MeshConfig
	if err := json.Unmarshal(b, &installed); err != nil {
		return Result{}, err
	}
	if m.Role == "" && m.NodeID == "" {
		wdttNet := m.WDTTNet
		m = installed
		if wdttNet != "" {
			m.WDTTNet = wdttNet
		}
	}
	m.defaults()
	if err := m.validate(); err != nil {
		return Result{}, err
	}
	if installed.NodeID != m.NodeID || installed.Role != m.Role {
		return Result{}, errors.New("Mesh node identity/role mismatch")
	}
	s := Inspect(ctx)
	meshConnected := strings.Contains(s.MeshStatus, "Connected")
	if m.Role == "egress" && !meshConnected {
		meshConnected = probeMeshPeer(ctx, m) == nil
	}
	if s.MeshContainer != "running" || !meshConnected {
		return Result{}, errors.New("Mesh is not connected")
	}
	if m.Role == "ingress" && !s.WDTTInterface {
		return Result{}, errors.New("WDTT interface missing")
	}
	if m.Role == "egress" && m.ExternalIf == "" {
		main, _ := command(ctx, "ip", "-4", "route", "show", "table", "main", "default")
		fields := strings.Fields(main)
		for i, f := range fields {
			if f == "dev" && i+1 < len(fields) {
				m.ExternalIf = fields[i+1]
				break
			}
		}
		if m.ExternalIf == "" {
			return Result{}, errors.New("public egress interface not found")
		}
	}
	if err := preflightRouting(ctx, m); err != nil {
		return Result{}, err
	}
	previous, _ := os.ReadFile(routingPath)
	id, err := beginRecovery(ctx, "routing", previous)
	if err != nil {
		return Result{}, err
	}
	if old, ok := readRouting(); ok {
		_ = removeRoutingRaw(ctx, old)
	}
	m.MeshToken = ""
	newData, _ := json.Marshal(m)
	if err := os.WriteFile(routingPath, newData, 0600); err != nil {
		_ = Recover(ctx, id)
		return Result{}, err
	}
	if err := applyRoutingRaw(ctx, m); err != nil {
		_ = Recover(ctx, id)
		return Result{}, err
	}
	if err := ensureRoutingPersistence(ctx); err != nil {
		_ = Recover(ctx, id)
		return Result{}, err
	}
	if err := routingSelftest(ctx, m); err != nil {
		_ = Recover(ctx, id)
		return Result{}, err
	}
	s = Inspect(ctx)
	return Result{Message: "Selective routing applied; recovery timer awaiting controller confirmation", Status: &s, RecoveryID: id}, nil
}

func preflightRouting(ctx context.Context, m MeshConfig) error {
	if _, err := command(ctx, "ip", "link", "show", "dev", m.Bridge); err != nil {
		return errors.New("Mesh bridge missing")
	}
	forward, _ := command(ctx, "sysctl", "-n", "net.ipv4.ip_forward")
	if forward != "1" {
		return errors.New("IPv4 forwarding is disabled")
	}
	if m.Role == "ingress" {
		rules, _ := command(ctx, "ip", "-4", "rule", "show")
		for _, line := range strings.Split(rules, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), strconv.Itoa(m.RulePref)+":") {
				old, owned := readRouting()
				if !owned || old.RulePref != m.RulePref || old.RouteTable != m.RouteTable {
					return errors.New("routing rule priority already in use")
				}
			}
		}
		routes, _ := command(ctx, "ip", "-4", "route", "show", "table", strconv.Itoa(m.RouteTable))
		if routes != "" {
			if _, owned := readRouting(); !owned {
				return errors.New("routing table already in use")
			}
		}
	}
	return nil
}

func applyRoutingRaw(ctx context.Context, m MeshConfig) error {
	m.defaults()
	if old, ok := readRouting(); ok {
		_ = removeRoutingRaw(ctx, old)
	}
	if m.Role == "" {
		return nil
	}
	if err := m.validate(); err != nil {
		return err
	}
	if m.Role == "ingress" {
		addr, _ := command(ctx, "ip", "-4", "-o", "addr", "show", "dev", m.WDTTIf)
		wdttIP := ""
		parts := strings.Fields(addr)
		for i, f := range parts {
			if f == "inet" && i+1 < len(parts) {
				wdttIP = strings.Split(parts[i+1], "/")[0]
				break
			}
		}
		if wdttIP == "" {
			return errors.New("WDTT server address unavailable")
		}
		table := strconv.Itoa(m.RouteTable)
		if err := run(ctx, "ip", "-4", "route", "replace", m.WDTTNet, "dev", m.WDTTIf, "scope", "link", "src", wdttIP, "table", table); err != nil {
			return err
		}
		if err := run(ctx, "ip", "-4", "route", "replace", "default", "via", m.ContainerIP, "dev", m.Bridge, "table", table); err != nil {
			return err
		}
		if err := run(ctx, "ip", "-4", "rule", "add", "pref", strconv.Itoa(m.RulePref), "from", m.WDTTNet, "table", table); err != nil {
			return err
		}
		// Cloudflare accepts traffic from this Mesh node's IP. Translate WDTT
		// clients before they enter WARP so the edge can route them to egress.
		if err := EnsureIngressSNAT(ctx, m); err != nil {
			return err
		}
		_ = run(ctx, "iptables", "-N", "WDTT_PANEL_INGRESS")
		if err := run(ctx, "iptables", "-F", "WDTT_PANEL_INGRESS"); err != nil {
			return err
		}
		for _, args := range [][]string{
			{"-A", "WDTT_PANEL_INGRESS", "-i", m.WDTTIf, "-s", m.WDTTNet, "-o", m.Bridge, "-j", "ACCEPT"},
			{"-A", "WDTT_PANEL_INGRESS", "-i", m.Bridge, "-o", m.WDTTIf, "-d", m.WDTTNet, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
			{"-A", "WDTT_PANEL_INGRESS", "-i", m.WDTTIf, "-s", m.WDTTNet, "-j", "DROP"},
		} {
			if err := run(ctx, "iptables", args...); err != nil {
				return err
			}
		}
		for _, args := range [][]string{
			{"-i", m.WDTTIf, "-s", m.WDTTNet, "-m", "comment", "--comment", "wdtt-panel:ingress-out", "-j", "WDTT_PANEL_INGRESS"},
			{"-i", m.Bridge, "-o", m.WDTTIf, "-d", m.WDTTNet, "-m", "comment", "--comment", "wdtt-panel:ingress-in", "-j", "WDTT_PANEL_INGRESS"},
		} {
			if err := run(ctx, "iptables", append([]string{"-I", "FORWARD", "1"}, args...)...); err != nil {
				return err
			}
		}
	} else {
		if err := run(ctx, "ip", "-4", "route", "replace", m.WDTTNet, "via", m.ContainerIP, "dev", m.Bridge); err != nil {
			return err
		}
		_ = run(ctx, "iptables", "-N", "WDTT_PANEL_EGRESS")
		if err := run(ctx, "iptables", "-F", "WDTT_PANEL_EGRESS"); err != nil {
			return err
		}
		for _, args := range [][]string{
			{"-A", "WDTT_PANEL_EGRESS", "-i", m.Bridge, "-o", m.ExternalIf, "-j", "ACCEPT"},
			{"-A", "WDTT_PANEL_EGRESS", "-i", m.ExternalIf, "-o", m.Bridge, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
			{"-A", "WDTT_PANEL_EGRESS", "-j", "RETURN"},
		} {
			if err := run(ctx, "iptables", args...); err != nil {
				return err
			}
		}
		for _, args := range [][]string{
			{"-i", m.Bridge, "-m", "comment", "--comment", "wdtt-panel:egress-out", "-j", "WDTT_PANEL_EGRESS"},
			{"-i", m.ExternalIf, "-o", m.Bridge, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-m", "comment", "--comment", "wdtt-panel:egress-in", "-j", "WDTT_PANEL_EGRESS"},
		} {
			if err := run(ctx, "iptables", append([]string{"-I", "FORWARD", "1"}, args...)...); err != nil {
				return err
			}
		}
		for _, subnet := range []string{m.DockerNet, m.WDTTNet} {
			if err := run(ctx, "iptables", "-t", "nat", "-I", "POSTROUTING", "1", "-s", subnet, "-o", m.ExternalIf, "-m", "comment", "--comment", "wdtt-panel:egress-nat", "-j", "MASQUERADE"); err != nil {
				return err
			}
		}
		if err := EnsureReturnRoutes(ctx, m); err != nil {
			return err
		}
	}
	return nil
}

func removeRoutingRaw(ctx context.Context, m MeshConfig) error {
	if m.Role == "ingress" {
		removeIngressSNAT(ctx, m)
		for _, args := range [][]string{
			{"-i", m.WDTTIf, "-s", m.WDTTNet, "-m", "comment", "--comment", "wdtt-panel:ingress-out", "-j", "WDTT_PANEL_INGRESS"},
			{"-i", m.Bridge, "-o", m.WDTTIf, "-d", m.WDTTNet, "-m", "comment", "--comment", "wdtt-panel:ingress-in", "-j", "WDTT_PANEL_INGRESS"},
		} {
			_ = run(ctx, "iptables", append([]string{"-D", "FORWARD"}, args...)...)
		}
		_ = run(ctx, "iptables", "-F", "WDTT_PANEL_INGRESS")
		_ = run(ctx, "iptables", "-X", "WDTT_PANEL_INGRESS")
		_ = run(ctx, "ip", "-4", "rule", "del", "pref", strconv.Itoa(m.RulePref), "from", m.WDTTNet, "table", strconv.Itoa(m.RouteTable))
		_ = run(ctx, "ip", "-4", "route", "del", "default", "via", m.ContainerIP, "dev", m.Bridge, "table", strconv.Itoa(m.RouteTable))
		_ = run(ctx, "ip", "-4", "route", "del", m.WDTTNet, "dev", m.WDTTIf, "table", strconv.Itoa(m.RouteTable))
	} else if m.Role == "egress" {
		for _, args := range [][]string{
			{"-i", m.Bridge, "-m", "comment", "--comment", "wdtt-panel:egress-out", "-j", "WDTT_PANEL_EGRESS"},
			{"-i", m.ExternalIf, "-o", m.Bridge, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-m", "comment", "--comment", "wdtt-panel:egress-in", "-j", "WDTT_PANEL_EGRESS"},
		} {
			_ = run(ctx, "iptables", append([]string{"-D", "FORWARD"}, args...)...)
		}
		_ = run(ctx, "iptables", "-F", "WDTT_PANEL_EGRESS")
		_ = run(ctx, "iptables", "-X", "WDTT_PANEL_EGRESS")
		for _, subnet := range []string{m.DockerNet, m.WDTTNet} {
			_ = run(ctx, "iptables", "-t", "nat", "-D", "POSTROUTING", "-s", subnet, "-o", m.ExternalIf, "-m", "comment", "--comment", "wdtt-panel:egress-nat", "-j", "MASQUERADE")
		}
		_ = run(ctx, "ip", "-4", "route", "del", m.WDTTNet, "via", m.ContainerIP, "dev", m.Bridge)
	}
	return nil
}

func routingSelftest(ctx context.Context, m MeshConfig) error {
	if m.Role == "ingress" {
		_, netw, err := netParseCIDR(m.WDTTNet)
		if err != nil {
			return err
		}
		probe := netw
		route, err := command(ctx, "ip", "-4", "route", "get", "1.1.1.1", "from", probe, "iif", m.WDTTIf)
		if err != nil || !strings.Contains(route, "via "+m.ContainerIP) || !strings.Contains(route, "dev "+m.Bridge) {
			return fmt.Errorf("WDTT policy route check failed: %s", route)
		}
		main, _ := command(ctx, "ip", "-4", "route", "show", "table", "main", "default")
		if strings.Contains(main, "dev "+m.Bridge) {
			return errors.New("host default route unexpectedly points to Mesh")
		}
		if err := checkIngressSNAT(ctx, m); err != nil {
			return fmt.Errorf("WDTT Mesh source NAT missing: %w", err)
		}
	} else {
		route, _ := command(ctx, "ip", "-4", "route", "show", m.WDTTNet)
		if !strings.Contains(route, "via "+m.ContainerIP) {
			return errors.New("egress return route missing")
		}
	}
	return nil
}

func ingressSNATArgs(m MeshConfig) []string {
	return []string{"POSTROUTING", "-s", m.WDTTNet, "-o", "CloudflareWARP", "-m", "comment", "--comment", "wdtt-panel:ingress-snat", "-j", "MASQUERADE"}
}

func meshNamespacePID(ctx context.Context) (string, error) {
	pid, err := command(ctx, "docker", "inspect", "-f", "{{.State.Pid}}", "cloudflare-mesh")
	if err != nil || pid == "" || pid == "0" {
		return "", errors.New("Mesh namespace unavailable")
	}
	if _, err := strconv.Atoi(pid); err != nil {
		return "", errors.New("invalid Mesh namespace PID")
	}
	return pid, nil
}

func checkIngressSNAT(ctx context.Context, m MeshConfig) error {
	pid, err := meshNamespacePID(ctx)
	if err != nil {
		return err
	}
	args := append([]string{"-t", pid, "-n", "iptables", "-t", "nat", "-C"}, ingressSNATArgs(m)...)
	return run(ctx, "nsenter", args...)
}

func EnsureIngressSNAT(ctx context.Context, m MeshConfig) error {
	if m.Role != "ingress" {
		return nil
	}
	if checkIngressSNAT(ctx, m) == nil {
		return nil
	}
	pid, err := meshNamespacePID(ctx)
	if err != nil {
		return err
	}
	args := append([]string{"-t", pid, "-n", "iptables", "-t", "nat", "-I", "POSTROUTING", "1"}, ingressSNATArgs(m)[1:]...)
	return run(ctx, "nsenter", args...)
}

func removeIngressSNAT(ctx context.Context, m MeshConfig) {
	pid, err := meshNamespacePID(ctx)
	if err != nil {
		return
	}
	args := append([]string{"-t", pid, "-n", "iptables", "-t", "nat", "-D"}, ingressSNATArgs(m)...)
	_ = run(ctx, "nsenter", args...)
}

func netParseCIDR(cidr string) (string, string, error) {
	parts := strings.Split(cidr, "/")
	if len(parts) != 2 {
		return "", "", errors.New("invalid subnet")
	}
	ip := strings.Split(parts[0], ".")
	if len(ip) != 4 {
		return "", "", errors.New("invalid IPv4 subnet")
	}
	n, err := strconv.Atoi(ip[3])
	if err != nil || n >= 254 {
		return "", "", errors.New("invalid probe subnet")
	}
	ip[3] = strconv.Itoa(n + 2)
	return cidr, strings.Join(ip, "."), nil
}

func EnsureReturnRoutes(ctx context.Context, m MeshConfig) error {
	pid, err := command(ctx, "docker", "inspect", "-f", "{{.State.Pid}}", "cloudflare-mesh")
	if err != nil || pid == "" || pid == "0" {
		return errors.New("Mesh namespace unavailable")
	}
	rules, err := command(ctx, "nsenter", "-t", pid, "-n", "ip", "-4", "rule", "show")
	if err != nil {
		return err
	}
	re := regexp.MustCompile(`fwmark\s+0x100cf.*lookup\s+([A-Za-z0-9_]+)`)
	match := re.FindStringSubmatch(rules)
	if len(match) != 2 {
		return errors.New("CloudflareWARP routing table not found")
	}
	for _, cidr := range []string{"100.64.0.0/12", "100.96.0.0/12", m.WDTTNet} {
		if err := run(ctx, "nsenter", "-t", pid, "-n", "ip", "-4", "route", "replace", cidr, "dev", "CloudflareWARP", "table", match[1]); err != nil {
			return err
		}
	}
	return nil
}

func ensureRoutingPersistence(ctx context.Context) error {
	unit := `[Unit]
Description=WDTT Panel selective routing
After=network-online.target docker.service wdtt.service
Wants=network-online.target docker.service
StartLimitIntervalSec=0

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/wdtt-panel node restore-routing
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
`
	if err := os.WriteFile("/etc/systemd/system/wdtt-panel-routing.service", []byte(unit), 0644); err != nil {
		return err
	}
	if err := run(ctx, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := run(ctx, "systemctl", "enable", "wdtt-panel-routing.service"); err != nil {
		return err
	}
	if m, ok := readRouting(); ok && (m.Role == "ingress" || m.Role == "egress") {
		keeper := `[Unit]
Description=WDTT Panel Mesh return-route keeper
After=docker.service wdtt-panel-routing.service
Wants=docker.service

[Service]
ExecStart=/usr/local/bin/wdtt-panel node route-keeper
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
`
		if err := os.WriteFile("/etc/systemd/system/wdtt-panel-route-keeper.service", []byte(keeper), 0644); err != nil {
			return err
		}
		if err := run(ctx, "systemctl", "daemon-reload"); err != nil {
			return err
		}
		if err := run(ctx, "systemctl", "enable", "--now", "wdtt-panel-route-keeper.service"); err != nil {
			return err
		}
	}
	return nil
}

func RestoreRouting(ctx context.Context) error {
	m, ok := readRouting()
	if !ok {
		return nil
	}
	deadline := time.Now().Add(2 * time.Minute)
	for {
		if meshRoutingReady(ctx, m) {
			break
		}
		if time.Now().After(deadline) {
			return errors.New("Mesh routing did not become ready after boot")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	if err := applyRoutingRaw(ctx, m); err != nil {
		return err
	}
	return routingSelftest(ctx, m)
}

func meshRoutingReady(ctx context.Context, m MeshConfig) bool {
	pid, err := meshNamespacePID(ctx)
	if err != nil {
		return false
	}
	if _, err := command(ctx, "nsenter", "-t", pid, "-n", "ip", "link", "show", "dev", "CloudflareWARP"); err != nil {
		return false
	}
	rules, err := command(ctx, "nsenter", "-t", pid, "-n", "ip", "-4", "rule", "show")
	if err != nil || !strings.Contains(rules, "fwmark 0x100cf") {
		return false
	}
	if m.Role == "ingress" {
		if _, err := command(ctx, "ip", "link", "show", "dev", m.WDTTIf); err != nil {
			return false
		}
	}
	return true
}
func RouteKeeper(ctx context.Context) error {
	for {
		m, ok := readRouting()
		if ok {
			switch m.Role {
			case "ingress":
				_ = EnsureIngressSNAT(ctx, m)
			case "egress":
				_ = EnsureReturnRoutes(ctx, m)
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
}
