package node

import (
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type Status struct {
	Hostname           string `json:"hostname"`
	OS                 string `json:"os"`
	Kernel             string `json:"kernel"`
	Uptime             string `json:"uptime"`
	Addresses          string `json:"addresses"`
	Routes             string `json:"routes"`
	Rules              string `json:"rules"`
	WDTTService        string `json:"wdtt_service"`
	WDTTImported       bool   `json:"wdtt_imported"`
	WDTTLegacy         bool   `json:"wdtt_legacy"`
	WDTTInterface      bool   `json:"wdtt_interface"`
	WDTTNetwork        string `json:"wdtt_network"`
	WDTTListeners      string `json:"wdtt_listeners"`
	DockerService      string `json:"docker_service"`
	MeshContainer      string `json:"mesh_container"`
	MeshStatus         string `json:"mesh_status"`
	MeshIP             string `json:"mesh_ip"`
	XUIService         string `json:"xui_service"`
	XUIVersion         string `json:"xui_version"`
	XUIWarpEnabled     bool   `json:"xui_warp_enabled"`
	XUIWarpReady       bool   `json:"xui_warp_ready"`
	VLESSEnabled       bool   `json:"vless_enabled"`
	VLESSReady         bool   `json:"vless_ready"`
	VLESSUserActive    bool   `json:"vless_user_active"`
	VLESSClientEnabled bool   `json:"vless_client_enabled"`
	VLESSClientReady   bool   `json:"vless_client_ready"`
	Firewall           string `json:"firewall"`
	ObservedAt         string `json:"observed_at"`
}

func command(ctx context.Context, name string, args ...string) (string, error) {
	c := exec.CommandContext(ctx, name, args...)
	b, err := c.Output()
	if len(b) > 128*1024 {
		return "", fmt.Errorf("output too large: %s", name)
	}
	return strings.TrimSpace(string(b)), err
}

func run(ctx context.Context, name string, args ...string) error {
	c := exec.CommandContext(ctx, name, args...)
	if b, err := c.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(b)))
	}
	return nil
}

func trim(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func Inspect(ctx context.Context) Status {
	s := Status{ObservedAt: time.Now().UTC().Format(time.RFC3339)}
	s.Hostname, _ = os.Hostname()
	osRelease, _ := os.ReadFile("/etc/os-release")
	for _, line := range strings.Split(string(osRelease), "\n") {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			s.OS = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
			break
		}
	}
	s.Kernel, _ = command(ctx, "uname", "-r")
	s.Uptime, _ = command(ctx, "uptime", "-p")
	s.Addresses, _ = command(ctx, "ip", "-br", "addr")
	s.Routes, _ = command(ctx, "ip", "-4", "route", "show", "table", "all")
	s.Rules, _ = command(ctx, "ip", "-4", "rule", "show")
	s.WDTTService, _ = command(ctx, "systemctl", "is-active", "wdtt.service")
	if _, err := os.Stat("/etc/wdtt-panel/wdtt-import.json"); err == nil {
		s.WDTTImported = true
	}
	if _, err := os.Stat("/etc/wdtt-mesh-egress.conf"); err == nil {
		s.WDTTLegacy = true
	}
	wdttAddr, err := command(ctx, "ip", "-4", "-o", "addr", "show", "dev", "wdtt0")
	s.WDTTInterface = err == nil && wdttAddr != ""
	if s.WDTTInterface {
		parts := strings.Fields(wdttAddr)
		for i, p := range parts {
			if p == "inet" && i+1 < len(parts) {
				s.WDTTNetwork = parts[i+1]
				break
			}
		}
	}
	listeners, _ := command(ctx, "ss", "-H", "-lun")
	for _, line := range strings.Split(listeners, "\n") {
		if strings.Contains(line, ":56000") || strings.Contains(line, ":56001") {
			s.WDTTListeners += line + "\n"
		}
	}
	s.DockerService, _ = command(ctx, "systemctl", "is-active", "docker.service")
	s.MeshContainer, _ = command(ctx, "docker", "inspect", "-f", "{{.State.Status}}", "cloudflare-mesh")
	if s.MeshContainer == "running" {
		mesh, _ := command(ctx, "docker", "exec", "cloudflare-mesh", "warp-cli", "--accept-tos", "status")
		s.MeshStatus = trim(mesh, 500)
		pid, _ := command(ctx, "docker", "inspect", "-f", "{{.State.Pid}}", "cloudflare-mesh")
		if pid != "" && pid != "0" {
			addr, _ := command(ctx, "nsenter", "-t", pid, "-n", "ip", "-4", "-o", "addr", "show", "dev", "CloudflareWARP")
			for _, p := range strings.Fields(addr) {
				if strings.HasPrefix(p, "100.") {
					s.MeshIP = strings.Split(p, "/")[0]
					break
				}
			}
		}
	}
	s.XUIService, _ = command(ctx, "systemctl", "is-active", "x-ui.service")
	if _, err := os.Stat("/usr/local/x-ui/x-ui"); err == nil {
		s.XUIVersion, _ = command(ctx, "/usr/local/x-ui/x-ui", "-v")
	}
	if b, err := os.ReadFile(xuiWarpMarker); err == nil {
		s.XUIWarpEnabled = true
		var marker warpMarker
		if json.Unmarshal(b, &marker) == nil && marker.InboundTag != "" && s.XUIService == "active" {
			s.XUIWarpReady = warpRouteLoaded(marker.InboundTag)
		}
	}
	if c, err := readVLESS(); err == nil {
		s.VLESSEnabled = true
		if s.MeshContainer == "running" {
			if pid, err := meshNamespacePID(ctx); err == nil {
				listeners, _ := command(ctx, "nsenter", "-t", pid, "-n", "ss", "-H", "-lnt")
				s.VLESSReady = strings.Contains(listeners, net.JoinHostPort(c.MeshIP, fmt.Sprint(c.Port)))
			}
		}
		s.VLESSUserActive = privateVLESSUserActive(c)
	}
	if _, err := os.Stat(vlessClientPath); err == nil {
		s.VLESSClientEnabled = true
		service, _ := command(ctx, "systemctl", "is-active", filepath.Base(vlessClientUnit))
		listeners, _ := command(ctx, "ss", "-H", "-lnt")
		s.VLESSClientReady = service == "active" && strings.Contains(listeners, ":12345")
	}
	filter, _ := command(ctx, "iptables", "-S")
	nat, _ := command(ctx, "iptables", "-t", "nat", "-S")
	for _, line := range strings.Split(filter+"\n"+nat, "\n") {
		if strings.Contains(line, "WDTT_PANEL") || strings.Contains(line, "wdtt-panel") {
			s.Firewall += line + "\n"
		}
	}
	return s
}

func privateVLESSUserActive(c VLESSConfig) bool {
	db, err := sql.Open("sqlite3", "file:/etc/x-ui/x-ui.db?mode=ro&_busy_timeout=2000")
	if err != nil {
		return false
	}
	defer db.Close()
	var enabled int
	if db.QueryRow(`SELECT enable FROM client_traffics WHERE inbound_id=? AND email='wdtt-panel-mesh'`, c.InboundID).Scan(&enabled) != nil || enabled != 1 {
		return false
	}
	b, err := os.ReadFile("/usr/local/x-ui/bin/config.json")
	if err != nil {
		return false
	}
	var generated struct {
		Inbounds []struct {
			Port     int `json:"port"`
			Settings struct {
				Clients []struct {
					ID string `json:"id"`
				} `json:"clients"`
			} `json:"settings"`
		} `json:"inbounds"`
	}
	if json.Unmarshal(b, &generated) != nil {
		return false
	}
	for _, inbound := range generated.Inbounds {
		if inbound.Port == c.Port {
			for _, client := range inbound.Settings.Clients {
				if strings.EqualFold(client.ID, c.UUID) {
					return true
				}
			}
		}
	}
	return false
}

type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}
type TestReport struct {
	Checks   []Check `json:"checks"`
	Passed   bool    `json:"passed"`
	TestedAt string  `json:"tested_at"`
}

func Selftest(ctx context.Context) TestReport {
	s := Inspect(ctx)
	m, routed := readRouting()
	if routed {
		m.defaults()
	}
	r := TestReport{Passed: true, TestedAt: time.Now().UTC().Format(time.RFC3339)}
	add := func(name string, ok bool, detail string) {
		r.Checks = append(r.Checks, Check{name, ok, detail})
		if !ok {
			r.Passed = false
		}
	}
	if s.WDTTService == "active" || (routed && m.Role == "ingress") {
		add("systemd WDTT", s.WDTTService == "active", s.WDTTService)
		add("wdtt0 interface", s.WDTTInterface, s.WDTTNetwork)
		add("WDTT public UDP listener", strings.Contains(s.WDTTListeners, ":56000"), strings.TrimSpace(s.WDTTListeners))
	}
	if _, err := os.Stat("/etc/wdtt-panel/mesh.json"); err == nil {
		add("Mesh container", s.MeshContainer == "running", s.MeshContainer)
		peerOK := false
		if routed && m.Role == "egress" && s.MeshContainer == "running" {
			if err := probeMeshPeer(ctx, m); err == nil {
				peerOK = true
				add("Mesh peer TCP", true, net.JoinHostPort(m.ProbeHost, fmt.Sprint(m.ProbePort)))
			} else {
				add("Mesh peer TCP", false, checkDetail(err))
			}
		}
		add("Cloudflare client", strings.Contains(s.MeshStatus, "Connected") || peerOK, s.MeshStatus)
	}
	if s.VLESSEnabled {
		add("private Mesh VLESS relay", s.VLESSReady, "Mesh listener")
		add("private 3x-ui VLESS user", s.VLESSUserActive, "enabled in 3x-ui and loaded by Xray")
	}
	if s.VLESSClientEnabled {
		add("WDTT transparent VLESS client", s.VLESSClientReady, "Xray listener")
		jump, _ := command(ctx, "iptables", "-t", "mangle", "-S", "PREROUTING")
		add("WDTT VLESS interception", strings.Contains(jump, "wdtt-panel:vless-client"), "WDTT interface rule")
	}
	if routed {
		err := routingSelftest(ctx, m)
		add("selective Mesh routing", err == nil, checkDetail(err))
		if m.Role == "ingress" && s.WDTTInterface {
			source := strings.Split(s.WDTTNetwork, "/")[0]
			ip, err := probeTCPFromWDTT(ctx, source)
			if err == nil {
				add("WDTT TCP public egress", true, ip)
			} else {
				add("WDTT TCP public egress", false, checkDetail(err))
			}
			err = probeDNSFromWDTT(ctx, source)
			add("WDTT UDP DNS", err == nil, checkDetail(err))
		}
	}
	return r
}

func probeMeshPeer(ctx context.Context, m MeshConfig) error {
	pid, err := meshNamespacePID(ctx)
	if err != nil {
		return err
	}
	url := fmt.Sprintf("https://%s:%d/", m.ProbeHost, m.ProbePort)
	return run(ctx, "nsenter", "-t", pid, "-n", "curl", "-k", "-sS", "-o", "/dev/null", "--connect-timeout", "5", "--max-time", "8", "--fail", url)
}

func checkDetail(err error) string {
	if err != nil {
		return err.Error()
	}
	return "ok"
}

func probeTCPFromWDTT(ctx context.Context, source string) (string, error) {
	ip := net.ParseIP(source).To4()
	if ip == nil {
		return "", fmt.Errorf("invalid WDTT source address")
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		Proxy:       nil,
		DialContext: (&net.Dialer{LocalAddr: &net.TCPAddr{IP: ip}, Timeout: 6 * time.Second}).DialContext,
	}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://1.1.1.1/cdn-cgi/trace", nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "ip=") {
			seen := strings.TrimSpace(strings.TrimPrefix(line, "ip="))
			if net.ParseIP(seen).To4() != nil {
				return seen, nil
			}
		}
	}
	return "", fmt.Errorf("public egress IP missing")
}

func probeDNSFromWDTT(ctx context.Context, source string) error {
	ip := net.ParseIP(source).To4()
	if ip == nil {
		return fmt.Errorf("invalid WDTT source address")
	}
	c, err := net.DialUDP("udp4", &net.UDPAddr{IP: ip}, &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 53})
	if err != nil {
		return err
	}
	defer c.Close()
	deadline := time.Now().Add(6 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = c.SetDeadline(deadline)
	question := []byte{0x4d, 0x53, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	if _, err := c.Write(question); err != nil {
		return err
	}
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		return err
	}
	if n < 12 || binary.BigEndian.Uint16(buf[:2]) != 0x4d53 || binary.BigEndian.Uint16(buf[6:8]) == 0 || buf[3]&0x0f != 0 {
		return fmt.Errorf("invalid UDP DNS response")
	}
	return nil
}

func Encode(v any) []byte { b, _ := json.Marshal(v); return b }
