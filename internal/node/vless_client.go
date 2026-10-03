package node

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const vlessClientPath = "/etc/wdtt-panel/vless-client.json"
const vlessClientXrayPath = "/etc/wdtt-panel/vless-client-xray.json"
const vlessClientBinary = "/usr/local/lib/wdtt-panel/xray"
const vlessClientUnit = "/etc/systemd/system/wdtt-panel-vless-client.service"
const vlessClientRoutingUnit = "/etc/systemd/system/wdtt-panel-vless-client-routing.service"
const vlessClientChain = "WDTT_PANEL_VLESS"
const vlessClientTable = "51888"
const vlessClientPref = "10666"
const vlessClientMark = "0x6677/0xffff"
const xrayZipURL = "https://github.com/XTLS/Xray-core/releases/download/v26.9.9/Xray-linux-64.zip"
const xrayZipSHA256 = "1eb9175d0f0a8f8149c9230a7fc5ae66ce332ed20a53155ce61fe62e3f58b7df"
const xrayBinarySHA256 = "c4ae6798c38e0e5343b192406746333cd0ba7ff3eb984f8c4b9939dcb68c3f8a"

type VLESSClientConfig struct {
	Profile string `json:"profile,omitempty"`
	MeshIP  string `json:"mesh_ip,omitempty"`
	UUID    string `json:"uuid,omitempty"`
	Port    int    `json:"port,omitempty"`
	WDTTIf  string `json:"wdtt_if,omitempty"`
	WDTTNet string `json:"wdtt_net,omitempty"`
	WDTTIP  string `json:"wdtt_ip,omitempty"`
}

func parseClientProfile(raw string) (VLESSClientConfig, error) {
	var c VLESSClientConfig
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u == nil || u.Scheme != "vless" {
		return c, errors.New("invalid VLESS profile")
	}
	ip := net.ParseIP(u.Hostname()).To4()
	_, privateMesh, _ := net.ParseCIDR("100.64.0.0/10")
	if ip == nil || !privateMesh.Contains(ip) {
		return c, errors.New("VLESS endpoint must be a private Cloudflare Mesh IPv4")
	}
	c.UUID, c.Port, err = parsePrivateProfile(raw, ip.String())
	if err != nil {
		return VLESSClientConfig{}, err
	}
	c.MeshIP = ip.String()
	return c, nil
}

func ensureXrayCore(ctx context.Context) error {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return errors.New("pinned Xray build supports only Linux amd64")
	}
	if b, err := os.ReadFile(vlessClientBinary); err == nil {
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) == xrayBinarySHA256 {
			return nil
		}
		return errors.New("existing Xray binary differs from pinned release")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, xrayZipURL, nil)
	if err != nil {
		return err
	}
	resp, err := (&http.Client{Timeout: 90 * time.Second}).Do(req)
	if err != nil {
		return errors.New("pinned Xray download failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("pinned Xray download HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 80<<20))
	if err != nil || len(b) == 0 || len(b) >= 80<<20 {
		return errors.New("invalid Xray archive size")
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != xrayZipSHA256 {
		return errors.New("pinned Xray archive checksum mismatch")
	}
	archive, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return errors.New("invalid Xray archive")
	}
	for _, file := range archive.File {
		if file.Name != "xray" || file.UncompressedSize64 > 64<<20 {
			continue
		}
		r, err := file.Open()
		if err != nil {
			return err
		}
		binary, readErr := io.ReadAll(io.LimitReader(r, 64<<20))
		_ = r.Close()
		if readErr != nil {
			return readErr
		}
		binarySum := sha256.Sum256(binary)
		if hex.EncodeToString(binarySum[:]) != xrayBinarySHA256 {
			return errors.New("pinned Xray executable checksum mismatch")
		}
		if err := os.MkdirAll(filepath.Dir(vlessClientBinary), 0755); err != nil {
			return err
		}
		tmp := vlessClientBinary + ".new"
		if err := os.WriteFile(tmp, binary, 0755); err != nil {
			return err
		}
		return os.Rename(tmp, vlessClientBinary)
	}
	return errors.New("Xray executable missing from pinned archive")
}

func vlessClientXrayConfig(c VLESSClientConfig) map[string]any {
	return map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"listen": "0.0.0.0", "port": 12345, "protocol": "tunnel", "tag": "wdtt-transparent",
			"settings":       map[string]any{"allowedNetwork": "tcp,udp", "followRedirect": true, "userLevel": 0},
			"streamSettings": map[string]any{"sockopt": map[string]any{"tproxy": "tproxy"}},
		}},
		"outbounds": []any{map[string]any{
			"protocol": "vless", "tag": "wdtt-mesh-egress", "sendThrough": c.WDTTIP,
			"settings":       map[string]any{"address": c.MeshIP, "port": c.Port, "id": c.UUID, "encryption": "none", "flow": ""},
			"streamSettings": map[string]any{"network": "tcp", "security": "none", "tcpSettings": map[string]any{"header": map[string]any{"type": "none"}}},
		}},
	}
}

func vlessClientPreflight(ctx context.Context, c VLESSClientConfig) error {
	if _, err := os.Stat(vlessClientPath); err == nil {
		return errors.New("WDTT VLESS client already enabled")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if _, err := command(ctx, "ip", "link", "show", "dev", c.WDTTIf); err != nil {
		return errors.New("WDTT interface missing")
	}
	rules, _ := command(ctx, "ip", "-4", "rule", "show")
	for _, line := range strings.Split(rules, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), vlessClientPref+":") {
			return errors.New("VLESS policy rule priority is already in use")
		}
	}
	routes, _ := command(ctx, "ip", "-4", "route", "show", "table", vlessClientTable)
	if routes != "" {
		return errors.New("VLESS policy routing table is already in use")
	}
	if _, err := command(ctx, "iptables", "-t", "mangle", "-S", vlessClientChain); err == nil {
		return errors.New("VLESS firewall chain is already in use")
	}
	if _, err := os.Stat(vlessClientUnit); err == nil {
		return errors.New("VLESS service unit is already in use")
	}
	return nil
}

func EnableVLESSClient(ctx context.Context, requested VLESSClientConfig) (result Result, retErr error) {
	c, err := parseClientProfile(requested.Profile)
	if err != nil {
		return Result{}, err
	}
	m, routed := readRouting()
	if !routed || m.Role != "ingress" {
		return Result{}, errors.New("WDTT ingress Mesh routing is required")
	}
	m.defaults()
	s := Inspect(ctx)
	if s.WDTTService != "active" || !s.WDTTInterface || s.MeshContainer != "running" {
		return Result{}, errors.New("WDTT or Mesh is not ready")
	}
	c.WDTTIf, c.WDTTNet, c.WDTTIP = m.WDTTIf, m.WDTTNet, strings.Split(s.WDTTNetwork, "/")[0]
	if net.ParseIP(c.WDTTIP).To4() == nil {
		return Result{}, errors.New("WDTT IPv4 address unavailable")
	}
	if err := vlessClientPreflight(ctx, c); err != nil {
		return Result{}, err
	}
	if err := ensureXrayCore(ctx); err != nil {
		return Result{}, err
	}
	config, err := json.Marshal(vlessClientXrayConfig(c))
	if err != nil {
		return Result{}, err
	}
	if err := os.WriteFile(vlessClientXrayPath, config, 0600); err != nil {
		return Result{}, err
	}
	if err := run(ctx, vlessClientBinary, "run", "-test", "-c", vlessClientXrayPath); err != nil {
		_ = os.Remove(vlessClientXrayPath)
		return Result{}, errors.New("Xray rejected generated transparent client configuration")
	}
	id, err := beginRecovery(ctx, "vless-client", nil)
	if err != nil {
		_ = os.Remove(vlessClientXrayPath)
		return Result{}, err
	}
	defer func() {
		if retErr != nil {
			cleanCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if Recover(cleanCtx, id) == nil {
				_ = CommitRecovery(cleanCtx, id)
			}
		}
	}()
	if err := os.WriteFile(vlessClientPath, Encode(c), 0600); err != nil {
		return Result{}, err
	}
	unit := "[Unit]\nDescription=WDTT transparent VLESS client\nAfter=network-online.target docker.service wdtt.service\nWants=network-online.target docker.service wdtt.service\n\n[Service]\nType=simple\nExecStart=" + vlessClientBinary + " run -c " + vlessClientXrayPath + "\nRestart=always\nRestartSec=2\n\n[Install]\nWantedBy=multi-user.target\n"
	if err := os.WriteFile(vlessClientUnit, []byte(unit), 0644); err != nil {
		return Result{}, err
	}
	routingUnit := "[Unit]\nDescription=WDTT transparent VLESS routing\nAfter=wdtt.service wdtt-panel-vless-client.service\nWants=wdtt.service wdtt-panel-vless-client.service\n\n[Service]\nType=oneshot\nExecStart=/usr/local/bin/wdtt-panel node restore-vless-client\nRemainAfterExit=yes\nRestart=on-failure\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n"
	if err := os.WriteFile(vlessClientRoutingUnit, []byte(routingUnit), 0644); err != nil {
		return Result{}, err
	}
	if err := run(ctx, "systemctl", "daemon-reload"); err != nil {
		return Result{}, err
	}
	if err := run(ctx, "systemctl", "enable", "--now", filepath.Base(vlessClientUnit)); err != nil {
		return Result{}, err
	}
	ready := false
	for i := 0; i < 15; i++ {
		listeners, _ := command(ctx, "ss", "-H", "-lnt")
		if strings.Contains(listeners, ":12345") {
			ready = true
			break
		}
		select {
		case <-ctx.Done():
			return Result{}, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	if !ready {
		return Result{}, errors.New("transparent Xray client did not start")
	}
	if err := run(ctx, "systemctl", "enable", "--now", filepath.Base(vlessClientRoutingUnit)); err != nil {
		return Result{}, err
	}
	if _, err := probeSyntheticTPROXY(ctx); err != nil {
		return Result{}, fmt.Errorf("WDTT transparent TCP/UDP probe failed: %w", err)
	}
	return Result{Message: "WDTT TCP and UDP now traverse private Mesh VLESS and 3x-ui; synthetic transparent probe passed", RecoveryID: id, Secret: map[string]string{"profile": requested.Profile}}, nil
}

func vlessJumpArgs(c VLESSClientConfig) []string {
	return []string{"-i", c.WDTTIf, "-s", c.WDTTNet, "-m", "comment", "--comment", "wdtt-panel:vless-client", "-j", vlessClientChain}
}

func vlessInputArgs(proto string) []string {
	return []string{"-p", proto, "--dport", "12345", "-m", "mark", "!", "--mark", vlessClientMark, "-m", "comment", "--comment", "wdtt-panel:vless-input", "-j", "DROP"}
}

func RestoreVLESSClient(ctx context.Context) error {
	b, err := os.ReadFile(vlessClientPath)
	if err != nil {
		return err
	}
	var c VLESSClientConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return err
	}
	if c.WDTTIf == "" || c.WDTTNet == "" || c.Port < 1 || !uuidPattern.MatchString(c.UUID) {
		return errors.New("invalid saved VLESS client")
	}
	if _, err := command(ctx, "ip", "link", "show", "dev", c.WDTTIf); err != nil {
		return errors.New("WDTT interface not ready")
	}
	if _, err := command(ctx, "iptables", "-t", "mangle", "-S", vlessClientChain); err != nil {
		if err := run(ctx, "iptables", "-t", "mangle", "-N", vlessClientChain); err != nil {
			return err
		}
	}
	if err := run(ctx, "iptables", "-t", "mangle", "-F", vlessClientChain); err != nil {
		return err
	}
	for _, cidr := range []string{c.WDTTNet, "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32"} {
		if err := run(ctx, "iptables", "-t", "mangle", "-A", vlessClientChain, "-d", cidr, "-j", "RETURN"); err != nil {
			return err
		}
	}
	for _, proto := range []string{"tcp", "udp"} {
		if err := run(ctx, "iptables", "-t", "mangle", "-A", vlessClientChain, "-p", proto, "-j", "TPROXY", "--on-port", "12345", "--tproxy-mark", vlessClientMark); err != nil {
			return err
		}
	}
	_ = run(ctx, "ip", "-4", "rule", "del", "pref", vlessClientPref, "fwmark", vlessClientMark, "table", vlessClientTable)
	if err := run(ctx, "ip", "-4", "route", "replace", "local", "default", "dev", "lo", "table", vlessClientTable); err != nil {
		return err
	}
	if err := run(ctx, "ip", "-4", "rule", "add", "pref", vlessClientPref, "fwmark", vlessClientMark, "table", vlessClientTable); err != nil {
		return err
	}
	jump := vlessJumpArgs(c)
	if run(ctx, "iptables", append([]string{"-t", "mangle", "-C", "PREROUTING"}, jump...)...) != nil {
		if err := run(ctx, "iptables", append([]string{"-t", "mangle", "-I", "PREROUTING", "1"}, jump...)...); err != nil {
			return err
		}
	}
	for _, proto := range []string{"tcp", "udp"} {
		input := vlessInputArgs(proto)
		if run(ctx, "iptables", append([]string{"-C", "INPUT"}, input...)...) != nil {
			if err := run(ctx, "iptables", append([]string{"-I", "INPUT", "1"}, input...)...); err != nil {
				return err
			}
		}
	}
	return nil
}

func removeVLESSClient(ctx context.Context) error {
	b, err := os.ReadFile(vlessClientPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var c VLESSClientConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return err
	}
	_ = run(ctx, "systemctl", "disable", "--now", filepath.Base(vlessClientRoutingUnit))
	_ = run(ctx, "systemctl", "disable", "--now", filepath.Base(vlessClientUnit))
	jump := vlessJumpArgs(c)
	for i := 0; i < 4; i++ {
		if run(ctx, "iptables", append([]string{"-t", "mangle", "-C", "PREROUTING"}, jump...)...) != nil {
			break
		}
		if err := run(ctx, "iptables", append([]string{"-t", "mangle", "-D", "PREROUTING"}, jump...)...); err != nil {
			return err
		}
	}
	for _, proto := range []string{"tcp", "udp"} {
		input := vlessInputArgs(proto)
		for i := 0; i < 4; i++ {
			if run(ctx, "iptables", append([]string{"-C", "INPUT"}, input...)...) != nil {
				break
			}
			if err := run(ctx, "iptables", append([]string{"-D", "INPUT"}, input...)...); err != nil {
				return err
			}
		}
	}
	_ = run(ctx, "iptables", "-t", "mangle", "-F", vlessClientChain)
	_ = run(ctx, "iptables", "-t", "mangle", "-X", vlessClientChain)
	_ = run(ctx, "ip", "-4", "rule", "del", "pref", vlessClientPref, "fwmark", vlessClientMark, "table", vlessClientTable)
	_ = run(ctx, "ip", "-4", "route", "flush", "table", vlessClientTable)
	_ = os.Remove(vlessClientRoutingUnit)
	_ = os.Remove(vlessClientUnit)
	_ = run(ctx, "systemctl", "daemon-reload")
	_ = os.Remove(vlessClientXrayPath)
	return os.Remove(vlessClientPath)
}

func DisableVLESSClient(ctx context.Context) (Result, error) {
	if err := removeVLESSClient(ctx); err != nil {
		return Result{}, err
	}
	return Result{Message: "WDTT transparent VLESS routing disabled and direct Mesh path restored"}, nil
}

type TrafficProbe struct {
	IP    string `json:"ip"`
	UDPOK bool   `json:"udp_ok"`
}

func ProbeTraffic(ctx context.Context) (TrafficProbe, error) {
	var probe TrafficProbe
	client := &http.Client{Timeout: 12 * time.Second, Transport: &http.Transport{Proxy: nil}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://1.1.1.1/cdn-cgi/trace", nil)
	if err != nil {
		return probe, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return probe, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return probe, fmt.Errorf("TCP trace HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return probe, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "ip=") {
			probe.IP = strings.TrimSpace(strings.TrimPrefix(line, "ip="))
		}
	}
	if net.ParseIP(probe.IP).To4() == nil {
		return probe, errors.New("public TCP egress IP missing")
	}
	conn, err := net.DialTimeout("udp4", "1.1.1.1:53", 5*time.Second)
	if err != nil {
		return probe, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	query := []byte{0x12, 0x34, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	if _, err := conn.Write(query); err != nil {
		return probe, err
	}
	answer := make([]byte, 4096)
	n, err := conn.Read(answer)
	if err != nil {
		return probe, err
	}
	if n < 12 || binary.BigEndian.Uint16(answer[:2]) != 0x1234 || binary.BigEndian.Uint16(answer[6:8]) == 0 || answer[3]&0x0f != 0 {
		return probe, errors.New("invalid UDP DNS response")
	}
	probe.UDPOK = true
	return probe, nil
}

func probeSyntheticTPROXY(ctx context.Context) (TrafficProbe, error) {
	var empty TrafficProbe
	direct, err := ProbeTraffic(ctx)
	if err != nil {
		return empty, fmt.Errorf("direct baseline: %w", err)
	}
	random := make([]byte, 3)
	if _, err := rand.Read(random); err != nil {
		return empty, err
	}
	suffix := hex.EncodeToString(random)
	ns, hostIf, peerIf := "wdttp"+suffix, "wdp"+suffix, "wdq"+suffix
	cleanup := func() {
		cleanCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = run(cleanCtx, "iptables", "-t", "mangle", "-D", "PREROUTING", "-i", hostIf, "-s", "198.18.77.2/32", "-j", vlessClientChain)
		_ = run(cleanCtx, "ip", "netns", "del", ns)
		_ = run(cleanCtx, "ip", "link", "del", hostIf)
	}
	defer cleanup()
	for _, args := range [][]string{
		{"netns", "add", ns},
		{"link", "add", hostIf, "type", "veth", "peer", "name", peerIf},
		{"link", "set", peerIf, "netns", ns},
		{"addr", "add", "198.18.77.1/30", "dev", hostIf},
		{"link", "set", hostIf, "up"},
		{"netns", "exec", ns, "ip", "addr", "add", "198.18.77.2/30", "dev", peerIf},
		{"netns", "exec", ns, "ip", "link", "set", peerIf, "up"},
		{"netns", "exec", ns, "ip", "link", "set", "lo", "up"},
		{"netns", "exec", ns, "ip", "route", "add", "default", "via", "198.18.77.1"},
	} {
		if err := run(ctx, "ip", args...); err != nil {
			return empty, err
		}
	}
	if err := run(ctx, "iptables", "-t", "mangle", "-I", "PREROUTING", "1", "-i", hostIf, "-s", "198.18.77.2/32", "-j", vlessClientChain); err != nil {
		return empty, err
	}
	out, err := command(ctx, "ip", "netns", "exec", ns, "/usr/local/bin/wdtt-panel", "node", "probe-traffic")
	if err != nil {
		return empty, errors.New("synthetic TCP/UDP flow failed")
	}
	var via TrafficProbe
	if json.Unmarshal([]byte(out), &via) != nil || !via.UDPOK || net.ParseIP(via.IP).To4() == nil {
		return empty, errors.New("synthetic TCP/UDP result invalid")
	}
	if via.IP == direct.IP {
		return empty, errors.New("synthetic flow bypassed the VLESS egress")
	}
	return via, nil
}

func ProbeVLESSClient(ctx context.Context) error {
	_, err := ProbeVLESSClientTraffic(ctx)
	return err
}

func ProbeVLESSClientTraffic(ctx context.Context) (TrafficProbe, error) {
	if _, err := os.Stat(vlessClientPath); err != nil {
		return TrafficProbe{}, errors.New("WDTT transparent VLESS client is not enabled")
	}
	return probeSyntheticTPROXY(ctx)
}
