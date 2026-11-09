package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Jetvac/wdtt-router/internal/spec"
)

const (
	XrayVersion = "26.10.31"
	xrayBin     = LibDir + "/xray"
	xrayConfig  = EtcDir + "/xray.json"
	xrayUnit    = "wdtt-router-xray.service"
)

var xraySHA = map[string]string{
	"amd64": "e4bd9119f50ae7c41658b1abd0679ae06f98bd864a2907ff33f2f2cf7081b214",
	"arm64": "1811c8f1da0c3b6dc707ebaf1c8390e987ba39859a8f0a7aadd8526157f2ec8d",
}

var xrayAsset = map[string]string{"amd64": "Xray-linux-64.zip", "arm64": "Xray-linux-arm64-v8a.zip"}

func xrayInstalledVersion() string {
	out, err := exec.Command(xrayBin, "version").Output()
	if err != nil {
		return ""
	}
	f := strings.Fields(string(out))
	if len(f) >= 2 {
		return f[1]
	}
	return ""
}

func installXray(ctx context.Context, changed *[]string) error {
	if xrayInstalledVersion() == XrayVersion {
		return nil
	}
	sha, ok := xraySHA[runtime.GOARCH]
	if !ok {
		return fmt.Errorf("unsupported architecture %s", runtime.GOARCH)
	}
	Logf("downloading Xray %s", XrayVersion)
	zip, err := fetch(ctx, "https://github.com/XTLS/Xray-core/releases/download/v"+XrayVersion+"/"+xrayAsset[runtime.GOARCH], sha)
	if err != nil {
		return err
	}
	bin, err := unzipFile(zip, "xray")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(LibDir, 0755); err != nil {
		return err
	}
	if _, err := writeIfChanged(xrayBin, bin, 0755); err != nil {
		return err
	}
	*changed = append(*changed, "xray: installed "+XrayVersion)
	return nil
}

const xrayUnitText = `[Unit]
Description=WDTT Router chain hop (Xray)
After=network-online.target warp-svc.service
Wants=network-online.target

[Service]
Type=simple
DynamicUser=yes
LoadCredential=config.json:/etc/wdtt-router/xray.json
ExecStart=/usr/local/lib/wdtt-router/xray run -config ${CREDENTIALS_DIRECTORY}/config.json
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
SystemCallArchitectures=native
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
`

// privateRanges are never reachable from the exit node.
var privateRanges = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/3",
	"::1/128", "fc00::/7", "fe80::/10", "2606:4700:cf1::/48",
}

type obj = map[string]any

func blackhole() obj { return obj{"tag": "block", "protocol": "blackhole"} }

// RenderXray builds the Xray configuration for a node. meshIP is the local
// Mesh address used as listen address of hop inbounds.
func RenderXray(s *spec.NodeSpec, meshIP string, ipv6 bool) ([]byte, error) {
	cfg := obj{"log": obj{"loglevel": "warning", "access": "none", "dnsLog": false}}
	switch s.Role {
	case spec.RoleEntry:
		e := s.Entry
		inbounds := []obj{{
			"tag": "local-in", "listen": "127.0.0.1", "port": e.SocksPort, "protocol": "socks",
			"settings": obj{"auth": "password", "accounts": []obj{{"user": e.SocksUser, "pass": e.SocksPass}}, "udp": true, "ip": "127.0.0.1"},
		}}
		tags := []string{"local-in"}
		if e.WDTT.Enabled {
			inbounds = append(inbounds, obj{
				"tag": "wdtt-in", "listen": "127.0.0.1", "port": e.WDTT.TProxy, "protocol": "dokodemo-door",
				"settings":       obj{"network": "tcp,udp", "followRedirect": true},
				"streamSettings": obj{"sockopt": obj{"tproxy": "tproxy"}},
				"sniffing":       obj{"enabled": true, "destOverride": []string{"http", "tls", "quic"}, "routeOnly": true},
			})
			tags = append(tags, "wdtt-in")
		}
		outbounds := []obj{}
		target := "block"
		for i, h := range e.Chain {
			o := obj{
				"tag": fmt.Sprintf("hop%d", i+1), "protocol": "vless",
				"settings":       obj{"vnext": []obj{{"address": h.Addr, "port": h.Port, "users": []obj{{"id": h.UUID, "encryption": h.Encryption}}}}},
				"streamSettings": obj{"network": "raw", "security": "none"},
			}
			if i > 0 {
				o["streamSettings"].(obj)["sockopt"] = obj{"dialerProxy": fmt.Sprintf("hop%d", i)}
			}
			outbounds = append(outbounds, o)
			target = fmt.Sprintf("hop%d", i+1)
		}
		outbounds = append(outbounds, blackhole())
		cfg["inbounds"] = inbounds
		cfg["outbounds"] = outbounds
		cfg["routing"] = obj{"domainStrategy": "AsIs", "rules": []obj{
			{"inboundTag": tags, "outboundTag": target},
		}}
	case spec.RoleRelay, spec.RoleExit:
		if meshIP == "" {
			return nil, errors.New("Mesh address is not assigned yet")
		}
		h := s.Hop
		cfg["inbounds"] = []obj{{
			"tag": "hop-in", "listen": meshIP, "port": h.Port, "protocol": "vless",
			"settings":       obj{"clients": []obj{{"id": h.UUID}}, "decryption": h.Decryption},
			"streamSettings": obj{"network": "raw", "security": "none"},
		}}
		if s.Role == spec.RoleRelay {
			cfg["outbounds"] = []obj{{"tag": "next", "protocol": "freedom"}, blackhole()}
			cfg["routing"] = obj{"domainStrategy": "AsIs", "rules": []obj{
				{"ip": []string{h.Next.Addr}, "port": fmt.Sprint(h.Next.Port), "network": "tcp", "outboundTag": "next"},
				{"network": "tcp,udp", "outboundTag": "block"},
			}}
		} else {
			strategy, query := "UseIPv4", "UseIPv4"
			if ipv6 {
				strategy, query = "UseIP", "UseIP"
			}
			cfg["dns"] = obj{"servers": []string{"https+local://1.1.1.1/dns-query", "https+local://9.9.9.9/dns-query"}, "queryStrategy": query}
			cfg["outbounds"] = []obj{{"tag": "direct", "protocol": "freedom", "settings": obj{"domainStrategy": strategy}}, blackhole()}
			cfg["routing"] = obj{"domainStrategy": "IPIfNonMatch", "rules": []obj{
				{"ip": privateRanges, "outboundTag": "block"},
				{"port": "25", "network": "tcp", "outboundTag": "block"},
				{"network": "tcp,udp", "outboundTag": "direct"},
			}}
		}
	default:
		return nil, nil
	}
	return json.MarshalIndent(cfg, "", "  ")
}

func reconcileXray(ctx context.Context, s *spec.NodeSpec, changed *[]string) error {
	if s.Role == spec.RoleIdle {
		if removeUnit(ctx, xrayUnit) {
			*changed = append(*changed, "xray: stopped (node is idle)")
		}
		removeIfExists(xrayConfig)
		return nil
	}
	if err := installXray(ctx, changed); err != nil {
		return err
	}
	cfg, err := RenderXray(s, MeshAddress(), hasGlobalIPv6())
	if err != nil {
		return err
	}
	tmp := EtcDir + "/xray.check.json"
	if err := os.WriteFile(tmp, cfg, 0600); err != nil {
		return err
	}
	defer os.Remove(tmp)
	if out, err := output(ctx, xrayBin, "run", "-test", "-config", tmp); err != nil {
		lines := strings.Split(out, "\n")
		return errors.New("generated Xray configuration rejected: " + tail(lines[len(lines)-1], 400))
	}
	cfgChanged, err := writeIfChanged(xrayConfig, cfg, 0600)
	if err != nil {
		return err
	}
	unitChanged, err := installUnit(ctx, xrayUnit, xrayUnitText)
	if err != nil {
		return err
	}
	if cfgChanged || unitChanged || unitState(xrayUnit) != "active" {
		Logf("restarting Xray hop")
		if err := systemctl(ctx, "restart", xrayUnit); err != nil {
			return err
		}
		*changed = append(*changed, "xray: configuration applied")
	}
	if err := waitActive(ctx, xrayUnit); err != nil {
		return err
	}
	return waitXrayListening(ctx, s, MeshAddress())
}

// waitXrayListening checks that Xray really accepts connections: systemd
// reports a crash-looping Type=simple unit as active for a moment, and a
// port Xray could not bind (-test does not bind) only shows up here.
func waitXrayListening(ctx context.Context, s *spec.NodeSpec, meshIP string) error {
	var addr string
	switch {
	case s.Role == spec.RoleEntry && s.Entry != nil:
		addr = net.JoinHostPort("127.0.0.1", strconv.Itoa(s.Entry.SocksPort))
	case s.Hop != nil && meshIP != "":
		addr = net.JoinHostPort(meshIP, strconv.Itoa(s.Hop.Port))
	default:
		return nil
	}
	var err error
	for i := 0; i < 15; i++ {
		var c net.Conn
		if c, err = net.DialTimeout("tcp", addr, 2*time.Second); err == nil {
			c.Close()
			return nil
		}
		if err := sleep(ctx, 1); err != nil {
			return err
		}
	}
	return fmt.Errorf("Xray не принимает соединения на %s (%v). %s", addr, err, xrayDiagnosis(ctx, addr))
}

// xrayDiagnosis explains why Xray is not listening: who holds the port and
// what Xray itself last said.
func xrayDiagnosis(ctx context.Context, addr string) string {
	_, port, _ := net.SplitHostPort(addr)
	var b strings.Builder
	if out, _ := output(ctx, "ss", "-Htlnp", "sport = :"+port); strings.TrimSpace(out) != "" {
		b.WriteString("Порт занят: " + tail(strings.TrimSpace(out), 300) + ". ")
	}
	b.WriteString("Состояние службы: " + unitState(xrayUnit) + ". ")
	if out, _ := output(ctx, "journalctl", "-u", xrayUnit, "-n", "10", "--no-pager", "-o", "cat"); strings.TrimSpace(out) != "" {
		b.WriteString("Журнал Xray: " + tail(strings.TrimSpace(out), 700))
	}
	return b.String()
}

func waitActive(ctx context.Context, unit string) error {
	for i := 0; i < 10; i++ {
		if unitState(unit) == "active" {
			return nil
		}
		if err := sleep(ctx, 1); err != nil {
			return err
		}
	}
	out, _ := output(ctx, "journalctl", "-u", unit, "-n", "15", "--no-pager", "-o", "cat")
	return fmt.Errorf("%s is not running: %s", unit, tail(out, 500))
}
