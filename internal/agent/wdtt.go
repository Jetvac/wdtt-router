package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/Jetvac/wdtt-router/internal/spec"
)

const (
	wdttUnit    = "wdtt-router-wdtt.service"
	wdttDataDir = VarDir + "/wdtt"
	// WDTTDataDir holds the WDTT server's keys and devices.
	WDTTDataDir = wdttDataDir
	tproxyTable = "wdtt_router_wdtt"
	tproxyMark  = "0x1"
	tproxyRT    = "51888"
	tproxyPref  = "10666"
	WDTTIface   = "wdtt0"
	WDTTNet     = "10.66.66.0/24"
)

// WDTTConfigPath is the configuration of the built-in WDTT server.
const (
	WDTTConfigPath = EtcDir + "/wdtt.json"
	WDTTStatusPath = "/run/wdtt-router/wdtt-status.json"
)

// WDTTServer is where one WDTT server of the entry node lives. The server
// for standard clients keeps the names of earlier versions.
type WDTTServer struct {
	Kind, Name, Unit, Config, Status, Data, Iface, Network, Addr string
}

// WDTTServers are the WDTT servers an entry node can run, standard first.
var WDTTServers = []WDTTServer{
	{Kind: spec.WDTTStandard, Name: "wdtt", Unit: wdttUnit, Config: WDTTConfigPath, Status: WDTTStatusPath,
		Data: wdttDataDir, Iface: WDTTIface, Network: WDTTNet, Addr: "10.66.66.1"},
	{Kind: spec.WDTTTurnVK, Name: "wdtt-turnvk", Unit: "wdtt-router-wdtt-turnvk.service", Config: EtcDir + "/wdtt-turnvk.json",
		Status: "/run/wdtt-router/wdtt-turnvk-status.json", Data: VarDir + "/wdtt-turnvk", Iface: "wdtt1", Network: "10.66.67.0/24", Addr: "10.66.67.1"},
}

// WDTTDataDirs maps each server's name to its data directory (backups).
func WDTTDataDirs() map[string]string {
	m := map[string]string{}
	for _, w := range WDTTServers {
		m[w.Name] = w.Data
	}
	return m
}

// WDTTServerOf returns the server of a client kind.
func WDTTServerOf(kind string) WDTTServer {
	for _, w := range WDTTServers {
		if w.Kind == kind {
			return w
		}
	}
	return WDTTServers[0]
}

// The WDTT server is part of this binary. It runs as root only for the
// network setup it needs (TUN device, its address): the unit keeps just
// CAP_NET_ADMIN and a read-only view of the system.
func wdttUnitText(w WDTTServer) string {
	desc := "WDTT server (managed by wdtt-router)"
	if w.Kind == spec.WDTTTurnVK {
		desc = "WDTT server for the TurnVK client (managed by wdtt-router)"
	}
	return fmt.Sprintf(`[Unit]
Description=%[5]s
After=network-online.target wdtt-router-xray.service
Wants=network-online.target

[Service]
Type=simple
ExecStartPre=+%[1]s agent tproxy-routes
ExecStart=%[1]s wdtt-server --config %[2]s
ExecReload=/bin/kill -HUP $MAINPID
ExecStopPost=-/usr/sbin/ip link del %[3]s
Restart=always
RestartSec=1
LimitNOFILE=65535
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_UNIX
SystemCallArchitectures=native
SystemCallFilter=@system-service
DeviceAllow=/dev/net/tun rw
ReadWritePaths=%[4]s
RuntimeDirectory=wdtt-router
RuntimeDirectoryPreserve=yes

[Install]
WantedBy=multi-user.target
`, SelfPath, w.Config, w.Iface, w.Data, desc)
}

type wdttConfig struct {
	Listen       string         `json:"listen"`
	DNS          string         `json:"dns"`
	DataDir      string         `json:"data_dir"`
	StatusFile   string         `json:"status_file"`
	MainPassword string         `json:"main_password"`
	Keys         []spec.WDTTKey `json:"keys"`
	MTU          int            `json:"mtu,omitempty"`
	Kind         string         `json:"kind,omitempty"`
	Iface        string         `json:"iface,omitempty"`
	Network      string         `json:"network,omitempty"`
}

func renderWDTTConfig(w spec.WDTTSpec) []byte {
	srv := WDTTServerOf(w.Kind)
	dns := w.DNS
	if dns == "" {
		dns = "1.1.1.1"
	}
	keys := w.Keys
	if keys == nil {
		keys = []spec.WDTTKey{}
	}
	b, _ := json.MarshalIndent(wdttConfig{Listen: fmt.Sprintf("0.0.0.0:%d", w.DTLSPort), DNS: dns, DataDir: srv.Data,
		StatusFile: srv.Status, MainPassword: w.Password, Keys: keys, MTU: w.MTU,
		Kind: srv.Kind, Iface: srv.Iface, Network: srv.Network}, "", " ")
	return append(b, '\n')
}

// tproxyScript diverts everything WDTT clients send to the Internet into the
// local Xray inbound, and drops any forwarding from or to wdtt0. If Xray or
// the chain is down the clients simply have no connectivity — their traffic
// never leaves through the entry server's own address.
func tproxyScript(port int, servers []WDTTServer) string {
	var ifaces, addrs []string
	for _, w := range servers {
		ifaces = append(ifaces, `"`+w.Iface+`"`)
		addrs = append(addrs, w.Addr)
	}
	return fmt.Sprintf(`table inet %[1]s
delete table inet %[1]s
table inet %[1]s {
	chain prerouting {
		type filter hook prerouting priority mangle; policy accept;
		iifname { %[2]s } ip daddr { %[5]s, 127.0.0.0/8, 224.0.0.0/4, 255.255.255.255 } return
		iifname { %[2]s } meta l4proto { tcp, udp } tproxy ip to 127.0.0.1:%[3]d meta mark set %[4]s accept
	}
	chain forward {
		type filter hook forward priority filter - 10; policy accept;
		iifname { %[2]s } drop
		oifname { %[2]s } drop
	}
}
`, tproxyTable, strings.Join(ifaces, ", "), port, tproxyMark, strings.Join(addrs, ", "))
}

// removeOriginalWDTT cleans up what the original WDTT server (built by
// earlier versions of this panel) left behind: its binary and the NAT and
// FORWARD rules it inserted on every start.
func removeOriginalWDTT(ctx context.Context) bool {
	changed := false
	for _, f := range []string{LibDir + "/wdtt-server", LibDir + "/wdtt-server.commit", EtcDir + "/wdtt.env"} {
		if exists(f) {
			removeIfExists(f)
			changed = true
		}
	}
	for _, args := range [][]string{{"-t", "nat", "-S", "POSTROUTING"}, {"-S", "FORWARD"}} {
		out, _ := output(ctx, "iptables", args...)
		for _, line := range strings.Split(out, "\n") {
			if !strings.Contains(line, "WDTT_MANAGED") || !strings.HasPrefix(line, "-A ") {
				continue
			}
			del := append([]string{}, args[:len(args)-2]...)
			del = append(del, "-D")
			for _, f := range strings.Fields(strings.TrimPrefix(line, "-A ")) {
				del = append(del, strings.Trim(f, "\""))
			}
			if run(ctx, "iptables", del...) == nil {
				changed = true
			}
		}
	}
	for _, t := range [][]string{{"ip", "wdtt"}, {"inet", "wdtt"}} {
		if run(ctx, "nft", "list", "table", t[0], t[1]) == nil {
			_ = run(ctx, "nft", "delete", "table", t[0], t[1])
			changed = true
		}
	}
	return changed
}

func applyTProxyRouting(ctx context.Context) error {
	// Delete duplicates first so repeated runs never stack rules.
	for run(ctx, "ip", "-4", "rule", "del", "pref", tproxyPref) == nil {
	}
	if err := run(ctx, "ip", "-4", "rule", "add", "pref", tproxyPref, "fwmark", tproxyMark, "lookup", tproxyRT); err != nil {
		return err
	}
	return run(ctx, "ip", "-4", "route", "replace", "local", "0.0.0.0/0", "dev", "lo", "table", tproxyRT)
}

func removeTProxy(ctx context.Context) bool {
	changed := false
	if nftTableExists(ctx, tproxyTable) {
		_ = run(ctx, "nft", "delete", "table", "inet", tproxyTable)
		changed = true
	}
	for run(ctx, "ip", "-4", "rule", "del", "pref", tproxyPref) == nil {
		changed = true
	}
	_ = run(ctx, "ip", "-4", "route", "flush", "table", tproxyRT)
	removeIfExists(EtcDir + "/wdtt-tproxy.nft")
	return changed
}

func reconcileWDTT(ctx context.Context, e *spec.EntrySpec, changed *[]string) error {
	enabled := map[string]spec.WDTTSpec{}
	var running []WDTTServer
	for _, w := range e.WDTTServers() {
		enabled[w.Kind] = w
		running = append(running, WDTTServerOf(w.Kind))
	}
	// Stop the servers that are off first: the traffic rules below only
	// cover the ones that stay.
	for _, srv := range WDTTServers {
		if _, on := enabled[srv.Kind]; !on && removeWDTTServer(ctx, srv) {
			*changed = append(*changed, srv.Name+": removed (client data kept in "+srv.Data+")")
		}
	}
	if len(running) == 0 {
		removed := removeTProxy(ctx)
		if removeOriginalWDTT(ctx) {
			removed = true
		}
		if removed {
			*changed = append(*changed, "wdtt: traffic rules removed")
		}
		return nil
	}
	if unitExists("wdtt.service") {
		return errors.New("a WDTT installation not managed by this panel (wdtt.service) exists; remove it first: systemctl disable --now wdtt.service")
	}
	if err := aptInstall(ctx, "nftables", "iproute2"); err != nil {
		return err
	}
	// Kill switch and diversion go in before the services start.
	script := tproxyScript(e.WDTTServers()[0].TProxy, running)
	if out, err := runStdin(ctx, script, "nft", "-f", "-"); err != nil {
		return fmt.Errorf("WDTT traffic rules rejected: %s", out)
	}
	if _, err := writeIfChanged(EtcDir+"/wdtt-tproxy.nft", []byte(script), 0600); err != nil {
		return err
	}
	if err := applyTProxyRouting(ctx); err != nil {
		return err
	}
	for _, srv := range running {
		if err := reconcileWDTTServer(ctx, srv, enabled[srv.Kind], changed); err != nil {
			return fmt.Errorf("%s: %w", srv.Name, err)
		}
	}
	if removeOriginalWDTT(ctx) {
		*changed = append(*changed, "wdtt: original WDTT server removed")
	}
	return nil
}

// removeWDTTServer stops one server and removes its unit and configuration;
// its keys and devices stay in its data directory.
func removeWDTTServer(ctx context.Context, srv WDTTServer) bool {
	removed := removeUnit(ctx, srv.Unit)
	if exists(srv.Config) {
		removeIfExists(srv.Config)
		removed = true
	}
	removeIfExists(srv.Status)
	_ = run(ctx, "ip", "link", "del", srv.Iface)
	return removed
}

func reconcileWDTTServer(ctx context.Context, srv WDTTServer, w spec.WDTTSpec, changed *[]string) error {
	if err := os.MkdirAll(srv.Data, 0700); err != nil {
		return err
	}
	cfgChanged, err := writeIfChanged(srv.Config, renderWDTTConfig(w), 0600)
	if err != nil {
		return err
	}
	unitChanged, err := installUnit(ctx, srv.Unit, wdttUnitText(srv))
	if err != nil {
		return err
	}
	// The binary changes on every panel update; the unit runs this binary.
	binChanged := wdttBinaryChanged(srv)
	switch {
	case unitChanged || binChanged || unitState(srv.Unit) != "active":
		Logf("starting %s", srv.Name)
		if err := systemctl(ctx, "restart", srv.Unit); err != nil {
			return err
		}
		*changed = append(*changed, srv.Name+": service started")
	case cfgChanged:
		// Passwords or MTU changed: reload without dropping connected clients.
		if err := systemctl(ctx, "reload", srv.Unit); err != nil {
			return err
		}
		*changed = append(*changed, srv.Name+": passwords reloaded")
	}
	if err := waitActive(ctx, srv.Unit); err != nil {
		return err
	}
	for i := 0; i < 15; i++ {
		if _, err := net.InterfaceByName(srv.Iface); err == nil {
			markWDTTBinary(srv)
			return nil
		}
		if err := sleep(ctx, 1); err != nil {
			return err
		}
	}
	return fmt.Errorf("started but interface %s did not appear", srv.Iface)
}

// The service runs this binary; remember which build it was started with so
// an update restarts it.
func wdttBuildMarker(srv WDTTServer) string { return srv.Data + "/.server-version" }

func wdttBinaryChanged(srv WDTTServer) bool {
	b, err := os.ReadFile(wdttBuildMarker(srv))
	return err != nil || strings.TrimSpace(string(b)) != Version
}

func markWDTTBinary(srv WDTTServer) {
	_ = os.WriteFile(wdttBuildMarker(srv), []byte(Version+"\n"), 0600)
}

// wdttRuntime reads the status published by a running server.
func wdttRuntime(srv WDTTServer) *spec.WDTTRuntime {
	b, err := os.ReadFile(srv.Status)
	if err != nil {
		return nil
	}
	var r spec.WDTTRuntime
	if json.Unmarshal(b, &r) != nil {
		return nil
	}
	return &r
}
