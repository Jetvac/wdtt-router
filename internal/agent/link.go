package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"strings"

	"github.com/Jetvac/wdtt-router/internal/link"
	"github.com/Jetvac/wdtt-router/internal/spec"
)

// The chain tunnel (docs/chain-link.md): a WireGuard link between the
// entry and the exit inside Mesh, next to the Xray chain. The service is
// this binary ("wdtt-router link"); the agent writes its configuration,
// the entry's routing and the exit's forwarding rules.
const (
	LinkIface      = "wrlink0"
	linkUnit       = "wdtt-router-link.service"
	linkConfigPath = EtcDir + "/link.json"
	// LinkStatusPath is where the service publishes its state.
	LinkStatusPath = "/run/wdtt-router/link-status.json"
	linkSet        = "via_link"
	linkTable      = "wdtt_router_link" // the exit's forwarding and NAT
	linkRT         = "51889"
	linkPrefIface  = "10667" // after TPROXY's 10666
	linkPrefMark   = "10668"
	// LinkMark marks the entry's own checks through the tunnel.
	LinkMark      = 0x2
	linkEntryAddr = "10.66.80.1"
	linkExitAddr  = "10.66.80.2"
	linkDataDir   = VarDir + "/link"
)

// LinkConfig renders the service's configuration for this server.
func LinkConfig(s *spec.NodeSpec, meshIP, publicIface string) (*link.Config, error) {
	l := s.Link
	c := &link.Config{Role: s.Role, MeshIface: MeshIface, StatusFile: LinkStatusPath}
	switch s.Role {
	case spec.RoleEntry:
		c.Mode, c.Iface, c.Address, c.MTU = l.Mode, LinkIface, linkEntryAddr+"/30", l.MTU
		c.Peer = net.JoinHostPort(l.Next.Addr, fmt.Sprint(l.Next.Port))
		c.PrivateKey, c.PeerKey, c.PSK, c.AllowedIP = l.PrivateKey, l.PeerKey, l.PSK, "0.0.0.0/0"
		for _, w := range s.Entry.WDTTServers() {
			c.WDTTIfaces = append(c.WDTTIfaces, WDTTServerOf(w.Kind).Iface)
		}
		c.NftTable, c.NftSet, c.RouteTable, c.Mark = tproxyTable, linkSet, 51889, LinkMark
	case spec.RoleExit, spec.RoleRelay:
		if meshIP == "" {
			return nil, errors.New("Mesh address is not assigned yet")
		}
		c.Listen = net.JoinHostPort(meshIP, fmt.Sprint(l.Port))
		if s.Role == spec.RoleRelay {
			c.Peer = net.JoinHostPort(l.Next.Addr, fmt.Sprint(l.Next.Port))
			break
		}
		if publicIface == "" {
			return nil, errors.New("no default route: cannot tell the Internet interface")
		}
		c.Iface, c.Address, c.MTU = LinkIface, linkExitAddr+"/30", l.MTU
		c.PrivateKey, c.PeerKey, c.PSK, c.AllowedIP = l.PrivateKey, l.PeerKey, l.PSK, linkEntryAddr+"/32"
		c.PublicIface = publicIface
	default:
		return nil, errors.New("the chain tunnel runs only on chain servers")
	}
	return c, c.Validate()
}

func linkUnitText(role string) string {
	pre, post := "", ""
	if role == spec.RoleEntry {
		pre = fmt.Sprintf("ExecStartPre=+%s agent link-routes\n", SelfPath)
	}
	if role != spec.RoleRelay {
		post = fmt.Sprintf("ExecStopPost=-/usr/sbin/ip link del %s\n", LinkIface)
	}
	return fmt.Sprintf(`[Unit]
Description=WDTT Router chain tunnel (%[1]s)
After=network-online.target warp-svc.service
Wants=network-online.target

[Service]
Type=simple
%[3]sExecStart=%[2]s link --config %[4]s
ExecReload=/bin/kill -HUP $MAINPID
%[5]sRestart=always
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
ReadWritePaths=%[6]s
RuntimeDirectory=wdtt-router
RuntimeDirectoryPreserve=yes

[Install]
WantedBy=multi-user.target
`, role, SelfPath, pre, linkConfigPath, post, linkDataDir)
}

// linkExitScript: the exit forwards what comes out of the tunnel to the
// Internet with the same limits as the Xray exit (no private or Mesh
// ranges, no port 25), lets only the replies back in, and never lets the
// host be used as a router from its Internet side or into Mesh.
func linkExitScript(pub string) string {
	var v4 []string
	for _, r := range privateRanges {
		if !strings.Contains(r, ":") {
			v4 = append(v4, r)
		}
	}
	return fmt.Sprintf(`table inet %[1]s
delete table inet %[1]s
table inet %[1]s {
	chain forward {
		type filter hook forward priority filter - 10; policy accept;
		iifname "%[2]s" oifname "%[3]s" ip daddr { %[5]s } drop
		iifname "%[2]s" oifname "%[3]s" tcp dport 25 drop
		iifname "%[2]s" oifname "%[3]s" ip saddr %[4]s accept
		iifname "%[3]s" oifname "%[2]s" ct state established,related accept
		iifname "%[2]s" drop
		oifname "%[2]s" drop
		iifname "%[3]s" oifname { "%[3]s", "%[6]s" } drop
	}
	chain input {
		type filter hook input priority filter - 10; policy accept;
		iifname "%[2]s" ct state established,related accept
		iifname "%[2]s" drop
	}
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		oifname "%[3]s" ip saddr %[4]s masquerade
	}
}
`, linkTable, LinkIface, pub, linkEntryAddr, strings.Join(v4, ", "), MeshIface)
}

// applyLinkRouting sends what the WDTT interfaces route (client UDP on
// the tunnel, see tproxyScript) and the entry's marked checks to the
// tunnel's table. The table always ends in a blackhole: nothing meant for
// the tunnel falls through to the main table.
func applyLinkRouting(ctx context.Context, ifaces []string) error {
	for _, pref := range []string{linkPrefIface, linkPrefMark} {
		for run(ctx, "ip", "-4", "rule", "del", "pref", pref) == nil {
		}
	}
	for _, ifc := range ifaces {
		if err := run(ctx, "ip", "-4", "rule", "add", "pref", linkPrefIface, "iif", ifc, "lookup", linkRT); err != nil {
			return err
		}
	}
	if err := run(ctx, "ip", "-4", "rule", "add", "pref", linkPrefMark, "fwmark", fmt.Sprintf("%#x", LinkMark), "lookup", linkRT); err != nil {
		return err
	}
	return run(ctx, "ip", "-4", "route", "replace", "blackhole", "default", "metric", "4096", "table", linkRT)
}

func linkRoutingPresent(ctx context.Context, ifaces []string) bool {
	rules, _ := output(ctx, "ip", "-4", "rule", "show")
	routes, _ := output(ctx, "ip", "-4", "route", "show", "table", linkRT)
	for _, ifc := range ifaces {
		if !strings.Contains(rules, "iif "+ifc+" lookup "+linkRT) {
			return false
		}
	}
	return strings.Contains(rules, "lookup "+linkRT) && strings.Contains(routes, "blackhole default")
}

func removeLinkRouting(ctx context.Context) bool {
	changed := false
	for _, pref := range []string{linkPrefIface, linkPrefMark} {
		for run(ctx, "ip", "-4", "rule", "del", "pref", pref) == nil {
			changed = true
		}
	}
	_ = run(ctx, "ip", "-4", "route", "flush", "table", linkRT)
	return changed
}

// LinkRoutes installs the entry's tunnel routing (the service's
// ExecStartPre).
func LinkRoutes(ctx context.Context) error {
	s, _, err := loadSaved()
	if err != nil || s.Entry == nil || s.Link == nil {
		return nil
	}
	return applyLinkRouting(ctx, linkIfaces(s))
}

func linkIfaces(s *spec.NodeSpec) []string {
	var out []string
	for _, w := range s.Entry.WDTTServers() {
		out = append(out, WDTTServerOf(w.Kind).Iface)
	}
	return out
}

// reconcileLink brings the tunnel service to the spec: configured and
// running, or gone with everything it set up. On the entry the WDTT step
// has already put the matching traffic rules in place.
func reconcileLink(ctx context.Context, s *spec.NodeSpec, changed *[]string) error {
	if s.Link == nil {
		removed := removeUnit(ctx, linkUnit)
		if exists(linkConfigPath) {
			removeIfExists(linkConfigPath)
			removed = true
		}
		removeIfExists(LinkStatusPath)
		_ = run(ctx, "ip", "link", "del", LinkIface)
		if removeLinkRouting(ctx) {
			removed = true
		}
		if nftTableExists(ctx, linkTable) {
			_ = run(ctx, "nft", "delete", "table", "inet", linkTable)
			removed = true
		}
		if removeLinkForward(ctx) {
			removed = true
		}
		if removed {
			*changed = append(*changed, "chain tunnel: removed")
		}
		return nil
	}
	if err := aptInstall(ctx, "nftables", "iproute2"); err != nil {
		return err
	}
	pub := linkPublicIface(ctx)
	cfg, err := LinkConfig(s, MeshAddress(), pub)
	if err != nil {
		return err
	}
	b, _ := json.MarshalIndent(cfg, "", " ")
	b = append(b, '\n')
	if err := os.MkdirAll(linkDataDir, 0700); err != nil {
		return err
	}
	old, _ := os.ReadFile(linkConfigPath)
	cfgChanged, err := writeIfChanged(linkConfigPath, b, 0600)
	if err != nil {
		return err
	}
	switch s.Role {
	case spec.RoleEntry:
		// Re-adding rules that are in place would open a gap of a few
		// packets; add them only when something is missing.
		if !linkRoutingPresent(ctx, linkIfaces(s)) {
			if err := applyLinkRouting(ctx, linkIfaces(s)); err != nil {
				return fmt.Errorf("tunnel routing: %w", err)
			}
		}
		if nftTableExists(ctx, linkTable) {
			_ = run(ctx, "nft", "delete", "table", "inet", linkTable)
		}
	case spec.RoleExit:
		script := linkExitScript(pub)
		if out, err := runStdin(ctx, script, "nft", "-f", "-"); err != nil {
			return fmt.Errorf("tunnel rules rejected: %s", out)
		}
		if _, err := writeIfChanged(EtcDir+"/link.nft", []byte(script), 0600); err != nil {
			return err
		}
		if added, err := ensureLinkForward(ctx, pub); err != nil {
			Logf("chain tunnel: iptables FORWARD: %v", err)
		} else if added {
			*changed = append(*changed, "chain tunnel: let through iptables FORWARD (ufw/Docker)")
		}
	default:
		if nftTableExists(ctx, linkTable) {
			_ = run(ctx, "nft", "delete", "table", "inet", linkTable)
		}
	}
	unitChanged, err := installUnit(ctx, linkUnit, linkUnitText(s.Role))
	if err != nil {
		return err
	}
	switch {
	case unitChanged || linkBinaryChanged() || unitState(linkUnit) != "active" || (cfgChanged && !modeOnly(old, b)):
		Logf("starting the chain tunnel")
		if err := systemctl(ctx, "restart", linkUnit); err != nil {
			return err
		}
		*changed = append(*changed, "chain tunnel: started ("+s.Link.Mode+")")
	case cfgChanged:
		// Only the entry's mode changed: no restart, no new handshake.
		if err := systemctl(ctx, "reload", linkUnit); err != nil {
			return err
		}
		*changed = append(*changed, "chain tunnel: mode "+s.Link.Mode)
	}
	if err := waitActive(ctx, linkUnit); err != nil {
		return err
	}
	markLinkBinary()
	return nil
}

// modeOnly: two configurations of the entry differ in the mode only (the
// service re-reads it on SIGHUP, without a new handshake).
func modeOnly(old, cur []byte) bool {
	var a, b link.Config
	if json.Unmarshal(old, &a) != nil || json.Unmarshal(cur, &b) != nil || a.Role != spec.RoleEntry {
		return false
	}
	a.Mode, b.Mode = "", ""
	return reflect.DeepEqual(a, b)
}

func linkBinaryChanged() bool {
	b, err := os.ReadFile(linkDataDir + "/.server-version")
	return err != nil || strings.TrimSpace(string(b)) != Version
}

func markLinkBinary() { _ = os.WriteFile(linkDataDir+"/.server-version", []byte(Version+"\n"), 0600) }

// linkPublicIface is where the exit's own Internet traffic leaves: the
// route to 1.1.1.1, unless that goes into Mesh or the tunnel (Cloudflare's
// client can take such routes), then the main table's default route.
func linkPublicIface(ctx context.Context) string {
	if dev, _ := defaultRoute(); dev != "" && dev != MeshIface && dev != LinkIface {
		return dev
	}
	out, _ := output(ctx, "ip", "-4", "route", "show", "table", "main", "default")
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "dev" && f[i+1] != MeshIface && f[i+1] != LinkIface {
				return f[i+1]
			}
		}
	}
	return ""
}

// linkRuntime reads the state the service publishes.
func linkRuntime() *spec.LinkStatus {
	b, err := os.ReadFile(LinkStatusPath)
	if err != nil {
		return nil
	}
	var st spec.LinkStatus
	if json.Unmarshal(b, &st) != nil {
		return nil
	}
	return &st
}

// maintainLink repairs what other software may remove (the policy rules,
// like TPROXY's) and restarts a service left on an older build by a panel
// update.
func maintainLink(ctx context.Context, s *spec.NodeSpec) {
	if s.Link == nil || !unitExists(linkUnit) {
		return
	}
	if s.Role == spec.RoleEntry && !linkRoutingPresent(ctx, linkIfaces(s)) {
		Logf("restoring the chain tunnel's policy routing")
		if err := applyLinkRouting(ctx, linkIfaces(s)); err != nil {
			Logf("chain tunnel routing: %v", err)
		}
	}
	// ufw and Docker rewrite FORWARD when they reload.
	if s.Role == spec.RoleExit {
		if pub := linkPublicIface(ctx); pub != "" {
			if added, err := ensureLinkForward(ctx, pub); err != nil {
				Logf("chain tunnel: iptables FORWARD: %v", err)
			} else if added {
				Logf("chain tunnel: restored its rules in iptables FORWARD")
			}
		}
	}
	if !linkBinaryChanged() {
		return
	}
	Logf("the chain tunnel runs an older build: restarting it")
	if _, err := installUnit(ctx, linkUnit, linkUnitText(s.Role)); err != nil {
		Logf("chain tunnel: %v", err)
		return
	}
	if err := systemctl(ctx, "restart", linkUnit); err != nil {
		Logf("chain tunnel: %v", err)
		return
	}
	markLinkBinary()
}
