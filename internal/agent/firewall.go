package agent

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/Jetvac/wdtt-router/internal/spec"
)

const (
	fwTable       = "wdtt_router"
	fwPath        = EtcDir + "/firewall.nft"
	fwPrevPath    = VarDir + "/firewall.prev.nft"
	fwPendingPath = VarDir + "/firewall.pending.nft"
	fwRevertUnit  = "wdtt-router-fw-revert"
	// RevertSeconds is how long a firewall change waits for confirmation.
	RevertSeconds = 120
)

// FirewallInputs are values discovered on the host that shape the ruleset.
type FirewallInputs struct {
	HopPort  int
	WDTT     []spec.WDTTSpec // enabled WDTT servers (EntrySpec.WDTTServers)
	XUIPorts []int
}

func set4and6(list []string) (v4, v6 []string) {
	for _, c := range list {
		if strings.Contains(c, ":") {
			v6 = append(v6, c)
		} else {
			v4 = append(v4, c)
		}
	}
	return
}

// allowRule renders "match accept" restricted to a source allow-list.
func allowRule(b *strings.Builder, match string, allow []string) {
	if len(allow) == 0 {
		fmt.Fprintf(b, "\t\t%s accept\n", match)
		return
	}
	v4, v6 := set4and6(allow)
	if len(v4) > 0 {
		fmt.Fprintf(b, "\t\tip saddr { %s } %s accept\n", strings.Join(v4, ", "), match)
	}
	if len(v6) > 0 {
		fmt.Fprintf(b, "\t\tip6 saddr { %s } %s accept\n", strings.Join(v6, ", "), match)
	}
}

func joinPorts(p []int) string {
	s := make([]string, len(p))
	for i, v := range p {
		s[i] = fmt.Sprint(v)
	}
	return strings.Join(s, ", ")
}

// RenderFirewall produces an nftables script that atomically replaces the
// wdtt_router table. Only this table is touched; rules of other software
// (cloudflare-warp, Docker, 3x-ui) are left alone.
func RenderFirewall(f spec.FirewallSpec, in FirewallInputs) string {
	var b strings.Builder
	b.WriteString("#!/usr/sbin/nft -f\n# Managed by wdtt-router. Do not edit: changes are overwritten.\n")
	fmt.Fprintf(&b, "table inet %s\ndelete table inet %s\n", fwTable, fwTable)
	fmt.Fprintf(&b, "table inet %s {\n", fwTable)
	// Per-source flood limit for public SSH: a scanner can only slow down
	// itself, never lock the administrator out.
	b.WriteString("\tset ssh_flood4 { type ipv4_addr; flags dynamic, timeout; timeout 2m; }\n")
	b.WriteString("\tset ssh_flood6 { type ipv6_addr; flags dynamic, timeout; timeout 2m; }\n")
	b.WriteString("\tchain input {\n\t\ttype filter hook input priority filter - 5; policy drop;\n")
	b.WriteString("\t\tiif \"lo\" accept\n")
	b.WriteString("\t\tct state established,related accept\n")
	b.WriteString("\t\tct state invalid drop\n")
	var wdttIfaces []string
	var wdttPorts []int
	for _, w := range in.WDTT {
		wdttIfaces = append(wdttIfaces, `"`+WDTTServerOf(w.Kind).Iface+`"`)
		wdttPorts = append(wdttPorts, w.DTLSPort)
	}
	if len(wdttIfaces) > 0 {
		// Only packets diverted by TPROXY may enter from WDTT clients; the
		// clients cannot reach services of the host itself.
		fmt.Fprintf(&b, "\t\tiifname { %s } meta mark 0x00000001 accept\n", strings.Join(wdttIfaces, ", "))
		fmt.Fprintf(&b, "\t\tiifname { %s } drop\n", strings.Join(wdttIfaces, ", "))
	}
	// Mesh: only SSH and the hop port, only from Mesh addresses.
	mesh := []int{f.SSHPort}
	if in.HopPort > 0 {
		mesh = append(mesh, in.HopPort)
	}
	fmt.Fprintf(&b, "\t\tiifname \"%s\" ip saddr 100.96.0.0/12 tcp dport { %s } accept\n", MeshIface, joinPorts(mesh))
	if f.PanelPort > 0 {
		// The panel is always reachable inside Mesh (the team's devices with
		// Cloudflare WARP, and the Telegram bot on another server); with
		// PanelMeshOnly it is reachable only there.
		fmt.Fprintf(&b, "\t\tiifname \"%s\" ip saddr 100.96.0.0/12 tcp dport %d accept\n", MeshIface, f.PanelPort)
	}
	fmt.Fprintf(&b, "\t\tiifname \"%s\" drop\n", MeshIface)
	if f.SSHPublic {
		fmt.Fprintf(&b, "\t\ttcp dport %d ct state new update @ssh_flood4 { ip saddr limit rate over 15/minute burst 30 packets } drop\n", f.SSHPort)
		fmt.Fprintf(&b, "\t\ttcp dport %d ct state new update @ssh_flood6 { ip6 saddr limit rate over 15/minute burst 30 packets } drop\n", f.SSHPort)
		allowRule(&b, fmt.Sprintf("tcp dport %d", f.SSHPort), f.SSHAllow)
	}
	if f.PanelPort > 0 && !f.PanelMeshOnly {
		allowRule(&b, fmt.Sprintf("tcp dport %d", f.PanelPort), f.PanelAllow)
	}
	if len(wdttPorts) > 0 {
		fmt.Fprintf(&b, "\t\tudp dport { %s } accept\n", joinPorts(wdttPorts))
	}
	if len(in.XUIPorts) > 0 {
		fmt.Fprintf(&b, "\t\tmeta l4proto { tcp, udp } th dport { %s } accept\n", joinPorts(in.XUIPorts))
	}
	if len(f.ExtraTCP) > 0 {
		fmt.Fprintf(&b, "\t\ttcp dport { %s } accept\n", joinPorts(f.ExtraTCP))
	}
	if len(f.ExtraUDP) > 0 {
		fmt.Fprintf(&b, "\t\tudp dport { %s } accept\n", joinPorts(f.ExtraUDP))
	}
	// ICMP errors are required for path MTU discovery; echo is optional.
	b.WriteString("\t\ticmp type { destination-unreachable, time-exceeded, parameter-problem } accept\n")
	b.WriteString("\t\ticmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert, nd-router-solicit } accept\n")
	if f.AllowPing {
		b.WriteString("\t\ticmp type echo-request limit rate 5/second accept\n")
		b.WriteString("\t\ticmpv6 type echo-request limit rate 5/second accept\n")
	}
	b.WriteString("\t\tudp sport 67 udp dport 68 accept\n")
	b.WriteString("\t\tudp sport 547 udp dport 546 accept\n")
	b.WriteString("\t}\n}\n")
	return b.String()
}

func nftTableExists(ctx context.Context, table string) bool {
	return run(ctx, "nft", "list", "table", "inet", table) == nil
}

// reconcileFirewall applies the ruleset and arms the dead-man revert timer
// when the effective rules changed. New rules are kept in firewall.pending
// until the controller confirms it can still connect; only confirmed rules
// are restored at boot. Without confirmation a transient systemd timer runs
// "nft -f firewall.prev.nft" directly (not this binary, so even a broken
// agent cannot prevent the rollback).
func reconcileFirewall(ctx context.Context, s *spec.NodeSpec, in FirewallInputs, changed *[]string) (bool, error) {
	if err := aptInstall(ctx, "nftables"); err != nil {
		return false, err
	}
	if !s.Firewall.Enabled {
		if nftTableExists(ctx, fwTable) || exists(fwPath) {
			stopRevert(ctx)
			_ = run(ctx, "nft", "delete", "table", "inet", fwTable)
			removeIfExists(fwPath, fwPendingPath, fwPrevPath)
			*changed = append(*changed, "firewall: disabled")
		}
		return false, nil
	}
	script := RenderFirewall(s.Firewall, in)
	if live, _ := os.ReadFile(fwPendingPath); string(live) == script && revertPending() {
		return true, nil
	}
	if cur, _ := os.ReadFile(fwPath); string(cur) == script && nftTableExists(ctx, fwTable) && !exists(fwPendingPath) {
		return false, nil
	}
	if err := os.MkdirAll(EtcDir, 0700); err != nil {
		return false, err
	}
	if err := os.MkdirAll(VarDir, 0700); err != nil {
		return false, err
	}
	tmp := EtcDir + "/firewall.check.nft"
	if err := os.WriteFile(tmp, []byte(script), 0600); err != nil {
		return false, err
	}
	defer os.Remove(tmp)
	if out, err := output(ctx, "nft", "-c", "-f", tmp); err != nil {
		return false, fmt.Errorf("firewall rules rejected: %s", tail(out, 400))
	}
	if !revertPending() {
		// When changes are stacked, keep the oldest known-good rules.
		if err := saveCurrent(ctx); err != nil {
			return false, err
		}
	}
	Logf("applying firewall (auto-revert in %d s unless confirmed)", RevertSeconds)
	if err := armRevert(ctx); err != nil {
		return false, err
	}
	if err := os.WriteFile(fwPendingPath, []byte(script), 0600); err != nil {
		return false, err
	}
	if out, err := output(ctx, "nft", "-f", tmp); err != nil {
		return false, fmt.Errorf("firewall apply failed: %s", tail(out, 400))
	}
	*changed = append(*changed, "firewall: rules applied")
	return true, nil
}

func saveCurrent(ctx context.Context) error {
	out, err := output(ctx, "nft", "list", "table", "inet", fwTable)
	if err != nil {
		out = "" // no table before: reverting means deleting ours
	}
	script := fmt.Sprintf("table inet %s\ndelete table inet %s\n%s\n", fwTable, fwTable, out)
	return os.WriteFile(fwPrevPath, []byte(script), 0600)
}

func nftPath() string {
	for _, p := range []string{"/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"} {
		if exists(p) {
			return p
		}
	}
	return "/usr/sbin/nft"
}

func stopRevert(ctx context.Context) {
	_ = run(ctx, "systemctl", "stop", fwRevertUnit+".timer")
	_ = run(ctx, "systemctl", "reset-failed", fwRevertUnit+".service", fwRevertUnit+".timer")
}

func armRevert(ctx context.Context) error {
	stopRevert(ctx)
	return run(ctx, "systemd-run", "--unit="+fwRevertUnit, fmt.Sprintf("--on-active=%d", RevertSeconds),
		"--timer-property=AccuracySec=1s", "--description=wdtt-router firewall dead-man revert",
		nftPath(), "-f", fwPrevPath)
}

func revertPending() bool {
	return unitState(fwRevertUnit+".timer") == "active"
}

// Confirm keeps the current firewall and cancels the pending revert.
func Confirm(ctx context.Context) error {
	if firewallReverted() {
		return fmt.Errorf("the firewall change was already reverted by the safety timer; apply again")
	}
	stopRevert(ctx)
	if b, err := os.ReadFile(fwPendingPath); err == nil {
		if _, err := writeIfChanged(fwPath, b, 0600); err != nil {
			return err
		}
		_ = os.Remove(fwPendingPath)
	}
	_ = os.Remove(fwPrevPath)
	return nil
}

// firewallReverted reports a change that was rolled back by the timer.
func firewallReverted() bool {
	return exists(fwPendingPath) && !revertPending()
}

func firewallSummary(ctx context.Context) (bool, []string) {
	if !nftTableExists(ctx, fwTable) {
		return false, nil
	}
	b, err := os.ReadFile(fwPendingPath)
	if err != nil {
		b, _ = os.ReadFile(fwPath)
	}
	lines := []string{}
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if strings.HasSuffix(l, "accept") && strings.Contains(l, "dport") {
			lines = append(lines, l)
		}
	}
	sort.Strings(lines)
	return true, lines
}
