package agent

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// Maintain runs every 30 s on the entry. It repairs state that other
// software may remove at any time and follows 3x-ui inbound changes:
//   - the TPROXY policy rule (systemd-networkd deletes foreign rules when it
//     starts or reloads, e.g. on "netplan apply");
//   - firewall ports of enabled 3x-ui inbounds.
func Maintain(ctx context.Context) error {
	unlock, err := Lock(5e9)
	if err != nil {
		return nil // an apply is running and refreshes everything itself
	}
	defer unlock()
	// Read the settings only under the lock: an apply that finished while we
	// waited has saved new ones, and acting on the old copy would undo it.
	s, _, err := loadSaved()
	if err != nil || s.Entry == nil {
		return nil
	}
	if s.Entry.WDTT.Enabled && !tproxyRoutingPresent(ctx) {
		Logf("restoring WDTT policy routing")
		if err := applyTProxyRouting(ctx); err != nil {
			return err
		}
	}
	if !s.Firewall.Enabled || !s.Entry.XUI.Enabled || revertPending() || firewallReverted() {
		return nil
	}
	in := FirewallInputs{XUIPorts: XUIPorts()}
	if s.Entry.WDTT.Enabled {
		w := s.Entry.WDTT
		in.WDTT = &w
	}
	// Only 3x-ui ports can differ from the confirmed rules here, so no
	// dead-man confirmation is needed.
	script := RenderFirewall(s.Firewall, in)
	if cur, _ := os.ReadFile(fwPath); string(cur) == script {
		return nil
	}
	tmp := EtcDir + "/firewall.check.nft"
	if err := os.WriteFile(tmp, []byte(script), 0600); err != nil {
		return err
	}
	defer os.Remove(tmp)
	if out, err := output(ctx, "nft", "-f", tmp); err != nil {
		return fmt.Errorf("firewall sync failed: %s", tail(out, 300))
	}
	_, err = writeIfChanged(fwPath, []byte(script), 0600)
	Logf("3x-ui ports synced: %v", in.XUIPorts)
	return err
}

// TProxyRoutes installs the WDTT policy routing (used by the WDTT unit).
func TProxyRoutes(ctx context.Context) error { return applyTProxyRouting(ctx) }

func tproxyRoutingPresent(ctx context.Context) bool {
	rules, _ := output(ctx, "ip", "-4", "rule", "show", "pref", tproxyPref)
	routes, _ := output(ctx, "ip", "-4", "route", "show", "table", tproxyRT)
	return strings.Contains(rules, "lookup "+tproxyRT) && strings.Contains(routes, "local default")
}

const maintainService = `[Unit]
Description=WDTT Router: repair policy routing and sync 3x-ui ports

[Service]
Type=oneshot
ExecStart=/usr/local/bin/wdtt-router agent maintain
`

const maintainTimer = `[Unit]
Description=WDTT Router maintenance every 30 s

[Timer]
OnBootSec=30s
OnUnitActiveSec=30s
AccuracySec=5s

[Install]
WantedBy=timers.target
`

func reconcileMaintain(ctx context.Context, want bool) error {
	if !want {
		removeUnit(ctx, "wdtt-router-maintain.timer")
		removeUnit(ctx, "wdtt-router-maintain.service")
		return nil
	}
	// Older builds used a separate timer for 3x-ui only.
	removeUnit(ctx, "wdtt-router-xui-sync.timer")
	removeUnit(ctx, "wdtt-router-xui-sync.service")
	if _, err := writeIfChanged("/etc/systemd/system/wdtt-router-maintain.service", []byte(maintainService), 0644); err != nil {
		return err
	}
	changed, err := installUnit(ctx, "wdtt-router-maintain.timer", maintainTimer)
	if err != nil {
		return err
	}
	if changed || unitState("wdtt-router-maintain.timer") != "active" {
		return systemctl(ctx, "restart", "wdtt-router-maintain.timer")
	}
	return nil
}
