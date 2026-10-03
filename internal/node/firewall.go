package node

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strconv"
)

const firewallPath = "/etc/wdtt-panel/firewall.json"

type FirewallConfig struct {
	Automatic      bool   `json:"automatic"`
	Stealth        bool   `json:"stealth"`
	RestrictSSH    bool   `json:"restrict_ssh"`
	ManagementCIDR string `json:"management_cidr"`
	SSHPort        int    `json:"ssh_port"`
}

func (f *FirewallConfig) defaults() {
	if f.SSHPort == 0 {
		f.SSHPort = 22
	}
}
func (f FirewallConfig) validate() error {
	if f.SSHPort < 1 || f.SSHPort > 65535 {
		return errors.New("invalid SSH port")
	}
	if f.RestrictSSH {
		ip, _, err := net.ParseCIDR(f.ManagementCIDR)
		if err != nil || ip.To4() == nil {
			return errors.New("IPv4 management CIDR required")
		}
	}
	return nil
}

func ApplyFirewall(ctx context.Context, f FirewallConfig) (Result, error) {
	f.defaults()
	if err := f.validate(); err != nil {
		return Result{}, err
	}
	previous, _ := os.ReadFile(firewallPath)
	id, err := beginRecovery(ctx, "firewall", previous)
	if err != nil {
		return Result{}, err
	}
	if err := os.MkdirAll("/etc/wdtt-panel", 0700); err != nil {
		return Result{}, err
	}
	b, _ := json.Marshal(f)
	if err := os.WriteFile(firewallPath, b, 0600); err != nil {
		return Result{}, err
	}
	if err := applyFirewallRaw(ctx, f); err != nil {
		_ = Recover(ctx, id)
		return Result{}, err
	}
	if err := ensureFirewallPersistence(ctx); err != nil {
		_ = Recover(ctx, id)
		return Result{}, err
	}
	return Result{Message: "Firewall rules applied; independent recovery timer awaits management check", RecoveryID: id}, nil
}

func applyFirewallRaw(ctx context.Context, f FirewallConfig) error {
	// Only the panel's named chains and exact jumps are changed.
	_ = run(ctx, "iptables", "-D", "INPUT", "-m", "comment", "--comment", "wdtt-panel:input", "-j", "WDTT_PANEL_INPUT")
	_ = run(ctx, "ip6tables", "-D", "INPUT", "-m", "comment", "--comment", "wdtt-panel:input6", "-j", "WDTT_PANEL_INPUT6")
	_ = run(ctx, "iptables", "-F", "WDTT_PANEL_INPUT")
	_ = run(ctx, "iptables", "-X", "WDTT_PANEL_INPUT")
	_ = run(ctx, "ip6tables", "-F", "WDTT_PANEL_INPUT6")
	_ = run(ctx, "ip6tables", "-X", "WDTT_PANEL_INPUT6")
	if !f.Automatic {
		return nil
	}
	_ = run(ctx, "iptables", "-N", "WDTT_PANEL_INPUT")
	_ = run(ctx, "ip6tables", "-N", "WDTT_PANEL_INPUT6")
	if err := run(ctx, "iptables", "-A", "WDTT_PANEL_INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"); err != nil {
		return err
	}
	if err := run(ctx, "ip6tables", "-A", "WDTT_PANEL_INPUT6", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"); err != nil {
		return err
	}
	if f.RestrictSSH {
		port := strconv.Itoa(f.SSHPort)
		if err := run(ctx, "iptables", "-A", "WDTT_PANEL_INPUT", "-p", "tcp", "-s", f.ManagementCIDR, "--dport", port, "-j", "ACCEPT"); err != nil {
			return err
		}
		if err := run(ctx, "iptables", "-A", "WDTT_PANEL_INPUT", "-p", "tcp", "--dport", port, "-j", "DROP"); err != nil {
			return err
		}
		// An IPv4-only allowlist must not silently leave public IPv6 SSH open.
		if err := run(ctx, "ip6tables", "-A", "WDTT_PANEL_INPUT6", "-p", "tcp", "--dport", port, "-j", "DROP"); err != nil {
			return err
		}
	}
	if f.Stealth {
		if err := run(ctx, "iptables", "-A", "WDTT_PANEL_INPUT", "-p", "icmp", "--icmp-type", "echo-request", "-j", "DROP"); err != nil {
			return err
		}
		if err := run(ctx, "ip6tables", "-A", "WDTT_PANEL_INPUT6", "-p", "ipv6-icmp", "--icmpv6-type", "echo-request", "-j", "DROP"); err != nil {
			return err
		}
	}
	if err := run(ctx, "iptables", "-A", "WDTT_PANEL_INPUT", "-j", "RETURN"); err != nil {
		return err
	}
	if err := run(ctx, "ip6tables", "-A", "WDTT_PANEL_INPUT6", "-j", "RETURN"); err != nil {
		return err
	}
	if err := run(ctx, "iptables", "-I", "INPUT", "1", "-m", "comment", "--comment", "wdtt-panel:input", "-j", "WDTT_PANEL_INPUT"); err != nil {
		return err
	}
	if err := run(ctx, "ip6tables", "-I", "INPUT", "1", "-m", "comment", "--comment", "wdtt-panel:input6", "-j", "WDTT_PANEL_INPUT6"); err != nil {
		return err
	}
	return nil
}

func ensureFirewallPersistence(ctx context.Context) error {
	unit := `[Unit]
Description=WDTT Panel firewall rules
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/wdtt-panel node restore-firewall

[Install]
WantedBy=multi-user.target
`
	if err := os.WriteFile("/etc/systemd/system/wdtt-panel-firewall.service", []byte(unit), 0644); err != nil {
		return err
	}
	if err := run(ctx, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	return run(ctx, "systemctl", "enable", "wdtt-panel-firewall.service")
}

func RestoreFirewall(ctx context.Context) error {
	b, err := os.ReadFile(firewallPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var f FirewallConfig
	if err := json.Unmarshal(b, &f); err != nil {
		return err
	}
	f.defaults()
	return applyFirewallRaw(ctx, f)
}
