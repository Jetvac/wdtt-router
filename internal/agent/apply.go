package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/Jetvac/wdtt-router/internal/spec"
)

const (
	specPath = EtcDir + "/spec.json"
	bootUnit = "wdtt-router-boot.service"
)

const bootUnitText = `[Unit]
Description=WDTT Router: restore firewall and traffic rules
DefaultDependencies=no
After=local-fs.target
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/wdtt-router agent boot

[Install]
WantedBy=multi-user.target
`

func loadSaved() (*spec.NodeSpec, []byte, error) {
	b, err := os.ReadFile(specPath)
	if err != nil {
		return nil, nil, err
	}
	var s spec.NodeSpec
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, nil, err
	}
	return &s, b, nil
}

// Apply reconciles the whole host to s. Components are applied in an order
// that never opens a gap: the firewall and the WDTT kill switch go first,
// Mesh before the hop that binds to it, and services last.
func Apply(ctx context.Context, s *spec.NodeSpec) (spec.ApplyResult, error) {
	res := spec.ApplyResult{Changed: []string{}, Secrets: map[string]string{}}
	if err := s.Validate(); err != nil {
		return res, err
	}
	unlock, err := Lock(10 * 60e9)
	if err != nil {
		return res, err
	}
	defer unlock()
	if err := os.MkdirAll(EtcDir, 0700); err != nil {
		return res, err
	}
	if err := os.MkdirAll(VarDir, 0700); err != nil {
		return res, err
	}
	steps := []struct {
		name string
		fn   func() error
	}{
		{"boot unit", func() error { _, err := installUnit(ctx, bootUnit, bootUnitText); return err }},
		{"network tuning", func() error { return reconcileSysctl(ctx, &res.Changed) }},
		{"Mesh", func() error { return reconcileMesh(ctx, s.Mesh, &res.Changed) }},
		{"chain hop", func() error { return reconcileXray(ctx, s, &res.Changed) }},
		{"WDTT", func() error { return reconcileWDTT(ctx, s.Entry, &res.Changed) }},
		{"3x-ui", func() error { return reconcileXUI(ctx, s.Entry, &res.Changed, res.Secrets) }},
		{"hardening", func() error { return reconcileHardening(ctx, s.Hardening, &res.Changed) }},
		{"Telegram bot", func() error { return reconcileBot(ctx, s.Bot, &res.Changed) }},
		// The firewall goes last: until then the previous (closed) policy
		// protects new services, and the dead-man timer starts only when
		// nothing slow is left before the controller's confirmation.
		{"firewall", func() error {
			in := FirewallInputs{}
			if s.Hop != nil {
				in.HopPort = s.Hop.Port
			}
			if s.Entry != nil && s.Entry.WDTT.Enabled {
				w := s.Entry.WDTT
				in.WDTT = &w
			}
			if s.Entry != nil && s.Entry.XUI.Enabled {
				in.XUIPorts = XUIPorts()
			}
			pending, err := reconcileFirewall(ctx, s, in, &res.Changed)
			res.RevertPending = pending
			if err != nil {
				return err
			}
			return reconcileMaintain(ctx, s.Entry != nil && (s.Entry.WDTT.Enabled || s.Entry.XUI.Enabled))
		}},
	}
	for _, st := range steps {
		Logf("%s…", st.name)
		if err := st.fn(); err != nil {
			res.Status = Inspect(ctx)
			return res, fmt.Errorf("%s: %w", st.name, err)
		}
	}
	b, _ := json.MarshalIndent(s, "", "  ")
	if _, err := writeIfChanged(specPath, b, 0600); err != nil {
		return res, err
	}
	res.Status = Inspect(ctx)
	return res, nil
}

// Boot restores runtime state (nftables tables and policy rules) that the
// kernel loses on reboot. Services restore themselves through systemd.
func Boot(ctx context.Context) error {
	if b, err := os.ReadFile(fwPath); err == nil {
		if out, err := runStdin(ctx, string(b), "nft", "-f", "-"); err != nil {
			return fmt.Errorf("restore firewall: %s", out)
		}
	}
	if b, err := os.ReadFile(EtcDir + "/wdtt-tproxy.nft"); err == nil {
		if out, err := runStdin(ctx, string(b), "nft", "-f", "-"); err != nil {
			return fmt.Errorf("restore WDTT rules: %s", out)
		}
		if err := applyTProxyRouting(ctx); err != nil {
			return err
		}
	}
	return nil
}

// Uninstall removes everything the agent created on the host. With purge the
// Cloudflare client and local data are removed as well.
func Uninstall(ctx context.Context, purge bool) ([]string, error) {
	unlock, err := Lock(5 * 60e9)
	if err != nil {
		return nil, err
	}
	defer unlock()
	changed := []string{}
	idle := &spec.NodeSpec{Version: spec.Version, Role: spec.RoleIdle}
	if xuiInstalled() {
		if purge {
			// Removes 3x-ui we installed; foreign installations are only detached.
			_ = reconcileXUI(ctx, nil, &changed, map[string]string{})
		} else {
			_ = detachXUI(ctx, &changed)
		}
	}
	_ = reconcileWDTT(ctx, nil, &changed)
	_ = reconcileXray(ctx, idle, &changed)
	if removeUnit(ctx, xrayUnit) {
		changed = append(changed, "xray: removed")
	}
	_ = Confirm(ctx)
	if nftTableExists(ctx, fwTable) {
		_ = run(ctx, "nft", "delete", "table", "inet", fwTable)
		changed = append(changed, "firewall: removed")
	}
	removeUnit(ctx, bootUnit)
	removeHardening(ctx, &changed)
	_ = reconcileBot(ctx, nil, &changed)
	_ = reconcileMaintain(ctx, false)
	removeUnit(ctx, "wdtt-router-xui-sync.timer")
	removeUnit(ctx, "wdtt-router-xui-sync.service")
	_ = reconcileMesh(ctx, spec.MeshSpec{}, &changed)
	if purge {
		purgeWarp(ctx)
		removeIfExists(LibDir+"/xray", VarDir)
	}
	removeIfExists(specPath, fwPath, fwPendingPath, fwPrevPath, xrayConfig, EtcDir+"/wdtt-tproxy.nft", sysctlPath)
	if purge {
		// The running binary can be unlinked on Linux; nothing of the panel
		// stays on the server.
		removeIfExists(EtcDir, LibDir, SelfPath)
	}
	return changed, nil
}

// DecodeSpec reads a spec from JSON.
func DecodeSpec(b []byte) (*spec.NodeSpec, error) {
	var s spec.NodeSpec
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return nil, errors.New("invalid spec: " + err.Error())
	}
	return &s, nil
}
