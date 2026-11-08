package agent

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/Jetvac/wdtt-router/internal/spec"
)

const (
	// The drop-in is named so that it sorts before cloud-init's
	// 50-cloud-init.conf: for most options sshd keeps the first value.
	sshdDropIn     = "/etc/ssh/sshd_config.d/00-wdtt-router.conf"
	sshdMain       = "/etc/ssh/sshd_config"
	rootKeys       = "/root/.ssh/authorized_keys"
	autoUpgrades   = "/etc/apt/apt.conf.d/20auto-upgrades"
	sshdBegin      = "# wdtt-router: begin (managed by the panel, read before any Include)"
	sshdEnd        = "# wdtt-router: end"
	keysBegin      = "# wdtt-router: administrator keys (managed by the panel)"
	keysEnd        = "# wdtt-router: end of administrator keys"
	managedAptMark = "// Managed by wdtt-router."
)

const sshdHardened = `PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PermitEmptyPasswords no
PermitRootLogin prohibit-password
MaxAuthTries 4
LoginGraceTime 30
`

const autoUpgradesText = managedAptMark + `
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
`

// reconcileHardening applies the host hardening. Keys go first, so that
// turning passwords off in the same apply never leaves root without a way in.
func reconcileHardening(ctx context.Context, h spec.HardeningSpec, changed *[]string) error {
	if ch, err := syncAdminKeys(h.AdminKeys); err != nil {
		return fmt.Errorf("SSH keys: %w", err)
	} else if ch {
		*changed = append(*changed, fmt.Sprintf("ssh: administrator keys updated (%d)", len(h.AdminKeys)))
	}
	if err := reconcileSSHD(ctx, h.SSHKeysOnly, changed); err != nil {
		return err
	}
	return reconcileAutoUpdates(ctx, h.AutoUpdates, changed)
}

// syncAdminKeys rewrites the marked block of root's authorized_keys and
// leaves every other line (the panel's key, keys added by hand) alone.
func syncAdminKeys(keys []string) (bool, error) {
	old, err := os.ReadFile(rootKeys)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	var kept []string
	in := false
	for _, line := range strings.Split(strings.TrimRight(string(old), "\n"), "\n") {
		switch {
		case line == keysBegin:
			in = true
		case line == keysEnd:
			in = false
		case !in && line != "":
			kept = append(kept, line)
		}
	}
	out := kept
	if len(keys) > 0 {
		out = append(append(append(out, keysBegin), keys...), keysEnd)
	}
	text := strings.Join(out, "\n")
	if text != "" {
		text += "\n"
	}
	if text == string(old) || (text == "" && len(old) == 0) {
		return false, nil
	}
	if err := os.MkdirAll("/root/.ssh", 0700); err != nil {
		return false, err
	}
	return writeIfChanged(rootKeys, []byte(text), 0600)
}

func countKeys(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 64*1024)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" && !strings.HasPrefix(l, "#") {
			n++
		}
	}
	return n
}

func reconcileSSHD(ctx context.Context, keysOnly bool, changed *[]string) error {
	// Earlier builds used a drop-in; providers ship drop-ins that sort
	// before it, so the settings now live at the top of sshd_config.
	legacy := removeIfExists(sshdDropIn)
	if !have("sshd") {
		if keysOnly {
			return errors.New("sshd not found")
		}
		return nil
	}
	if keysOnly && countKeys(rootKeys) == 0 {
		return errors.New("root has no SSH key: add your key first, otherwise only the provider's console will let you in")
	}
	block := ""
	if keysOnly {
		block = sshdHardened
	}
	old, err := os.ReadFile(sshdMain)
	if err != nil {
		return err
	}
	next := withTopBlock(string(old), block)
	if next != string(old) {
		if err := os.WriteFile(sshdMain, []byte(next), 0644); err != nil {
			return err
		}
		if out, err := output(ctx, "sshd", "-t"); err != nil {
			_ = os.WriteFile(sshdMain, old, 0644)
			return fmt.Errorf("sshd rejected the settings: %s", tail(out, 300))
		}
	}
	if next != string(old) || legacy {
		if err := reloadSSHD(ctx); err != nil {
			return err
		}
		if keysOnly {
			*changed = append(*changed, "ssh: logins by key only")
		} else {
			*changed = append(*changed, "ssh: password logins allowed again")
		}
	}
	if keysOnly {
		if eff := sshdEffective(ctx); eff["passwordauthentication"] != "no" {
			return errors.New("sshd still allows passwords: another setting overrides the panel's (check /etc/ssh/sshd_config)")
		}
	}
	return nil
}

// withTopBlock puts the managed block at the very top of sshd_config, where
// it is read before any Include; sshd keeps the first value of an option.
func withTopBlock(conf, block string) string {
	var rest []string
	in := false
	for _, line := range strings.Split(conf, "\n") {
		switch {
		case line == sshdBegin:
			in = true
		case line == sshdEnd:
			in = false
		case !in:
			rest = append(rest, line)
		}
	}
	out := strings.Join(rest, "\n")
	if block == "" {
		return out
	}
	return sshdBegin + "\n" + block + sshdEnd + "\n" + out
}

func reloadSSHD(ctx context.Context) error {
	if err := systemctl(ctx, "reload", "ssh"); err == nil {
		return nil
	}
	return systemctl(ctx, "reload", "sshd")
}

// sshdEffective returns sshd's effective settings (lower-case keys).
func sshdEffective(ctx context.Context) map[string]string {
	out, err := output(ctx, "sshd", "-T", "-C", "user=root,host=localhost,addr=127.0.0.1")
	if err != nil {
		out, _ = output(ctx, "sshd", "-T")
	}
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), " "); ok {
			if _, seen := m[k]; !seen {
				m[k] = v
			}
		}
	}
	return m
}

func reconcileAutoUpdates(ctx context.Context, on bool, changed *[]string) error {
	if !on {
		if b, err := os.ReadFile(autoUpgrades); err == nil && strings.HasPrefix(string(b), managedAptMark) {
			_ = os.Remove(autoUpgrades)
			*changed = append(*changed, "updates: automatic security updates off")
		}
		return nil
	}
	if !have("unattended-upgrade") {
		if err := aptInstall(ctx, "unattended-upgrades"); err != nil {
			return err
		}
	}
	ch, err := writeIfChanged(autoUpgrades, []byte(autoUpgradesText), 0644)
	if err != nil {
		return err
	}
	if ch {
		*changed = append(*changed, "updates: automatic security updates on")
	}
	return nil
}

func inspectHardening(ctx context.Context) *spec.HardeningStatus {
	h := &spec.HardeningStatus{RootKeys: countKeys(rootKeys), RebootRequired: exists("/var/run/reboot-required")}
	if have("sshd") {
		eff := sshdEffective(ctx)
		h.SSHPasswordAuth = eff["passwordauthentication"] != "no" || eff["kbdinteractiveauthentication"] == "yes"
		h.SSHRootLogin = eff["permitrootlogin"]
	}
	if have("unattended-upgrade") {
		out, _ := output(ctx, "apt-config", "dump", "APT::Periodic::Unattended-Upgrade")
		h.AutoUpdates = strings.Contains(out, `"1"`)
	}
	return h
}

// removeHardening undoes the panel's host changes on uninstall.
func removeHardening(ctx context.Context, changed *[]string) {
	_, _ = syncAdminKeys(nil)
	_ = reconcileSSHD(ctx, false, changed)
	_ = reconcileAutoUpdates(ctx, false, changed)
}
