package node

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const wdttURL = "https://raw.githubusercontent.com/XXcipherX/vkturn-vps-setup/0bb8fe58fe9a30a244f56b132a1d1cf49aab15d6/wdtt-systemd-setup.sh"
const wdttSHA = "7472a5733e8bbede93af852f87bed9ba5ccfca5a39187831275555748af2755b"
const xuiURL = "https://raw.githubusercontent.com/MHSanaei/3x-ui/v3.8.5/install.sh"
const xuiSHA = "4e3fe7fe00ef8e904ce6a0e9c36fd8a0c7179fe5e786f23e31801aee84c6347d"

type Request struct {
	Action       string             `json:"action"`
	SnapshotID   string             `json:"snapshot_id,omitempty"`
	ManagementIP string             `json:"management_ip,omitempty"`
	Password     string             `json:"password,omitempty"`
	VKLink       string             `json:"vk_link,omitempty"`
	PublicHost   string             `json:"public_host,omitempty"`
	DTLSPort     int                `json:"dtls_port,omitempty"`
	WGPort       int                `json:"wg_port,omitempty"`
	Mesh         *MeshConfig        `json:"mesh,omitempty"`
	Firewall     *FirewallConfig    `json:"firewall,omitempty"`
	VLESS        *VLESSConfig       `json:"vless,omitempty"`
	VLESSClient  *VLESSClientConfig `json:"vless_client,omitempty"`
}

type Result struct {
	Message    string            `json:"message"`
	Status     *Status           `json:"status,omitempty"`
	Secret     map[string]string `json:"secret,omitempty"`
	RecoveryID string            `json:"recovery_id,omitempty"`
}

func fetchPinned(ctx context.Context, url, want, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("installer download HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return err
	}
	if len(b) == 0 || len(b) >= 2<<20 {
		return errors.New("invalid installer size")
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != want {
		return errors.New("installer SHA-256 mismatch")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0700)
}

func validPassword(p string) bool {
	return regexp.MustCompile(`^[A-Za-z0-9._-]{16,128}$`).MatchString(p)
}
func validPublicHost(h string) bool {
	if h == "" {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.To4() != nil && !ip.IsLoopback() && !ip.IsPrivate()
	}
	return regexp.MustCompile(`^[A-Za-z0-9.-]{1,253}$`).MatchString(h) && strings.Contains(h, ".")
}

func Apply(ctx context.Context, r Request) (Result, error) {
	switch r.Action {
	case "status":
		s := Inspect(ctx)
		return Result{Message: "Observed state refreshed", Status: &s}, nil
	case "wdtt.import":
		return importWDTT(ctx)
	case "wdtt.install", "wdtt.reconfigure":
		return wdttInstall(ctx, r)
	case "wdtt.start", "wdtt.stop", "wdtt.restart":
		verb := strings.TrimPrefix(r.Action, "wdtt.")
		if err := run(ctx, "systemctl", verb, "wdtt.service"); err != nil {
			return Result{}, err
		}
		s := Inspect(ctx)
		return Result{Message: "WDTT " + verb + " complete", Status: &s}, nil
	case "wdtt.uninstall":
		if err := fetchPinned(ctx, wdttURL, wdttSHA, "/var/lib/wdtt-panel/installers/wdtt-systemd-setup.sh"); err != nil {
			return Result{}, err
		}
		if err := run(ctx, "bash", "/var/lib/wdtt-panel/installers/wdtt-systemd-setup.sh", "uninstall"); err != nil {
			return Result{}, err
		}
		return Result{Message: "WDTT service removed; configuration preserved"}, nil
	case "xui.install":
		return xuiInstall(ctx)
	case "xui.credentials":
		if _, err := os.Stat("/etc/wdtt-panel/xui-owned.json"); err != nil {
			return Result{}, errors.New("3x-ui is not panel-owned")
		}
		secret := readXUIInstallResult()
		if secret["XUI_USERNAME"] == "" || secret["XUI_PASSWORD"] == "" || secret["XUI_PANEL_PORT"] == "" {
			return Result{}, errors.New("3x-ui installation credentials unavailable")
		}
		return Result{Message: "Saved 3x-ui access refreshed", Secret: secret}, nil
	case "xui.warp.enable":
		return EnableXUIWarp(ctx)
	case "xui.warp.disable":
		return DisableXUIWarp(ctx)
	case "xui.start", "xui.stop", "xui.restart":
		verb := strings.TrimPrefix(r.Action, "xui.")
		if err := run(ctx, "systemctl", verb, "x-ui.service"); err != nil {
			return Result{}, err
		}
		return Result{Message: "3x-ui " + verb + " complete"}, nil
	case "vless.enable":
		if r.VLESS == nil {
			return Result{}, errors.New("VLESS configuration required")
		}
		return EnableVLESS(ctx, *r.VLESS)
	case "vless.disable":
		return DisableVLESS(ctx)
	case "vless.repair":
		return RepairVLESS(ctx)
	case "vless.client.enable":
		if r.VLESSClient == nil {
			return Result{}, errors.New("VLESS client profile required")
		}
		return EnableVLESSClient(ctx, *r.VLESSClient)
	case "vless.client.disable":
		return DisableVLESSClient(ctx)
	case "mesh.install":
		if r.Mesh == nil {
			return Result{}, errors.New("mesh config required")
		}
		return InstallMesh(ctx, *r.Mesh)
	case "mesh.uninstall":
		if err := removeOwnedMesh(ctx); err != nil {
			return Result{}, err
		}
		s := Inspect(ctx)
		return Result{Message: "Panel-owned Mesh container removed", Status: &s}, nil
	case "mesh.restart":
		return RestartMesh(ctx)
	case "routing.apply":
		if r.Mesh == nil {
			return Result{}, errors.New("mesh config required")
		}
		return ApplyRouting(ctx, *r.Mesh)
	case "firewall.apply":
		if r.Firewall == nil {
			return Result{}, errors.New("firewall config required")
		}
		return ApplyFirewall(ctx, *r.Firewall)
	case "recovery.restore":
		return RestoreSnapshot(ctx, r.SnapshotID, r.ManagementIP)
	default:
		return Result{}, fmt.Errorf("unsupported action: %s", r.Action)
	}
}

func wdttInstall(ctx context.Context, r Request) (Result, error) {
	if _, err := os.Stat("/etc/wdtt-mesh-egress.conf"); err == nil {
		return Result{}, errors.New("legacy WDTT router detected; import it without changing its configuration")
	}
	if !validPassword(r.Password) {
		return Result{}, errors.New("WDTT password must have 16–128 safe characters")
	}
	if !validPublicHost(r.PublicHost) {
		return Result{}, errors.New("invalid public host")
	}
	if r.VKLink != "" && !strings.HasPrefix(r.VKLink, "https://vk.ru/call/join/") {
		return Result{}, errors.New("invalid VK Call link")
	}
	if r.DTLSPort == 0 {
		r.DTLSPort = 56000
	}
	if r.WGPort == 0 {
		r.WGPort = 56001
	}
	if r.DTLSPort < 1 || r.DTLSPort > 65535 || r.WGPort < 1 || r.WGPort > 65535 || r.DTLSPort == r.WGPort {
		return Result{}, errors.New("invalid WDTT ports")
	}
	path := "/var/lib/wdtt-panel/installers/wdtt-systemd-setup.sh"
	if err := fetchPinned(ctx, wdttURL, wdttSHA, path); err != nil {
		return Result{}, err
	}
	c := exec.CommandContext(ctx, "bash", path, "install")
	if err := os.MkdirAll("/var/cache/wdtt-panel/go-build", 0700); err != nil {
		return Result{}, err
	}
	c.Env = append(os.Environ(), "HOME=/var/lib/wdtt-panel", "GOPATH=/var/cache/wdtt-panel/go", "GOCACHE=/var/cache/wdtt-panel/go-build", "WDTT_PASSWORD="+r.Password, "WDTT_VK_LINK="+r.VKLink, "WDTT_DTLS_PORT="+strconv.Itoa(r.DTLSPort), "WDTT_WG_PORT="+strconv.Itoa(r.WGPort))
	if r.PublicHost != "" {
		c.Env = append(c.Env, "WDTT_PUBLIC_HOST="+r.PublicHost)
	}
	// Upstream prints a wdtt:// URL containing the password. Never return its raw output.
	out, err := c.CombinedOutput()
	if err != nil {
		return Result{}, fmt.Errorf("WDTT installer failed: %w: %s", err, safeInstallerError(string(out), r.Password, r.VKLink))
	}
	s := Inspect(ctx)
	if s.WDTTService != "active" || !s.WDTTInterface {
		return Result{}, errors.New("WDTT installer finished but service/interface not ready")
	}
	return Result{Message: "WDTT installed and service/interface verified", Status: &s}, nil
}

func importWDTT(ctx context.Context) (Result, error) {
	loadState, err := command(ctx, "systemctl", "show", "-p", "LoadState", "--value", "wdtt.service")
	if err != nil || loadState != "loaded" {
		return Result{}, errors.New("existing wdtt.service was not found")
	}
	legacy := false
	if _, err := os.Stat("/etc/wdtt-mesh-egress.conf"); err == nil {
		legacy = true
	}
	if err := os.MkdirAll("/etc/wdtt-panel", 0700); err != nil {
		return Result{}, err
	}
	b, _ := json.Marshal(map[string]any{"source": "existing-service", "legacy_v022": legacy, "imported_at": time.Now().UTC().Format(time.RFC3339)})
	if err := os.WriteFile("/etc/wdtt-panel/wdtt-import.json", b, 0600); err != nil {
		return Result{}, err
	}
	s := Inspect(ctx)
	message := "Existing WDTT service imported without changing its configuration"
	if legacy {
		message = "Legacy v0.2.2 router discovered; existing service and configuration preserved"
	}
	return Result{Message: message, Status: &s}, nil
}

func xuiInstall(ctx context.Context) (Result, error) {
	const ownershipFile = "/etc/wdtt-panel/xui-owned.json"
	_, binErr := os.Stat("/usr/local/x-ui/x-ui")
	newInstall := errors.Is(binErr, os.ErrNotExist)
	if binErr != nil && !newInstall {
		return Result{}, binErr
	}
	if !newInstall {
		if _, err := os.Stat(ownershipFile); err != nil {
			return Result{}, errors.New("existing 3x-ui is not panel-owned; import it before changing settings")
		}
	}
	path := "/var/lib/wdtt-panel/installers/xui-install.sh"
	if newInstall {
		if err := fetchPinned(ctx, xuiURL, xuiSHA, path); err != nil {
			return Result{}, err
		}
		c := exec.CommandContext(ctx, "bash", path, "v3.8.5")
		c.Env = append(os.Environ(), "HOME=/var/lib/wdtt-panel", "XUI_NONINTERACTIVE=1", "XUI_SSL_MODE=none", "XUI_DB_TYPE=sqlite")
		out, err := c.CombinedOutput()
		if err != nil {
			return Result{}, fmt.Errorf("3x-ui installer failed: %w: %s", err, safeInstallerError(string(out)))
		}
	}
	if err := secureXUISubscription(ctx); err != nil {
		return Result{}, err
	}
	if err := run(ctx, "/usr/local/x-ui/x-ui", "setting", "-listenIP", "127.0.0.1"); err != nil {
		return Result{}, err
	}
	if err := run(ctx, "systemctl", "restart", "x-ui.service"); err != nil {
		return Result{}, err
	}
	s := Inspect(ctx)
	if s.XUIService != "active" {
		return Result{}, errors.New("3x-ui did not become active")
	}
	if newInstall {
		b, _ := json.Marshal(map[string]string{"managed_by": "wdtt-panel", "version": "3.8.5"})
		if err := os.WriteFile(ownershipFile, b, 0600); err != nil {
			return Result{}, err
		}
	}
	// Install credentials are returned only across the encrypted SSH transport and
	// stored by the controller as AES-GCM fields. Never emit them in job logs.
	secret := readXUIInstallResult()
	return Result{Message: "3x-ui installed; management and subscriptions bound to 127.0.0.1", Status: &s, Secret: secret}, nil
}

func secureXUISubscription(ctx context.Context) error {
	db, err := sql.Open("sqlite3", "file:/etc/x-ui/x-ui.db?mode=rw&_busy_timeout=5000")
	if err != nil {
		return err
	}
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, "UPDATE settings SET value='127.0.0.1' WHERE key='subListen'")
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		if _, err := tx.ExecContext(ctx, "INSERT INTO settings(key,value) VALUES('subListen','127.0.0.1')"); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func safeInstallerError(output string, secrets ...string) string {
	message := "see installer logs on the node"
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[wdtt-setup] ") && !strings.Contains(line, "link:") {
			message = "last phase: " + line
		}
		if strings.Contains(line, "ERROR:") || strings.Contains(line, "Error:") {
			message = line
		}
	}
	for _, secret := range secrets {
		if secret != "" {
			message = strings.ReplaceAll(message, secret, "<redacted>")
		}
	}
	message = regexp.MustCompile(`(?i)(wdtt|vless)://\S+`).ReplaceAllString(message, "<redacted-profile>")
	if len(message) > 240 {
		message = message[:240]
	}
	return message
}

func redactXUI(s string) string {
	for _, key := range []string{"password", "apiToken", "username"} {
		s = regexp.MustCompile(`(?i)(`+key+`)[=:][^\s]+`).ReplaceAllString(s, `${1}=<redacted>`)
	}
	return s
}

func readXUIInstallResult() map[string]string {
	b, err := os.ReadFile("/etc/x-ui/install-result.env")
	if err != nil {
		return nil
	}
	result := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.Trim(strings.TrimSpace(parts[1]), "'\"")
		if len(value) > 512 {
			continue
		}
		switch key {
		case "XUI_USERNAME", "XUI_PASSWORD", "XUI_PANEL_PORT", "XUI_WEB_BASE_PATH", "XUI_SCHEME":
			result[key] = value
		}
	}
	return result
}
