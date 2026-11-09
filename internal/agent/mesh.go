package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/Jetvac/wdtt-router/internal/spec"
)

const (
	meshStatePath = EtcDir + "/mesh.json"
	warpKeyring   = "/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg"
	warpList      = "/etc/apt/sources.list.d/cloudflare-client.list"
	MeshIface     = "CloudflareWARP"
)

type meshState struct {
	CFNodeID string `json:"cf_node_id"`
	NodeName string `json:"node_name"`
}

func warp(ctx context.Context, args ...string) (string, error) {
	return output(ctx, "warp-cli", append([]string{"--accept-tos"}, args...)...)
}

func installWarp(ctx context.Context) error {
	if have("warp-cli") {
		return nil
	}
	Logf("installing Cloudflare One client (cloudflare-warp)")
	if err := aptInstall(ctx, "ca-certificates", "gnupg", "curl"); err != nil {
		return err
	}
	key, err := fetch(ctx, "https://pkg.cloudflareclient.com/pubkey.gpg", "")
	if err != nil {
		return err
	}
	if _, err := runStdin(ctx, string(key), "gpg", "--yes", "--dearmor", "-o", warpKeyring); err != nil {
		return err
	}
	// apt checks signatures as the unprivileged _apt user: the keyring must
	// be world-readable whatever umask the agent runs with.
	if err := os.Chmod(warpKeyring, 0644); err != nil {
		return err
	}
	codename := osRelease()["VERSION_CODENAME"]
	if codename == "" {
		return errors.New("cannot determine distribution codename")
	}
	line := "deb [signed-by=" + warpKeyring + "] https://pkg.cloudflareclient.com/ " + codename + " main\n"
	if _, err := writeIfChanged(warpList, []byte(line), 0644); err != nil {
		return err
	}
	aptUpdated = false
	if err := aptInstall(ctx, "cloudflare-warp"); err != nil {
		// A repository apt cannot use would break every later apt-get
		// update on this server (security updates included).
		removeIfExists(warpList)
		aptUpdated = false
		return err
	}
	return systemctl(ctx, "enable", "--now", "warp-svc.service")
}

// MeshAddress returns the IPv4 address of the Mesh interface.
func MeshAddress() string {
	ifc, err := net.InterfaceByName(MeshIface)
	if err != nil {
		return ""
	}
	addrs, _ := ifc.Addrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && spec.MeshIP(n.IP.String()) {
			return n.IP.String()
		}
	}
	return ""
}

func meshConnected(ctx context.Context) bool {
	out, _ := warp(ctx, "status")
	return strings.Contains(out, "Connected")
}

func readMeshState() meshState {
	var st meshState
	if b, err := os.ReadFile(meshStatePath); err == nil {
		_ = json.Unmarshal(b, &st)
	}
	return st
}

func registered(ctx context.Context) bool {
	out, err := warp(ctx, "-j", "registration", "show")
	if err != nil {
		return false
	}
	var r struct {
		ID string `json:"id"`
	}
	return json.Unmarshal([]byte(out), &r) == nil && r.ID != ""
}

// reconcileMesh enrols or removes the host from Cloudflare Mesh.
func reconcileMesh(ctx context.Context, m spec.MeshSpec, changed *[]string) error {
	if !m.Enabled {
		if !have("warp-cli") || !exists(meshStatePath) {
			return nil
		}
		Logf("leaving Cloudflare Mesh")
		_, _ = warp(ctx, "disconnect")
		_, _ = warp(ctx, "registration", "delete")
		_ = os.Remove(meshStatePath)
		*changed = append(*changed, "mesh: left")
		return nil
	}
	if err := installWarp(ctx); err != nil {
		return err
	}
	st := readMeshState()
	if st.CFNodeID != m.CFNodeID || !registered(ctx) {
		Logf("registering Mesh node %s", m.NodeName)
		_, _ = warp(ctx, "disconnect")
		_, _ = warp(ctx, "registration", "delete")
		if _, err := warp(ctx, "connector", "new", m.Token); err != nil {
			return errors.New("Mesh registration failed; check that the node token is valid: " + err.Error())
		}
		b, _ := json.Marshal(meshState{CFNodeID: m.CFNodeID, NodeName: m.NodeName})
		if _, err := writeIfChanged(meshStatePath, b, 0600); err != nil {
			return err
		}
		*changed = append(*changed, "mesh: registered")
	}
	if !meshConnected(ctx) || MeshAddress() == "" {
		_, _ = warp(ctx, "connect")
	}
	for i := 0; i < 45; i++ {
		if meshConnected(ctx) && MeshAddress() != "" {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	out, _ := warp(ctx, "status")
	return errors.New("Mesh did not connect within 90 s: " + tail(out, 300))
}

func purgeWarp(ctx context.Context) {
	if have("warp-cli") {
		_, _ = warp(ctx, "disconnect")
		_, _ = warp(ctx, "registration", "delete")
	}
	if exists("/usr/bin/warp-svc") || exists("/bin/warp-svc") {
		Logf("removing cloudflare-warp package")
		_ = run(ctx, "apt-get", "purge", "-y", "-qq", "cloudflare-warp")
	}
	removeIfExists(warpList, warpKeyring, meshStatePath)
}

func meshVersion() string {
	out, err := exec.Command("warp-cli", "--version").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(strings.SplitN(string(out), "\n", 2)[0], "warp-cli "))
}
