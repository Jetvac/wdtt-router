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
	"strings"

	"github.com/Jetvac/wdtt-router/internal/spec"
)

const (
	wdttBin     = LibDir + "/wdtt-server"
	wdttUnit    = "wdtt-router-wdtt.service"
	wdttDataDir = VarDir + "/wdtt"
	wdttEnvPath = EtcDir + "/wdtt.env"
	tproxyTable = "wdtt_router_wdtt"
	tproxyMark  = "0x1"
	tproxyRT    = "51888"
	tproxyPref  = "10666"
	WDTTIface   = "wdtt0"
	WDTTNet     = "10.66.66.0/24"
)

func wdttUnitText(w spec.WDTTSpec) string {
	dns := w.DNS
	if dns == "" {
		dns = "1.1.1.1"
	}
	// The password is passed through the environment file (mode 0600) so it
	// is not stored in the unit; wdtt-server only accepts it as a flag.
	return fmt.Sprintf(`[Unit]
Description=WDTT server (managed by wdtt-router)
After=network-online.target wdtt-router-xray.service
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=%s
ExecStartPre=-/usr/sbin/ip link del %s
ExecStartPre=%s agent tproxy-routes
ExecStart=%s -listen 0.0.0.0:%d -wg-port %d -config-dir %s -password ${WDTT_PASSWORD} -dns %s
ExecStartPost=-%s agent wdtt-post-start
ExecStopPost=-/usr/sbin/ip link del %s
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
`, wdttEnvPath, WDTTIface, SelfPath, wdttBin, w.DTLSPort, w.WGPort, wdttDataDir, dns, SelfPath, WDTTIface)
}

// tproxyScript diverts everything WDTT clients send to the Internet into the
// local Xray inbound, and drops any forwarding from or to wdtt0. If Xray or
// the chain is down the clients simply have no connectivity — their traffic
// never leaves through the entry server's own address.
func tproxyScript(port int) string {
	return fmt.Sprintf(`table inet %[1]s
delete table inet %[1]s
table inet %[1]s {
	chain prerouting {
		type filter hook prerouting priority mangle; policy accept;
		iifname "%[2]s" ip daddr { 10.66.66.1, 127.0.0.0/8, 224.0.0.0/4, 255.255.255.255 } return
		iifname "%[2]s" meta l4proto { tcp, udp } tproxy ip to 127.0.0.1:%[3]d meta mark set %[4]s accept
	}
	chain forward {
		type filter hook forward priority filter - 10; policy accept;
		iifname "%[2]s" drop
		oifname "%[2]s" drop
	}
}
`, tproxyTable, WDTTIface, port, tproxyMark)
}

// WDTT server source is GPL-3.0 software by amurcanov. It is built on the
// entry server from a pinned commit with a pinned Go toolchain, both verified
// by SHA-256, so the panel never redistributes the binary.
const (
	wdttCommit    = "7355598eae4a359d6874409f3437768f3548565b"
	wdttSourceSHA = "beecfd0b26198e4113b30603c8b5213a621dc71716af7a819c3c419358f746d7"
	goVersion     = "1.27.3"
)

var goSHA = map[string]string{
	"amd64": "65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40",
	"arm64": "a06e99309dbcbdca1a8ccd2282c3ee146e55930886e26b4f1193269587165f49",
}

func buildWDTT(ctx context.Context, changed *[]string) error {
	marker := wdttBin + ".commit"
	if b, err := os.ReadFile(marker); err == nil && strings.TrimSpace(string(b)) == wdttCommit && exists(wdttBin) {
		return nil
	}
	arch := runtime.GOARCH
	sha, ok := goSHA[arch]
	if !ok {
		return fmt.Errorf("unsupported architecture %s", arch)
	}
	dir := VarDir + "/build"
	_ = os.RemoveAll(dir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	Logf("downloading Go %s toolchain to build WDTT (one time, ~75 MB)", goVersion)
	if err := fetchToFile(ctx, "https://go.dev/dl/go"+goVersion+".linux-"+arch+".tar.gz", sha, dir+"/go.tgz"); err != nil {
		return err
	}
	if err := run(ctx, "tar", "-xzf", dir+"/go.tgz", "-C", dir); err != nil {
		return err
	}
	_ = os.Remove(dir + "/go.tgz")
	Logf("downloading WDTT server source (commit %s)", wdttCommit[:12])
	if err := fetchToFile(ctx, "https://codeload.github.com/amurcanov/proxy-turn-vk-android/tar.gz/"+wdttCommit, wdttSourceSHA, dir+"/src.tgz"); err != nil {
		return err
	}
	if err := run(ctx, "tar", "-xzf", dir+"/src.tgz", "-C", dir); err != nil {
		return err
	}
	src := dir + "/proxy-turn-vk-android-" + wdttCommit + "/app/src/main/assets/linux-server"
	Logf("building wdtt-server")
	c := exec.CommandContext(ctx, dir+"/go/bin/go", "build", "-trimpath", "-ldflags=-s -w", "-o", dir+"/wdtt-server", ".")
	c.Dir = src
	c.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=" + dir, "GOPATH=" + dir + "/gopath", "GOCACHE=" + dir + "/cache",
		"GOTOOLCHAIN=local", "GOFLAGS=-mod=readonly", "CGO_ENABLED=0", "GOPROXY=https://proxy.golang.org", "GOSUMDB=sum.golang.org"}
	if out, err := c.CombinedOutput(); err != nil {
		return fmt.Errorf("WDTT build failed: %s", tail(string(out), 500))
	}
	bin, err := os.ReadFile(dir + "/wdtt-server")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(LibDir, 0755); err != nil {
		return err
	}
	if _, err := writeIfChanged(wdttBin, bin, 0755); err != nil {
		return err
	}
	*changed = append(*changed, "wdtt: server built from commit "+wdttCommit[:12])
	_, err = writeIfChanged(marker, []byte(wdttCommit+"\n"), 0644)
	return err
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
	w := spec.WDTTSpec{}
	if e != nil {
		w = e.WDTT
	}
	if !w.Enabled {
		removed := removeUnit(ctx, wdttUnit)
		if removeTProxy(ctx) {
			removed = true
		}
		removeIfExists(wdttEnvPath)
		_ = run(ctx, "ip", "link", "del", WDTTIface)
		if removed {
			*changed = append(*changed, "wdtt: removed (client data kept in "+wdttDataDir+")")
		}
		return nil
	}
	if unitExists("wdtt.service") {
		return errors.New("a WDTT installation not managed by this panel (wdtt.service) exists; remove it first: systemctl disable --now wdtt.service")
	}
	if err := aptInstall(ctx, "nftables", "iproute2", "tar"); err != nil {
		return err
	}
	if err := buildWDTT(ctx, changed); err != nil {
		return err
	}
	if err := os.MkdirAll(wdttDataDir, 0700); err != nil {
		return err
	}
	// Kill switch and diversion go in before the service starts.
	script := tproxyScript(w.TProxy)
	if out, err := runStdin(ctx, script, "nft", "-f", "-"); err != nil {
		return fmt.Errorf("WDTT traffic rules rejected: %s", out)
	}
	if _, err := writeIfChanged(EtcDir+"/wdtt-tproxy.nft", []byte(script), 0600); err != nil {
		return err
	}
	if err := applyTProxyRouting(ctx); err != nil {
		return err
	}
	envChanged, err := writeIfChanged(wdttEnvPath, []byte("WDTT_PASSWORD="+w.Password+"\n"), 0600)
	if err != nil {
		return err
	}
	unitChanged, err := installUnit(ctx, wdttUnit, wdttUnitText(w))
	if err != nil {
		return err
	}
	if envChanged || unitChanged || unitState(wdttUnit) != "active" {
		Logf("starting WDTT server")
		if err := systemctl(ctx, "restart", wdttUnit); err != nil {
			return err
		}
		*changed = append(*changed, "wdtt: service applied")
	}
	if err := waitActive(ctx, wdttUnit); err != nil {
		return err
	}
	for i := 0; i < 15; i++ {
		if _, err := net.InterfaceByName(WDTTIface); err == nil {
			return nil
		}
		if err := sleep(ctx, 1); err != nil {
			return err
		}
	}
	return errors.New("WDTT started but interface wdtt0 did not appear")
}

// WDTTPostStart removes the NAT and FORWARD rules that wdtt-server inserts on
// every start. Our kill switch already blocks forwarding; removing them keeps
// the ruleset clean and makes intent explicit.
func WDTTPostStart(ctx context.Context) {
	for i := 0; i < 20; i++ {
		_ = sleep(ctx, 1)
		if _, err := net.InterfaceByName(WDTTIface); err == nil {
			break
		}
	}
	_ = sleep(ctx, 2)
	for _, args := range [][]string{
		{"-t", "nat", "-S", "POSTROUTING"},
		{"-S", "FORWARD"},
	} {
		out, _ := output(ctx, "iptables", args...)
		for _, line := range strings.Split(out, "\n") {
			if !strings.Contains(line, "WDTT_MANAGED") || !strings.HasPrefix(line, "-A ") {
				continue
			}
			del := append([]string{}, args[:len(args)-2]...)
			del = append(del, "-D")
			del = append(del, strings.Fields(strings.TrimPrefix(line, "-A "))...)
			_ = run(ctx, "iptables", stripQuotes(del)...)
		}
	}
}

func stripQuotes(a []string) []string {
	out := make([]string, len(a))
	for i, s := range a {
		out[i] = strings.Trim(s, "\"")
	}
	return out
}

func wdttPeers() int {
	b, err := os.ReadFile(wdttDataDir + "/passwords.json")
	if err != nil {
		return 0
	}
	var db struct {
		Devices map[string]any `json:"devices"`
	}
	if json.Unmarshal(b, &db) != nil {
		return 0
	}
	return len(db.Devices)
}
