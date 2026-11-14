package agent

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Jetvac/wdtt-router/internal/spec"
)

func osRelease() map[string]string {
	m := map[string]string{}
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return m
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		if k, v, ok := strings.Cut(s.Text(), "="); ok {
			m[k] = strings.Trim(v, `"`)
		}
	}
	return m
}

func sleep(ctx context.Context, sec int) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(time.Duration(sec) * time.Second):
		return nil
	}
}

// defaultRoute returns the interface and source address of the IPv4 default route.
func defaultRoute() (string, string) {
	out, err := exec.Command("ip", "-4", "route", "get", "1.1.1.1").Output()
	if err != nil {
		return "", ""
	}
	f := strings.Fields(string(out))
	var dev, src string
	for i := 0; i+1 < len(f); i++ {
		switch f[i] {
		case "dev":
			dev = f[i+1]
		case "src":
			src = f[i+1]
		}
	}
	return dev, src
}

func hasGlobalIPv6() bool {
	out, err := exec.Command("ip", "-6", "route", "show", "default").Output()
	return err == nil && strings.Contains(string(out), "default")
}

func memInfo() (total, avail int64) {
	b, _ := os.ReadFile("/proc/meminfo")
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		v, _ := strconv.ParseInt(f[1], 10, 64)
		switch f[0] {
		case "MemTotal:":
			total = v / 1024
		case "MemAvailable:":
			avail = v / 1024
		}
	}
	return
}

func specHash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

// Inspect reports the observed state of the host.
func Inspect(ctx context.Context) spec.Status {
	s := spec.Status{AgentVersion: Version, Arch: runtime.GOARCH, Problems: []string{}}
	s.Hostname, _ = os.Hostname()
	s.OS = osRelease()["PRETTY_NAME"]
	if out, err := exec.Command("uname", "-r").Output(); err == nil {
		s.Kernel = strings.TrimSpace(string(out))
	}
	s.PublicIface, s.PublicIPv4 = defaultRoute()
	if b, err := os.ReadFile("/proc/uptime"); err == nil {
		f := strings.Fields(string(b))
		if len(f) > 0 {
			v, _ := strconv.ParseFloat(f[0], 64)
			s.UptimeSec = int64(v)
		}
	}
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		f := strings.Fields(string(b))
		if len(f) > 0 {
			s.Load1, _ = strconv.ParseFloat(f[0], 64)
		}
	}
	s.MemTotalMB, s.MemAvailMB = memInfo()
	var fs syscall.Statfs_t
	if syscall.Statfs("/", &fs) == nil {
		s.DiskFreeMB = int64(fs.Bavail) * int64(fs.Bsize) / (1 << 20)
	}

	s.Hardening = inspectHardening(ctx)
	s.NetRxBytes, s.NetTxBytes = ifaceCounters(s.PublicIface)

	if sp, raw, err := loadSaved(); err == nil {
		s.SpecRole = sp.Role
		s.SpecHash = specHash(raw)
		if st, err := os.Stat(specPath); err == nil {
			s.SpecApplied = st.ModTime().UTC().Format(time.RFC3339)
		}
	}

	s.MeshInstalled = have("warp-cli")
	if s.MeshInstalled {
		s.MeshVersion = meshVersion()
		out, _ := warp(ctx, "status")
		s.MeshStatus = "Disconnected"
		if strings.Contains(out, "Connected") {
			s.MeshStatus = "Connected"
		} else if strings.Contains(out, "Connecting") {
			s.MeshStatus = "Connecting"
		} else if strings.Contains(out, "Registration Missing") || strings.Contains(out, "Unable") {
			s.MeshStatus = "Not registered"
		}
		s.MeshIP = MeshAddress()
	}
	s.XrayVersion = xrayInstalledVersion()
	s.XrayInstalled = s.XrayVersion != ""
	s.XrayActive = unitState(xrayUnit)
	s.FirewallActive, s.FirewallPorts = firewallSummary(ctx)
	s.RevertPending = revertPending()
	if firewallReverted() {
		s.Problems = append(s.Problems, "firewall change was automatically reverted after a lost connection")
	}
	std := WDTTServerOf(spec.WDTTStandard)
	s.WDTTInstalled = exists("/etc/systemd/system/" + std.Unit)
	s.WDTTActive = unitState(std.Unit)
	_, err := net.InterfaceByName(std.Iface)
	s.WDTTIface = err == nil
	if s.WDTTInstalled {
		if r := wdttRuntime(std); r != nil {
			s.WDTT = r
			s.WDTTPeers = r.Devices
		}
	}
	tv := WDTTServerOf(spec.WDTTTurnVK)
	if exists("/etc/systemd/system/" + tv.Unit) {
		ts := &spec.WDTTServerStatus{Installed: true, Active: unitState(tv.Unit)}
		_, err := net.InterfaceByName(tv.Iface)
		ts.Iface = err == nil
		ts.Runtime = wdttRuntime(tv)
		s.TurnVK = ts
	}
	s.XUIInstalled = xuiInstalled()
	if s.XUIInstalled {
		s.XUIActive = unitState("x-ui.service")
		s.XUIPorts = XUIPorts()
		s.Problems = append(s.Problems, XUIProblems()...)
	}

	if s.MemAvailMB > 0 && s.MemAvailMB < 80 {
		s.Problems = append(s.Problems, "low free memory")
	}
	if s.DiskFreeMB > 0 && s.DiskFreeMB < 300 {
		s.Problems = append(s.Problems, "low free disk space")
	}
	if s.SpecRole != "" && s.SpecRole != spec.RoleIdle && s.XrayActive != "active" {
		s.Problems = append(s.Problems, "chain hop (Xray) is not running")
	}
	if exists(meshStatePath) && s.MeshStatus != "Connected" {
		s.Problems = append(s.Problems, "Mesh is not connected")
	}
	if s.WDTTInstalled && s.WDTTActive != "active" {
		s.Problems = append(s.Problems, "WDTT service is not running")
	}
	return s
}

// ifaceCounters returns the byte counters of a network interface.
func ifaceCounters(iface string) (rx, tx int64) {
	if iface == "" || strings.ContainsAny(iface, "/.") {
		return 0, 0
	}
	read := func(name string) int64 {
		b, err := os.ReadFile("/sys/class/net/" + iface + "/statistics/" + name)
		if err != nil {
			return 0
		}
		v, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
		return v
	}
	return read("rx_bytes"), read("tx_bytes")
}
