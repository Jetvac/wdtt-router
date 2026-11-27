package link

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// The kernel's own view of the tunnel's path, which the tests in network
// namespaces cannot see on a real server: a host may filter by reverse
// path (strict rp_filter drops replies that come in through the tunnel
// from Internet addresses), have forwarding off, or route the exit's
// traffic elsewhere than the agent thinks.

// looseRPF makes reverse path filtering on the tunnel interface loose when
// the host has it strict. The kernel takes the larger of "all" and the
// interface's value, so 2 on the interface wins over a strict 1 for all.
// Loose still drops sources that are not routable at all.
func looseRPF(iface string) {
	all := readInt("/proc/sys/net/ipv4/conf/all/rp_filter")
	own := readInt("/proc/sys/net/ipv4/conf/" + iface + "/rp_filter")
	if max(all, own) == 1 {
		_ = os.WriteFile("/proc/sys/net/ipv4/conf/"+iface+"/rp_filter", []byte("2"), 0644)
	}
}

func readInt(p string) int {
	b, err := os.ReadFile(p)
	if err != nil {
		return 0
	}
	v, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return v
}

// routeVia asks the kernel how it would route a packet from src to dst
// that came in on iif: the interface it leaves by ("local" for this
// server), or why it would be dropped (forwarding off, reverse path).
func routeVia(dst, src, iif string) (string, error) {
	out, err := exec.Command("ip", "-4", "route", "get", dst, "from", src, "iif", iif).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s", strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(out)), "RTNETLINK answers:")))
	}
	f := strings.Fields(string(out))
	if len(f) > 0 && f[0] == "local" {
		return "local", nil
	}
	for i := 0; i+1 < len(f); i++ {
		if f[i] == "dev" {
			return f[i+1], nil
		}
	}
	return "", fmt.Errorf("no interface in %q", strings.TrimSpace(string(out)))
}

// pathProblem checks both ways through this end: what comes out of the
// tunnel and what answers it. "" when the kernel would pass both.
func pathProblem(cfg *Config, entryAddr string) string {
	const internet = "1.1.1.1"
	switch cfg.Role {
	case "exit":
		if _, err := os.Stat("/sys/class/net/" + cfg.PublicIface); err != nil {
			return fmt.Sprintf("интерфейса %s, через который выход ходит в Интернет, нет", cfg.PublicIface)
		}
		dev, err := routeVia(internet, entryAddr, cfg.Iface)
		switch {
		case err != nil:
			return fmt.Sprintf("ядро выхода не пропускает пакеты из туннеля в Интернет: %v", err)
		case dev != cfg.PublicIface:
			return fmt.Sprintf("пакеты из туннеля уходят через %s, а правила выхода ждут %s", dev, cfg.PublicIface)
		}
		if dev, err := routeVia(entryAddr, internet, cfg.PublicIface); err != nil || dev != cfg.Iface {
			return fmt.Sprintf("ответы из Интернета не идут обратно в туннель: %s", errOr(err, dev))
		}
	case "entry":
		if dev, err := routeVia(entryAddr, internet, cfg.Iface); err != nil || dev != "local" {
			return fmt.Sprintf("ядро входа не принимает ответы из туннеля: %s", errOr(err, dev))
		}
	}
	return ""
}

func errOr(err error, dev string) string {
	if err != nil {
		return err.Error()
	}
	return "уходят через " + dev
}

// tunPackets: packets that came out of the tunnel into this server (in)
// and that the server put into the tunnel (out).
func tunPackets(iface string) (in, out uint64) {
	r := func(name string) uint64 {
		b, _ := os.ReadFile("/sys/class/net/" + iface + "/statistics/" + name)
		v, _ := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
		return v
	}
	return r("rx_packets"), r("tx_packets")
}
