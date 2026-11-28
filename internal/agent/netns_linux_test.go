//go:build linux

package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/Jetvac/wdtt-router/internal/link"
	"github.com/Jetvac/wdtt-router/internal/spec"
)

// The chain tunnel end to end, in network namespaces: a client behind the
// entry's "wdtt1", the entry and the exit joined by a "Mesh" veth, an
// "Internet" namespace with a UDP echo and DNS on 1.1.1.1 and 9.9.9.9 that
// the exit and (for leak checks) the entry both reach. The real service
// runs in each namespace with the agent's own rules.
//
// It needs root and runs only with WDTT_NETNS_TEST=1 (CI does that):
//
//	sudo -E WDTT_NETNS_TEST=1 go test -run TestNetnsLink -v ./internal/agent

func TestMain(m *testing.M) {
	if r := os.Getenv("WDTT_NETNS_ROLE"); r != "" {
		os.Exit(netnsRole(r))
	}
	os.Exit(m.Run())
}

// netnsRole runs a helper process of the test (inside "ip netns exec").
func netnsRole(r string) int {
	kind, arg, _ := strings.Cut(r, "=")
	switch kind {
	case "link":
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		if err := link.Run(ctx, arg, "test"); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	case "echo", "dns":
		addr, logp, _ := strings.Cut(arg, ",")
		c, err := net.ListenPacket("udp4", addr)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		f, _ := os.OpenFile(logp, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		buf := make([]byte, 65536)
		for {
			n, src, err := c.ReadFrom(buf)
			if err != nil {
				return 1
			}
			fmt.Fprintln(f, src.String(), n)
			if kind == "dns" && n >= 12 {
				buf[2] |= 0x80 // a response, no error, no answers: enough for the check
				buf[3] &^= 0x0f
			}
			_, _ = c.WriteTo(buf[:n], src)
		}
	case "forward":
		// What the agent does on the exit when it applies the tunnel.
		added, err := ensureLinkForward(context.Background(), arg)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if !added {
			return 3
		}
		return 0
	case "send":
		addr, size, _ := strings.Cut(arg, ",")
		n, _ := strconv.Atoi(size)
		p := make([]byte, n)
		_, _ = rand.Read(p)
		c, err := net.Dial("udp4", addr)
		if err != nil {
			return 1
		}
		got := make([]byte, 65536)
		for try := 0; try < 3; try++ {
			_, _ = c.Write(p)
			_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
			if m, err := c.Read(got); err == nil && bytes.Equal(got[:m], p) {
				return 0
			}
		}
		return 1
	}
	return 2
}

type netns struct {
	t    *testing.T
	self string
	dir  string
	cmds map[string]*exec.Cmd
}

func (n *netns) sh(args ...string) string {
	n.t.Helper()
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		n.t.Fatalf("%s: %v: %s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func (n *netns) in(ns string, args ...string) string {
	n.t.Helper()
	return n.sh(append([]string{"ip", "netns", "exec", ns}, args...)...)
}

func (n *netns) script(ns, script string) error {
	c := exec.Command("ip", "netns", "exec", ns, "nft", "-f", "-")
	c.Stdin = strings.NewReader(script)
	out, err := c.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, out)
	}
	return nil
}

// start runs a helper process in ns under name (its output goes to a log).
func (n *netns) start(name, ns, role string) {
	n.t.Helper()
	log, _ := os.Create(filepath.Join(n.dir, name+".log"))
	c := exec.Command("ip", "netns", "exec", ns, n.self, "-test.run=^$")
	c.Env = append(os.Environ(), "WDTT_NETNS_ROLE="+role)
	c.Stdout, c.Stderr = log, log
	if err := c.Start(); err != nil {
		n.t.Fatal(err)
	}
	n.cmds[name] = c
}

func (n *netns) kill(name string) {
	if c := n.cmds[name]; c != nil {
		_ = c.Process.Signal(syscall.SIGKILL)
		_, _ = c.Process.Wait()
		delete(n.cmds, name)
	}
}

func (n *netns) send(ns, addr string, size int) bool {
	c := exec.Command("ip", "netns", "exec", ns, n.self, "-test.run=^$")
	c.Env = append(os.Environ(), fmt.Sprintf("WDTT_NETNS_ROLE=send=%s,%d", addr, size))
	return c.Run() == nil
}

func (n *netns) status(name string) spec.LinkStatus {
	var st spec.LinkStatus
	b, _ := os.ReadFile(filepath.Join(n.dir, name+".json"))
	_ = json.Unmarshal(b, &st)
	return st
}

func (n *netns) waitFor(what string, within time.Duration, ok func() bool) {
	n.t.Helper()
	deadline := time.Now().Add(within)
	for !ok() {
		if time.Now().After(deadline) {
			n.fatalf("%s: not within %s", what, within)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// leaked: the Internet namespace heard from the entry's own address.
func (n *netns) leaked() bool {
	b, _ := os.ReadFile(filepath.Join(n.dir, "echo.sources"))
	return strings.Contains(string(b), "203.0.113.1:")
}

// heard: how many datagrams of size bytes the Internet's echo got.
func (n *netns) heard(size int) int {
	b, _ := os.ReadFile(filepath.Join(n.dir, "echo.sources"))
	return strings.Count(string(b), fmt.Sprintf(" %d\n", size))
}

// fatalf fails with what it takes to see where packets stopped: both
// ends' status and logs, drops per interface, the Mesh qdisc, UDP socket
// errors, and the entry's routing state.
func (n *netns) fatalf(format string, args ...any) {
	n.t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, format, args...)
	for _, name := range []string{"entry", "exit"} {
		st, _ := os.ReadFile(filepath.Join(n.dir, name+".json"))
		lg, _ := os.ReadFile(filepath.Join(n.dir, name+".log"))
		fmt.Fprintf(&b, "\n--- %s status: %s\n--- %s log:\n%s", name, st, name, lastLines(lg, 40))
	}
	echo, _ := os.ReadFile(filepath.Join(n.dir, "echo.sources"))
	fmt.Fprintf(&b, "\n--- echo heard (source, size):\n%s", lastLines(echo, 15))
	for _, c := range [][]string{
		{"wrt-e", "ip", "-s", "-s", "link"},
		{"wrt-x", "ip", "-s", "-s", "link"},
		{"wrt-e", "tc", "-s", "qdisc", "show", "dev", "e-mesh"},
		{"wrt-e", "grep", "^Udp:", "/proc/net/snmp"},
		{"wrt-x", "grep", "^Udp:", "/proc/net/snmp"},
		{"wrt-e", "nft", "list", "set", "inet", tproxyTable, linkSet},
		{"wrt-e", "ip", "route", "show", "table", linkRT},
	} {
		out, err := exec.Command("ip", append([]string{"netns", "exec"}, c...)...).CombinedOutput()
		fmt.Fprintf(&b, "\n--- %s: %s (err %v)\n%s", c[0], strings.Join(c[1:], " "), err, out)
	}
	n.t.Fatal(b.String())
}

func lastLines(b []byte, k int) string {
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	return strings.Join(lines[max(0, len(lines)-k):], "\n")
}

func wgKeys(t *testing.T) (priv, pub string) {
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	k[0] &= 248
	k[31] = k[31]&127 | 64
	p, err := curve25519.X25519(k, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(k), base64.StdEncoding.EncodeToString(p)
}

func TestNetnsLink(t *testing.T) {
	if os.Getenv("WDTT_NETNS_TEST") != "1" || os.Geteuid() != 0 {
		t.Skip("needs root and WDTT_NETNS_TEST=1")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	n := &netns{t: t, self: self, dir: t.TempDir(), cmds: map[string]*exec.Cmd{}}
	spaces := []string{"wrt-c", "wrt-e", "wrt-x", "wrt-i"}
	for _, ns := range spaces {
		_ = exec.Command("ip", "netns", "del", ns).Run()
		n.sh("ip", "netns", "add", ns)
		n.in(ns, "ip", "link", "set", "lo", "up")
	}
	t.Cleanup(func() {
		for name := range n.cmds {
			n.kill(name)
		}
		for _, ns := range spaces {
			_ = exec.Command("ip", "netns", "del", ns).Run()
		}
	})
	veth := func(a, nsA, addrA, b, nsB, addrB string) {
		n.sh("ip", "link", "add", a, "type", "veth", "peer", "name", b)
		n.sh("ip", "link", "set", a, "netns", nsA)
		n.sh("ip", "link", "set", b, "netns", nsB)
		n.in(nsA, "ip", "addr", "add", addrA, "dev", a)
		n.in(nsB, "ip", "addr", "add", addrB, "dev", b)
		n.in(nsA, "ip", "link", "set", a, "up")
		n.in(nsB, "ip", "link", "set", b, "up")
	}
	veth("c0", "wrt-c", "10.66.67.5/24", "wdtt1", "wrt-e", "10.66.67.1/24")
	veth("e-mesh", "wrt-e", "100.96.0.16/24", "x-mesh", "wrt-x", "100.96.0.17/24")
	veth("x-pub", "wrt-x", "198.51.100.1/24", "i-x", "wrt-i", "198.51.100.2/24")
	veth("e-pub", "wrt-e", "203.0.113.1/24", "i-e", "wrt-i", "203.0.113.2/24")
	n.in("wrt-c", "ip", "route", "add", "default", "via", "10.66.67.1")
	n.in("wrt-e", "ip", "route", "add", "default", "via", "203.0.113.2")
	n.in("wrt-x", "ip", "route", "add", "default", "via", "198.51.100.2")
	n.in("wrt-i", "ip", "addr", "add", "1.1.1.1/32", "dev", "lo")
	n.in("wrt-i", "ip", "addr", "add", "9.9.9.9/32", "dev", "lo")
	if err := exec.Command("ip", "netns", "exec", "wrt-e", "tc", "qdisc", "add", "dev", "e-mesh", "root", "netem", "delay", "20ms", "loss", "1%").Run(); err != nil {
		t.Log("netem unavailable: the Mesh link has no delay or loss")
	}

	// The entry's rules exactly as the agent writes them.
	srv := []WDTTServer{WDTTServerOf(spec.WDTTTurnVK)}
	if err := n.script("wrt-e", tproxyScript(20001, srv, true)); err != nil {
		t.Skipf("nftables here cannot load the entry's rules (TPROXY?): %v", err)
	}
	n.in("wrt-e", "ip", "rule", "add", "pref", tproxyPref, "fwmark", tproxyMark, "lookup", tproxyRT)
	n.in("wrt-e", "ip", "route", "replace", "local", "0.0.0.0/0", "dev", "lo", "table", tproxyRT)
	n.in("wrt-e", "ip", "rule", "add", "pref", linkPrefIface, "iif", "wdtt1", "lookup", linkRT)
	n.in("wrt-e", "ip", "rule", "add", "pref", linkPrefMark, "fwmark", "0x2", "lookup", linkRT)
	n.in("wrt-e", "ip", "route", "replace", "blackhole", "default", "metric", "4096", "table", linkRT)
	if err := n.script("wrt-x", linkExitScript("x-pub")); err != nil {
		t.Fatal(err)
	}
	// A real exit may run ufw or Docker: iptables FORWARD drops what it
	// does not accept. The agent lets the tunnel through it.
	if out, err := exec.Command("ip", "netns", "exec", "wrt-x", "iptables", "-P", "FORWARD", "DROP").CombinedOutput(); err != nil {
		t.Logf("iptables unavailable, FORWARD stays open: %v: %s", err, out)
	} else {
		c := exec.Command("ip", "netns", "exec", "wrt-x", self, "-test.run=^$")
		c.Env = append(os.Environ(), "WDTT_NETNS_ROLE=forward=x-pub")
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("the agent did not open iptables FORWARD for the tunnel: %v: %s", err, out)
		}
	}
	// And filter by reverse path strictly: replies come back through the
	// tunnel from Internet addresses the main table routes elsewhere.
	for _, ns := range []string{"wrt-e", "wrt-x"} {
		n.in(ns, "sysctl", "-qw", "net.ipv4.conf.all.rp_filter=1", "net.ipv4.conf.default.rp_filter=1")
	}

	ePriv, ePub := wgKeys(t)
	xPriv, xPub := wgKeys(t)
	psk, _ := wgKeys(t)
	write := func(name string, c link.Config) {
		c.StatusFile = filepath.Join(n.dir, name+".json")
		if err := c.Validate(); err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(c)
		if err := os.WriteFile(filepath.Join(n.dir, name+".cfg"), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("exit", link.Config{Role: "exit", Iface: LinkIface, Address: linkExitAddr + "/30", MTU: 1280, Listen: "100.96.0.17:41000",
		PrivateKey: xPriv, PeerKey: ePub, PSK: psk, AllowedIP: linkEntryAddr + "/32", MeshIface: "x-mesh", PublicIface: "x-pub"})
	write("entry", link.Config{Role: "entry", Mode: "udp", Iface: LinkIface, Address: linkEntryAddr + "/30", MTU: 1280, Peer: "100.96.0.17:41000",
		PrivateKey: ePriv, PeerKey: xPub, PSK: psk, AllowedIP: "0.0.0.0/0", MeshIface: "e-mesh", WDTTIfaces: []string{"wdtt1"},
		NftTable: tproxyTable, NftSet: linkSet, RouteTable: 51889, Mark: LinkMark})

	n.start("echo", "wrt-i", "echo=0.0.0.0:7,"+filepath.Join(n.dir, "echo.sources"))
	// One server per address, as 1.1.1.1 and 9.9.9.9 answer from the
	// address asked: one on 0.0.0.0 answers from 198.51.100.2, which the
	// exit's NAT does not take for the reply.
	n.start("dns1", "wrt-i", "dns=1.1.1.1:53,"+filepath.Join(n.dir, "dns.sources"))
	n.start("dns9", "wrt-i", "dns=9.9.9.9:53,"+filepath.Join(n.dir, "dns.sources"))
	n.start("exit", "wrt-x", "link="+filepath.Join(n.dir, "exit.cfg"))
	n.start("entry", "wrt-e", "link="+filepath.Join(n.dir, "entry.cfg"))

	// Healthy for 30 s: client UDP moves to the tunnel.
	n.waitFor("client UDP on the tunnel", 75*time.Second, func() bool { return n.status("entry").Routing })
	for _, size := range []int{100, 1200, 1252} {
		if !n.send("wrt-c", "198.51.100.2:7", size) {
			n.fatalf("UDP of %d bytes did not come back through the tunnel", size)
		}
	}
	n.in("wrt-c", "ping", "-c", "3", "-W", "2", "198.51.100.2")
	if n.leaked() {
		n.fatalf("client traffic left from the entry's own address")
	}
	// Both ends see a clear path and count the packets that crossed it.
	n.waitFor("path checks and packet counts", 20*time.Second, func() bool {
		e, x := n.status("entry"), n.status("exit")
		return e.PathProblem == "" && x.PathProblem == "" && x.PublicIface == "x-pub" &&
			e.TunOut > 0 && e.TunIn > 0 && x.TunIn > 0 && x.TunOut > 0
	})

	// Cloudflare lowers the Mesh MTU: big packets go in parts.
	n.in("wrt-e", "ip", "link", "set", "e-mesh", "mtu", "1147")
	n.in("wrt-x", "ip", "link", "set", "x-mesh", "mtu", "1147")
	for _, side := range []string{"entry", "exit"} {
		n.waitFor(side+"'s datagrams follow the MTU", 10*time.Second, func() bool {
			st := n.status(side)
			return st.Datagram > 0 && st.Datagram <= 1147-28
		})
	}
	split, heard := n.status("entry").Split, n.heard(1252)
	if !n.send("wrt-c", "198.51.100.2:7", 1252) {
		// Which way broke: whether the big one reached the Internet (the
		// entry's parts were put together) and only the answer was lost,
		// and whether a packet that still fits one datagram passes.
		got := n.heard(1252) - heard
		whole := n.send("wrt-c", "198.51.100.2:7", 1000)
		n.fatalf("a full-size packet did not pass at MTU 1147 (the echo heard %d of 3 tries; a 1000-byte one passes: %v)", got, whole)
	}
	n.waitFor("sent in parts", 5*time.Second, func() bool { return n.status("entry").Split > split })

	// A restart of the entry's service keeps client UDP on the tunnel: the
	// new run takes over the kernel's timed entry.
	n.kill("entry")
	n.start("entry", "wrt-e", "link="+filepath.Join(n.dir, "entry.cfg"))
	restarted := time.Now().Unix()
	n.waitFor("routing kept through a restart", 8*time.Second, func() bool {
		st := n.status("entry")
		return st.Routing && st.StartedAt >= restarted
	})
	if !n.send("wrt-c", "198.51.100.2:7", 500) {
		n.fatalf("no traffic after a restart")
	}

	// Mesh itself goes quiet for a few seconds: Xray, which rides it too,
	// could not carry anything either, so client UDP waits in the tunnel
	// and the outage is reported.
	before := n.status("entry").SwitchAt
	if err := n.script("wrt-e", `table inet wrtest {
	chain out {
		type filter hook output priority 0; policy accept;
		oifname "e-mesh" drop
	}
}
`); err != nil {
		n.fatalf("%v", err)
	}
	time.Sleep(6 * time.Second)
	if st := n.status("entry"); !st.Routing || st.SwitchAt != before {
		n.fatalf("client UDP left the tunnel during a Mesh outage: %+v", st)
	}
	n.in("wrt-e", "nft", "delete", "table", "inet", "wrtest")
	n.waitFor("the Mesh outage reported", 10*time.Second, func() bool { return n.status("entry").MeshOuts > 0 })
	if st := n.status("entry"); !st.Routing || st.SwitchAt != before {
		n.fatalf("client UDP left the tunnel after a Mesh outage: %+v", st)
	}
	if !n.send("wrt-c", "198.51.100.2:7", 500) {
		n.fatalf("no traffic after a Mesh outage")
	}

	// Mesh drops the tunnel: within a few seconds UDP leaves it (to Xray,
	// absent here: dropped, never leaked), and comes back once healthy.
	if err := n.script("wrt-e", `table inet wrtest {
	chain out {
		type filter hook output priority 0; policy accept;
		oifname "e-mesh" udp dport 41000 drop
	}
}
`); err != nil {
		n.fatalf("%v", err)
	}
	n.waitFor("client UDP off a dead tunnel", 10*time.Second, func() bool { return !n.status("entry").Routing })
	if st := n.status("entry"); st.SwitchTo != "xray" || st.SwitchWhy == "" {
		n.fatalf("switch not reported: %+v", st)
	}
	_ = n.send("wrt-c", "198.51.100.2:7", 100)
	if n.leaked() {
		n.fatalf("client traffic leaked while the tunnel was down")
	}
	n.in("wrt-e", "nft", "delete", "table", "inet", "wrtest")
	n.waitFor("client UDP back on the tunnel", 60*time.Second, func() bool { return n.status("entry").Routing })
	if !n.send("wrt-c", "198.51.100.2:7", 1200) {
		n.fatalf("no traffic after the tunnel came back")
	}

	// The service dies for good: the kernel lets UDP off the tunnel by itself.
	n.kill("entry")
	n.waitFor("the kernel's entry lapses", 10*time.Second, func() bool {
		out, _ := exec.Command("ip", "netns", "exec", "wrt-e", "nft", "list", "set", "inet", tproxyTable, linkSet).CombinedOutput()
		return !strings.Contains(string(out), "elements =")
	})
	_ = n.send("wrt-c", "198.51.100.2:7", 100)
	if n.leaked() {
		n.fatalf("client traffic leaked with the service gone")
	}
	if b, _ := os.ReadFile(filepath.Join(n.dir, "dns.sources")); len(b) == 0 {
		n.fatalf("the entry's DNS checks never went through the tunnel")
	}
}
