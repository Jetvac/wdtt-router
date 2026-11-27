package agent

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Jetvac/wdtt-router/internal/spec"
)

func testKey() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

// With the tunnel off, the entry's traffic rules are exactly those of the
// versions before it: a panel update changes nothing on a running server.
func TestTProxyScriptUnchangedWithoutLink(t *testing.T) {
	want := fmt.Sprintf(`table inet %[1]s
delete table inet %[1]s
table inet %[1]s {
	chain prerouting {
		type filter hook prerouting priority mangle; policy accept;
		iifname { %[2]s } ip daddr { %[5]s, 127.0.0.0/8, 224.0.0.0/4, 255.255.255.255 } return
		iifname { %[2]s } meta l4proto { tcp, udp } tproxy ip to 127.0.0.1:%[3]d meta mark set %[4]s accept
	}
	chain forward {
		type filter hook forward priority filter - 10; policy accept;
		iifname { %[2]s } drop
		oifname { %[2]s } drop
	}
}
`, tproxyTable, `"wdtt0", "wdtt1"`, 30001, tproxyMark, "10.66.66.1, 10.66.67.1")
	if got := tproxyScript(30001, WDTTServers, false); got != want {
		t.Fatalf("the script changed:\n%s", got)
	}
}

func TestTProxyScriptWithLink(t *testing.T) {
	s := tproxyScript(30001, WDTTServers, true)
	if strings.Contains(s, "delete table") || strings.Contains(s, "flush set") || strings.Contains(s, "flush table") {
		t.Fatal("re-applying the rules must keep the tunnel's set")
	}
	if !strings.Contains(s, "add set inet wdtt_router_wdtt via_link { type ifname; flags timeout; }") {
		t.Fatal("no timed set")
	}
	udp := strings.Index(s, "iifname @via_link meta l4proto udp accept")
	tp := strings.Index(s, "tproxy ip to 127.0.0.1:30001")
	ret := strings.Index(s, "ip daddr { 10.66.66.1, 10.66.67.1,")
	if udp < 0 || tp < 0 || ret < 0 || !(ret < udp && udp < tp) {
		t.Fatal("client UDP on the tunnel must skip TPROXY, after the servers' own addresses")
	}
	if strings.Contains(s, "via_link meta l4proto tcp") || strings.Contains(s, "via_link meta l4proto { tcp") {
		t.Fatal("TCP stays on Xray")
	}
	for _, want := range []string{
		`forward iifname @via_link oifname "wrlink0" meta l4proto { udp, icmp } accept`,
		`forward iifname "wrlink0" oifname { "wdtt0", "wdtt1" } ct state established,related accept`,
		`forward iifname { "wdtt0", "wdtt1" } drop`,
		`forward oifname { "wdtt0", "wdtt1" } drop`,
		`forward iifname "wrlink0" drop`,
		`oifname "wrlink0" ip saddr { 10.66.66.0/24, 10.66.67.0/24 } snat ip to 10.66.80.1`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q", want)
		}
	}
	// The accept to the tunnel comes before the kill switch.
	if strings.Index(s, `oifname "wrlink0" meta l4proto`) > strings.Index(s, `forward iifname { "wdtt0", "wdtt1" } drop`) {
		t.Fatal("kill switch before the tunnel's accept")
	}
}

func TestLinkExitScript(t *testing.T) {
	s := linkExitScript("eth0")
	for _, want := range []string{
		`iifname "wrlink0" oifname "eth0" ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10,`,
		`iifname "wrlink0" oifname "eth0" tcp dport 25 drop`,
		`iifname "wrlink0" oifname "eth0" ip saddr 10.66.80.1 accept`,
		`iifname "eth0" oifname "wrlink0" ct state established,related accept`,
		`oifname "wrlink0" drop`,
		`iifname "eth0" oifname { "eth0", "CloudflareWARP" } drop`,
		`iifname "wrlink0" drop`,
		`oifname "eth0" ip saddr 10.66.80.1 masquerade`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q", want)
		}
	}
	if strings.Contains(s, "::") {
		t.Fatal("IPv6 ranges in an IPv4 rule")
	}
}

func linkSpecs() (entry, exit, relay *spec.NodeSpec) {
	ek, xk, psk := testKey(), testKey(), testKey()
	w := spec.WDTTSpec{Enabled: true, DTLSPort: 56010, WGPort: 56011, Password: "owner-password-0123", TProxy: 20001}
	entry = &spec.NodeSpec{Version: spec.Version, Role: spec.RoleEntry,
		Entry: &spec.EntrySpec{Chain: []spec.OnionHop{}, SocksPort: 20000, SocksUser: "user01", SocksPass: "pass0123456789abcdef", TurnVK: &w},
		Link:  &spec.LinkSpec{Mode: spec.LinkCheck, Next: &spec.NextHop{Addr: "100.96.0.17", Port: 41000}, PrivateKey: ek, PeerKey: xk, PSK: psk, MTU: 1280}}
	hk, _ := spec.NewHopKeys()
	mesh := spec.MeshSpec{Enabled: true, NodeName: "node", Token: "token"}
	exit = &spec.NodeSpec{Version: spec.Version, Role: spec.RoleExit, Mesh: mesh,
		Hop:  &spec.HopSpec{Port: 41000, UUID: spec.NewUUID(), Decryption: hk.Decryption},
		Link: &spec.LinkSpec{Mode: spec.LinkOn, Port: 41000, PrivateKey: xk, PeerKey: ek, PSK: psk, MTU: 1280}}
	relay = &spec.NodeSpec{Version: spec.Version, Role: spec.RoleRelay, Mesh: mesh,
		Hop:  &spec.HopSpec{Port: 42000, UUID: spec.NewUUID(), Decryption: hk.Decryption, Next: &spec.NextHop{Addr: "100.96.0.17", Port: 41000}},
		Link: &spec.LinkSpec{Mode: spec.LinkOn, Port: 42000, Next: &spec.NextHop{Addr: "100.96.0.17", Port: 41000}}}
	return
}

func TestLinkConfig(t *testing.T) {
	entry, exit, relay := linkSpecs()
	c, err := LinkConfig(entry, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if c.Peer != "100.96.0.17:41000" || c.Mode != "check" || len(c.WDTTIfaces) != 1 || c.WDTTIfaces[0] != "wdtt1" || c.AllowedIP != "0.0.0.0/0" || c.Mark != LinkMark {
		t.Fatalf("entry %+v", c)
	}
	if _, err := LinkConfig(exit, "", "eth0"); err == nil {
		t.Fatal("exit without a Mesh address")
	}
	if _, err := LinkConfig(exit, "100.96.0.17", ""); err == nil {
		t.Fatal("exit without an Internet interface")
	}
	c, err = LinkConfig(exit, "100.96.0.17", "eth0")
	if err != nil || c.Listen != "100.96.0.17:41000" || c.AllowedIP != "10.66.80.1/32" || c.PublicIface != "eth0" {
		t.Fatalf("exit %+v %v", c, err)
	}
	c, err = LinkConfig(relay, "100.96.0.18", "")
	if err != nil || c.Listen != "100.96.0.18:42000" || c.Peer != "100.96.0.17:41000" || c.PrivateKey != "" {
		t.Fatalf("relay %+v %v", c, err)
	}
	for _, s := range []*spec.NodeSpec{entry, exit, relay} {
		if err := s.Validate(); err != nil {
			t.Fatalf("%s: %v", s.Role, err)
		}
	}
}

func TestLinkModeOnly(t *testing.T) {
	entry, exit, _ := linkSpecs()
	c1, _ := LinkConfig(entry, "", "")
	a, _ := json.Marshal(c1)
	entry.Link.Mode = spec.LinkUDP
	c2, _ := LinkConfig(entry, "", "")
	b, _ := json.Marshal(c2)
	if !modeOnly(a, b) {
		t.Fatal("a mode change needs no restart")
	}
	entry.Link.MTU = 1300
	c3, _ := LinkConfig(entry, "", "")
	c, _ := json.Marshal(c3)
	if modeOnly(b, c) {
		t.Fatal("an MTU change needs a restart")
	}
	x, _ := LinkConfig(exit, "100.96.0.17", "eth0")
	xb, _ := json.Marshal(x)
	if modeOnly(xb, xb) || modeOnly(nil, b) {
		t.Fatal("only the entry reloads")
	}
}

func TestLinkUnit(t *testing.T) {
	e := linkUnitText(spec.RoleEntry)
	if !strings.Contains(e, "ExecStartPre=+"+SelfPath+" agent link-routes") || !strings.Contains(e, "ExecStopPost=-/usr/sbin/ip link del wrlink0") {
		t.Fatal(e)
	}
	r := linkUnitText(spec.RoleRelay)
	if strings.Contains(r, "ExecStartPre") || strings.Contains(r, "ExecStopPost") || !strings.Contains(r, "link --config /etc/wdtt-router/link.json") {
		t.Fatal(r)
	}
}

func TestFirewallOpensLinkPortToMesh(t *testing.T) {
	f := spec.FirewallSpec{Enabled: true, SSHPort: 22}
	s := RenderFirewall(f, FirewallInputs{HopPort: 41000, LinkPort: 41000})
	if !strings.Contains(s, `iifname "CloudflareWARP" ip saddr 100.96.0.0/12 udp dport 41000 accept`) {
		t.Fatal("tunnel port not open to Mesh")
	}
	if strings.Index(s, "udp dport 41000") > strings.Index(s, `iifname "CloudflareWARP" drop`) {
		t.Fatal("opened after Mesh is closed")
	}
	if strings.Contains(RenderFirewall(f, FirewallInputs{HopPort: 41000}), "udp dport 41000") {
		t.Fatal("opened without the tunnel")
	}
}

func TestForwardDrops(t *testing.T) {
	ufw := "-P INPUT DROP\n-P FORWARD DROP\n-P OUTPUT ACCEPT\n-A FORWARD -j ufw-before-logging-forward\n-A FORWARD -j ufw-before-forward\n"
	docker := "-P FORWARD DROP\n-A FORWARD -j DOCKER-USER\n-A FORWARD -j DOCKER-FORWARD\n"
	rhel := "-P FORWARD ACCEPT\n-A FORWARD -j REJECT --reject-with icmp-host-prohibited\n"
	open := "-P FORWARD ACCEPT\n"
	for _, c := range []struct {
		rules string
		drops bool
	}{{ufw, true}, {docker, true}, {rhel, true}, {open, false}, {"", false}} {
		if got := forwardDrops(c.rules); got != c.drops {
			t.Errorf("forwardDrops(%q) = %v", c.rules, got)
		}
	}
	own := ownForwardRules(docker + "-A FORWARD -s 10.66.80.1/32 -i wrlink0 -o eth0 -m comment --comment \"wdtt-router-link\" -j ACCEPT\n-A FORWARD -i ens3 -o wrlink0 -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment wdtt-router-link -j ACCEPT\n")
	if len(own) != 2 {
		t.Fatalf("own rules: %q", own)
	}
	// After a move to ens3 the eth0 rule is stale, the ens3 one is not.
	if strings.Contains(own[0], " ens3 ") || !strings.Contains(own[1], " ens3 ") {
		t.Fatalf("interface match: %q", own)
	}
	for _, r := range linkForwardRules("eth0") {
		if !strings.Contains(strings.Join(r, " "), "--comment "+linkFwdComment) {
			t.Fatalf("rule without the comment: %q", r)
		}
	}
}
