package agent

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Jetvac/wdtt-router/internal/spec"
)

func keys(t *testing.T) spec.HopKeys {
	t.Helper()
	k, err := spec.NewHopKeys()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestEntryOnionChain(t *testing.T) {
	k1, k2 := keys(t), keys(t)
	s := &spec.NodeSpec{Version: spec.Version, Role: spec.RoleEntry, Entry: &spec.EntrySpec{
		SocksPort: 30000, SocksUser: "user", SocksPass: "0123456789abcdefXYZ",
		Chain: []spec.OnionHop{
			{Addr: "100.96.0.2", Port: 31000, UUID: spec.NewUUID(), Encryption: k1.Encryption},
			{Addr: "100.96.0.3", Port: 32000, UUID: spec.NewUUID(), Encryption: k2.Encryption},
		},
		WDTT: spec.WDTTSpec{Enabled: true, DTLSPort: 56000, WGPort: 56001, Password: "0123456789abcdefXY", TProxy: 30001},
	}}
	b, err := RenderXray(s, "", false)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Inbounds  []map[string]any `json:"inbounds"`
		Outbounds []map[string]any `json:"outbounds"`
		Routing   struct {
			Rules []map[string]any `json:"rules"`
		} `json:"routing"`
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Inbounds) != 2 {
		t.Fatalf("want socks + tproxy inbounds, got %d", len(cfg.Inbounds))
	}
	for _, in := range cfg.Inbounds {
		if in["listen"] != "127.0.0.1" {
			t.Fatalf("entry inbound must be loopback only: %v", in["listen"])
		}
	}
	// hop2 (exit) is dialed through hop1: the relay never sees plaintext.
	hop2 := cfg.Outbounds[1]
	ss := hop2["streamSettings"].(map[string]any)
	if ss["sockopt"].(map[string]any)["dialerProxy"] != "hop1" {
		t.Fatal("last hop must be tunnelled through the previous hop")
	}
	if cfg.Routing.Rules[0]["outboundTag"] != "hop2" {
		t.Fatal("client traffic must go to the outermost hop")
	}
}

func TestEntryWithoutChainBlocks(t *testing.T) {
	s := &spec.NodeSpec{Version: spec.Version, Role: spec.RoleEntry, Entry: &spec.EntrySpec{SocksPort: 30000, SocksUser: "u", SocksPass: "0123456789abcdefXYZ"}}
	b, _ := RenderXray(s, "", false)
	if !strings.Contains(string(b), `"outboundTag": "block"`) {
		t.Fatal("without a chain client traffic must be blocked, never sent directly")
	}
}

func TestRelayOnlyReachesNextHop(t *testing.T) {
	k := keys(t)
	s := &spec.NodeSpec{Version: spec.Version, Role: spec.RoleRelay, Mesh: spec.MeshSpec{Enabled: true, NodeName: "n", Token: "tok"},
		Hop: &spec.HopSpec{Port: 31000, UUID: spec.NewUUID(), Decryption: k.Decryption, Next: &spec.NextHop{Addr: "100.96.0.3", Port: 32000}}}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	b, err := RenderXray(s, "100.96.0.2", false)
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)
	if !strings.Contains(out, `"listen": "100.96.0.2"`) {
		t.Fatal("hop must listen on the Mesh address only")
	}
	if !strings.Contains(out, `"100.96.0.3"`) || !strings.Contains(out, `"outboundTag": "block"`) {
		t.Fatal("relay must allow only the next hop and block everything else")
	}
}

func TestExitBlocksPrivateRanges(t *testing.T) {
	k := keys(t)
	s := &spec.NodeSpec{Version: spec.Version, Role: spec.RoleExit, Mesh: spec.MeshSpec{Enabled: true, NodeName: "n", Token: "tok"},
		Hop: &spec.HopSpec{Port: 31000, UUID: spec.NewUUID(), Decryption: k.Decryption}}
	b, err := RenderXray(s, "100.96.0.3", false)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"100.64.0.0/10", "10.0.0.0/8", "IPIfNonMatch", "https+local://1.1.1.1/dns-query"} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("exit config misses %s", want)
		}
	}
	if _, err := RenderXray(s, "", false); err == nil {
		t.Fatal("hop without Mesh address must fail")
	}
}

func TestFirewallClosedSSH(t *testing.T) {
	f := spec.FirewallSpec{Enabled: true, SSHPort: 22, SSHPublic: false}
	r := RenderFirewall(f, FirewallInputs{HopPort: 31000})
	if !strings.Contains(r, `iifname "CloudflareWARP" ip saddr 100.96.0.0/12 tcp dport { 22, 31000 } accept`) {
		t.Fatal("SSH and hop must be reachable through Mesh")
	}
	if strings.Contains(r, "\t\ttcp dport 22 accept") {
		t.Fatal("public SSH must be closed")
	}
	if !strings.Contains(r, "policy drop") {
		t.Fatal("default policy must be drop")
	}
}

func TestFirewallEntry(t *testing.T) {
	f := spec.FirewallSpec{Enabled: true, SSHPort: 22, SSHPublic: true, SSHAllow: []string{"203.0.113.5", "2001:db8::/32"}, PanelPort: 8443}
	w := spec.WDTTSpec{DTLSPort: 56000}
	r := RenderFirewall(f, FirewallInputs{WDTT: &w, XUIPorts: []int{443}})
	for _, want := range []string{
		"ip saddr { 203.0.113.5 } tcp dport 22 accept",
		"ip6 saddr { 2001:db8::/32 } tcp dport 22 accept",
		"update @ssh_flood4",
		"tcp dport 8443 accept",
		"udp dport 56000 accept",
		"th dport { 443 } accept",
		`iifname "wdtt0" meta mark 0x00000001 accept`,
	} {
		if !strings.Contains(r, want) {
			t.Fatalf("missing %q in\n%s", want, r)
		}
	}
	if strings.Contains(r, "56001") {
		t.Fatal("internal WireGuard port must stay closed")
	}
}

func TestPatchTemplateIdempotent(t *testing.T) {
	e := &spec.EntrySpec{SocksPort: 30000, SocksUser: "u", SocksPass: "p"}
	once, err := patchTemplate(xuiDefaultTemplate, true, e)
	if err != nil {
		t.Fatal(err)
	}
	twice, _ := patchTemplate(once, true, e)
	if normJSON(once) != normJSON(twice) {
		t.Fatal("patch must be idempotent")
	}
	if strings.Count(twice, chainTag) != 1 {
		t.Fatal("chain outbound must appear once")
	}
	var cfg struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	_ = json.Unmarshal([]byte(once), &cfg)
	if cfg.Outbounds[0]["tag"] != chainTag {
		t.Fatal("chain must be the default (first) outbound")
	}
	removed, _ := patchTemplate(once, false, nil)
	if strings.Contains(removed, chainTag) || normJSON(removed) != normJSON(xuiDefaultTemplate) {
		t.Fatal("removing must restore the original template")
	}
}

func TestTProxyScriptKillSwitch(t *testing.T) {
	s := tproxyScript(30001)
	if !strings.Contains(s, `iifname "wdtt0" drop`) || !strings.Contains(s, `oifname "wdtt0" drop`) {
		t.Fatal("forwarding from WDTT clients must be dropped")
	}
	if !strings.Contains(s, "tproxy ip to 127.0.0.1:30001") {
		t.Fatal("client traffic must be diverted to Xray")
	}
}
