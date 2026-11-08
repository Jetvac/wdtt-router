package spec

import (
	"strings"
	"testing"
)

func TestHopKeysFormat(t *testing.T) {
	k, err := NewHopKeys()
	if err != nil {
		t.Fatal(err)
	}
	if !reKey.MatchString(k.Decryption) || !reKey.MatchString(k.Encryption) {
		t.Fatalf("bad key format: %s / %s", k.Decryption, k.Encryption)
	}
	if !strings.HasPrefix(k.Encryption, "mlkem768x25519plus.random.0rtt.") {
		t.Fatal("client side must use 0-RTT")
	}
	if !reUUID.MatchString(NewUUID()) {
		t.Fatal("bad UUID")
	}
}

func TestValidate(t *testing.T) {
	k, _ := NewHopKeys()
	ok := NodeSpec{Version: Version, Role: RoleExit, Mesh: MeshSpec{Enabled: true, NodeName: "x", Token: "t"},
		Hop: &HopSpec{Port: 1000, UUID: NewUUID(), Decryption: k.Decryption}, Firewall: FirewallSpec{Enabled: true, SSHPort: 22}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(s *NodeSpec){
		"exit without Mesh":     func(s *NodeSpec) { s.Mesh.Enabled = false; s.Firewall.SSHPublic = true },
		"relay without next":    func(s *NodeSpec) { s.Role = RoleRelay },
		"next outside Mesh":     func(s *NodeSpec) { s.Role = RoleRelay; s.Hop.Next = &NextHop{Addr: "8.8.8.8", Port: 1} },
		"bad port":              func(s *NodeSpec) { s.Hop.Port = 0 },
		"closed SSH no Mesh":    func(s *NodeSpec) { s.Role = RoleIdle; s.Hop = nil; s.Mesh.Enabled = false },
		"bad allow address":     func(s *NodeSpec) { s.Firewall.SSHAllow = []string{"not-an-ip"} },
		"token with whitespace": func(s *NodeSpec) { s.Mesh.Token = "a b" },
	}
	for name, mut := range cases {
		s := ok
		h := *ok.Hop
		s.Hop = &h
		mut(&s)
		if err := s.Validate(); err == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}
}

func TestMeshIP(t *testing.T) {
	for ip, want := range map[string]bool{"100.96.0.1": true, "100.111.255.255": true, "100.112.0.1": false, "10.0.0.1": false, "bad": false} {
		if MeshIP(ip) != want {
			t.Errorf("MeshIP(%s) != %v", ip, want)
		}
	}
}
