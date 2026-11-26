package spec

import (
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func key32() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func TestValidateLink(t *testing.T) {
	hk, _ := NewHopKeys()
	next := &NextHop{Addr: "100.96.0.3", Port: 32000}
	exit := func() *NodeSpec {
		return &NodeSpec{Version: Version, Role: RoleExit, Mesh: MeshSpec{Enabled: true, NodeName: "x", Token: "t"},
			Hop:  &HopSpec{Port: 32000, UUID: NewUUID(), Decryption: hk.Decryption},
			Link: &LinkSpec{Mode: LinkOn, Port: 32000, PrivateKey: key32(), PeerKey: key32(), PSK: key32(), MTU: 1280}}
	}
	if err := exit().Validate(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(s *NodeSpec){
		"port differs from the hop": func(s *NodeSpec) { s.Link.Port = 32001 },
		"bad key":                   func(s *NodeSpec) { s.Link.PSK = "short" },
		"entry mode on the exit":    func(s *NodeSpec) { s.Link.Mode = LinkUDP },
		"MTU too small":             func(s *NodeSpec) { s.Link.MTU = 1000 },
		"exit with a next hop":      func(s *NodeSpec) { s.Link.Next = next },
		"on an idle server":         func(s *NodeSpec) { s.Role, s.Hop = RoleIdle, nil },
	} {
		s := exit()
		change(s)
		if s.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	relay := &NodeSpec{Version: Version, Role: RoleRelay, Mesh: MeshSpec{Enabled: true, NodeName: "r", Token: "t"},
		Hop:  &HopSpec{Port: 31000, UUID: NewUUID(), Decryption: hk.Decryption, Next: next},
		Link: &LinkSpec{Mode: LinkOn, Port: 31000, Next: next}}
	if err := relay.Validate(); err != nil {
		t.Fatal(err)
	}
	relay.Link.PSK = key32()
	if relay.Validate() == nil {
		t.Error("a relay holds no keys")
	}
	relay.Link.PSK, relay.Link.Next = "", &NextHop{Addr: "8.8.8.8", Port: 1}
	if relay.Validate() == nil {
		t.Error("a relay's next hop must be in Mesh")
	}
}
