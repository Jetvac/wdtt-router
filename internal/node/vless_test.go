package node

import (
	"encoding/json"
	"testing"
)

func TestParsePrivateProfile(t *testing.T) {
	const uuid = "e069377c-b99e-44f4-9be1-8a27e7494dcc"
	const meshIP = "100.96.0.2"
	cases := []struct {
		name, link string
		valid      bool
	}{
		{"private profile", "vless://" + uuid + "@100.96.0.2:24443?encryption=none&security=none&type=tcp#mesh", true},
		{"wrong node", "vless://" + uuid + "@100.96.0.3:24443?encryption=none&security=none&type=tcp", false},
		{"public node", "vless://" + uuid + "@203.0.113.1:24443?encryption=none&security=none&type=tcp", false},
		{"TLS option ignored", "vless://" + uuid + "@100.96.0.2:24443?encryption=none&security=none&type=tcp&sni=example.com", false},
		{"transport mismatch", "vless://" + uuid + "@100.96.0.2:24443?encryption=none&security=none&type=ws", false},
		{"bad identity", "vless://bad@100.96.0.2:24443?encryption=none&security=none&type=tcp", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, port, err := parsePrivateProfile(tc.link, meshIP)
			if tc.valid && (err != nil || got != uuid || port != 24443) {
				t.Fatalf("valid profile rejected: uuid=%q port=%d error=%v", got, port, err)
			}
			if !tc.valid && err == nil {
				t.Fatal("unsafe profile accepted")
			}
		})
	}
}

func TestPrivateInboundUserSurvivesRestart(t *testing.T) {
	c := VLESSConfig{UUID: "e069377c-b99e-44f4-9be1-8a27e7494dcc", Gateway: "172.31.255.1", Port: 24443}
	payload := xuiInboundPayload(c)
	settings, err := json.Marshal(payload["settings"])
	if err != nil {
		t.Fatal(err)
	}
	inbound := xuiInbound{Remark: vlessRemark, Listen: c.Gateway, Port: c.Port, Protocol: "vless", Enable: true, Settings: settings}
	if !xuiInboundMatches(inbound, c) || !xuiClientEnabled(inbound, c) {
		t.Fatal("new private inbound lacks a persistently enabled VLESS user")
	}
}

func TestClientProfileMustUsePrivateMesh(t *testing.T) {
	const uuid = "e069377c-b99e-44f4-9be1-8a27e7494dcc"
	for _, tc := range []struct {
		address string
		valid   bool
	}{
		{"100.96.0.4", true}, {"100.127.255.254", true}, {"100.128.0.1", false}, {"203.0.113.1", false},
	} {
		link := "vless://" + uuid + "@" + tc.address + ":24443?encryption=none&security=none&type=tcp"
		_, err := parseClientProfile(link)
		if (err == nil) != tc.valid {
			t.Errorf("address %s: valid=%v err=%v", tc.address, tc.valid, err)
		}
	}
}
