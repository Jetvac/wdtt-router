package node

import (
	"context"
	"testing"
)

func TestMakeWarpOutbound(t *testing.T) {
	data := map[string]string{"private_key": "private", "client_id": "AQID"}
	registration := map[string]any{"config": map[string]any{
		"interface": map[string]any{"addresses": map[string]any{"v4": "172.16.0.2", "v6": "2606:4700:110::1"}},
		"peers":     []any{map[string]any{"public_key": "public", "endpoint": map[string]any{"host": "engage.cloudflareclient.com:2408"}}},
	}}
	outbound, err := makeWarpOutbound(data, registration)
	if err != nil {
		t.Fatal(err)
	}
	if outbound["tag"] != xuiWarpTag || outbound["protocol"] != "wireguard" {
		t.Fatalf("wrong outbound: %#v", outbound)
	}
	settings := outbound["settings"].(map[string]any)
	if settings["noKernelTun"] != true {
		t.Fatal("userspace WireGuard must be selected")
	}
	reserved := settings["reserved"].([]int)
	if len(reserved) != 3 || reserved[0] != 1 || reserved[2] != 3 {
		t.Fatalf("wrong WARP reserved bytes: %v", reserved)
	}
}

func TestResolveWarpEndpointIPv4(t *testing.T) {
	outbound := map[string]any{"settings": map[string]any{"peers": []any{map[string]any{"endpoint": "127.0.0.1:2408"}}}}
	if err := resolveWarpEndpointIPv4(context.Background(), outbound); err != nil {
		t.Fatal(err)
	}
	peer := outbound["settings"].(map[string]any)["peers"].([]any)[0].(map[string]any)
	if peer["endpoint"] != "127.0.0.1:2408" {
		t.Fatal("literal IPv4 endpoint changed")
	}
}

func TestMakeWarpOutboundRejectsIncompleteResponse(t *testing.T) {
	if _, err := makeWarpOutbound(map[string]string{"private_key": "private"}, map[string]any{}); err == nil {
		t.Fatal("missing peer configuration must fail")
	}
}
