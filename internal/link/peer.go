package link

import (
	"encoding/hex"
	"fmt"
	"strings"

	"golang.zx2c4.com/wireguard/device"
)

func hexKey(k string) string {
	b, _ := decodeKey(k)
	return hex.EncodeToString(b)
}

// peerIPC is WireGuard's configuration of the other side.
func peerIPC(cfg *Config) string {
	var s strings.Builder
	fmt.Fprintf(&s, "public_key=%s\npreshared_key=%s\nreplace_allowed_ips=true\nallowed_ip=%s\n", hexKey(cfg.PeerKey), hexKey(cfg.PSK), cfg.AllowedIP)
	if cfg.Role == "entry" {
		// Keepalives keep WireGuard's keys fresh while no client sends, so a
		// first packet never waits for a handshake.
		fmt.Fprintf(&s, "endpoint=%s\npersistent_keepalive_interval=10\n", cfg.Peer)
	}
	return s.String()
}

func ipcConfig(cfg *Config) string {
	return "private_key=" + hexKey(cfg.PrivateKey) + "\n" + peerIPC(cfg)
}

// resetPeer drops the other side's keys and sets it up again. On the entry
// the keepalive setting sends a handshake initiation at once.
func resetPeer(dev *device.Device, cfg *Config) error {
	return dev.IpcSet("public_key=" + hexKey(cfg.PeerKey) + "\nremove=true\n" + peerIPC(cfg))
}
