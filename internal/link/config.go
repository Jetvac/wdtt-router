package link

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
)

// Config is the tunnel service's configuration, written by the agent
// (/etc/wdtt-router/link.json).
type Config struct {
	Role string `json:"role"`           // entry, exit, relay
	Mode string `json:"mode,omitempty"` // entry: check, udp
	// Iface and Address: the tunnel interface and its address (entry, exit).
	Iface   string `json:"iface,omitempty"`
	Address string `json:"address,omitempty"`
	MTU     int    `json:"mtu,omitempty"`
	// Listen: this server's Mesh address and port (exit, relay).
	Listen string `json:"listen,omitempty"`
	// Peer: where this server sends the tunnel (entry, relay).
	Peer string `json:"peer,omitempty"`
	// WireGuard keys, base64 (entry, exit).
	PrivateKey string `json:"private_key,omitempty"`
	PeerKey    string `json:"peer_key,omitempty"`
	PSK        string `json:"psk,omitempty"`
	// AllowedIP: the addresses the other side may send from (exit: the
	// entry's tunnel address; entry: any).
	AllowedIP string `json:"allowed_ip,omitempty"`
	// MeshIface: Cloudflare's interface, whose MTU limits the datagrams.
	MeshIface string `json:"mesh_iface"`
	// PublicIface: the exit's Internet interface (forwarding of replies).
	PublicIface string `json:"public_iface,omitempty"`
	// Entry: the WDTT interfaces whose client UDP may use the tunnel, the
	// nftables set that says which do now, the routing table of the tunnel,
	// and the mark of the entry's own checks through it.
	WDTTIfaces []string `json:"wdtt_ifaces,omitempty"`
	NftTable   string   `json:"nft_table,omitempty"`
	NftSet     string   `json:"nft_set,omitempty"`
	RouteTable int      `json:"route_table,omitempty"`
	Mark       int      `json:"mark,omitempty"`
	StatusFile string   `json:"status_file"`
}

// LoadConfig reads and checks a configuration file.
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, c.Validate()
}

func decodeKey(k string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(k)
	if err != nil || len(b) != 32 {
		return nil, errors.New("bad key")
	}
	return b, nil
}

// Validate checks what each role needs.
func (c *Config) Validate() error {
	if c.StatusFile == "" {
		return errors.New("status_file is required")
	}
	ap := func(s string) bool { _, err := netip.ParseAddrPort(s); return err == nil }
	switch c.Role {
	case "relay":
		if !ap(c.Listen) || !ap(c.Peer) {
			return errors.New("relay: listen and peer are required")
		}
		return nil
	case "entry", "exit":
	default:
		return fmt.Errorf("unknown role %q", c.Role)
	}
	for _, k := range []string{c.PrivateKey, c.PeerKey, c.PSK} {
		if _, err := decodeKey(k); err != nil {
			return errors.New("bad WireGuard key")
		}
	}
	if _, err := netip.ParsePrefix(c.Address); err != nil || c.Iface == "" || c.MTU < 576 {
		return errors.New("iface, address and mtu are required")
	}
	if _, err := netip.ParsePrefix(c.AllowedIP); err != nil {
		return errors.New("allowed_ip is required")
	}
	if c.Role == "exit" {
		if !ap(c.Listen) || c.PublicIface == "" {
			return errors.New("exit: listen and public_iface are required")
		}
		return nil
	}
	if !ap(c.Peer) || (c.Mode != "check" && c.Mode != "udp") || c.NftTable == "" || c.NftSet == "" || c.RouteTable == 0 || c.Mark == 0 {
		return errors.New("entry: peer, mode, nft_table, nft_set, route_table and mark are required")
	}
	return nil
}
