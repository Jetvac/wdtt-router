// Package spec holds the declarative node specification shared by the
// controller and the node agent. The controller computes a NodeSpec for every
// server and the agent reconciles the host to exactly that state. Applying the
// same spec twice is a no-op, which is what makes repeated install/uninstall
// requests safe.
package spec

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

// Version of the spec format. The agent refuses specs it does not understand.
const Version = 1

// Role of a node inside the chain.
const (
	RoleEntry = "entry" // runs the panel, WDTT and 3x-ui; first hop
	RoleRelay = "relay" // forwards to the next hop only
	RoleExit  = "exit"  // releases traffic to the Internet
	RoleIdle  = "idle"  // enrolled, but not part of the chain
)

// NodeSpec is the complete desired state of one server.
type NodeSpec struct {
	Version  int          `json:"version"`
	NodeID   int64        `json:"node_id"`
	Role     string       `json:"role"`
	Mesh     MeshSpec     `json:"mesh"`
	Hop      *HopSpec     `json:"hop,omitempty"`   // relay and exit
	Entry    *EntrySpec   `json:"entry,omitempty"` // entry only
	Firewall FirewallSpec `json:"firewall"`
	// Hardening of the host itself (SSH, updates).
	Hardening HardeningSpec `json:"hardening"`
	// Bot runs the Telegram bot on this node.
	Bot *BotSpec `json:"bot,omitempty"`
}

// BotSpec is the Telegram bot. It needs no open port: it polls Telegram and
// the panel's bot API (over Mesh, or locally on the panel's server).
type BotSpec struct {
	Token            string `json:"token"`             // Telegram bot token
	PanelURL         string `json:"panel_url"`         // https://<panel Mesh address>:<port>
	PanelFingerprint string `json:"panel_fingerprint"` // SHA-256 of the panel certificate
	APIToken         string `json:"api_token"`         // the bot's key for the panel's bot API
}

// HardeningSpec tightens the host beyond the firewall.
type HardeningSpec struct {
	// SSHKeysOnly turns off password and keyboard-interactive SSH logins
	// (root may log in with a key only).
	SSHKeysOnly bool `json:"ssh_keys_only,omitempty"`
	// AutoUpdates installs security updates daily (unattended-upgrades).
	AutoUpdates bool `json:"auto_updates,omitempty"`
	// AdminKeys are the administrator's own SSH public keys for root, kept
	// in a marked block of authorized_keys (the panel's key is separate).
	AdminKeys []string `json:"admin_keys,omitempty"`
}

// HardeningStatus is what is actually in effect on the host.
type HardeningStatus struct {
	SSHPasswordAuth bool   `json:"ssh_password_auth"`
	SSHRootLogin    string `json:"ssh_root_login"`
	RootKeys        int    `json:"root_keys"`
	AutoUpdates     bool   `json:"auto_updates"`
	RebootRequired  bool   `json:"reboot_required"`
}

// MeshSpec describes Cloudflare Mesh enrolment of the node.
type MeshSpec struct {
	Enabled  bool   `json:"enabled"`
	NodeName string `json:"node_name,omitempty"`
	CFNodeID string `json:"cf_node_id,omitempty"`
	Token    string `json:"token,omitempty"`
}

// HopSpec is the VLESS inbound of a relay or exit node. It listens only on the
// node's Mesh address. A relay may forward only to Next; an exit releases to
// the Internet but never to private or Mesh ranges.
type HopSpec struct {
	Port       int      `json:"port"`
	UUID       string   `json:"uuid"`
	Decryption string   `json:"decryption"`
	Next       *NextHop `json:"next,omitempty"`
}

// NextHop is the only destination a relay is allowed to reach.
type NextHop struct {
	Addr string `json:"addr"`
	Port int    `json:"port"`
}

// OnionHop is one layer of the entry's nested outbound. Encryption is the
// client half of the hop's VLESS Encryption key pair.
type OnionHop struct {
	Addr       string `json:"addr"`
	Port       int    `json:"port"`
	UUID       string `json:"uuid"`
	Encryption string `json:"encryption"`
}

// EntrySpec is the configuration of the first node.
type EntrySpec struct {
	// Chain lists the downstream hops in order. The entry encrypts the stream
	// for the last hop first, so intermediate nodes forward opaque bytes.
	Chain     []OnionHop `json:"chain"`
	SocksPort int        `json:"socks_port"`
	SocksUser string     `json:"socks_user"`
	SocksPass string     `json:"socks_pass"`
	WDTT      WDTTSpec   `json:"wdtt"`
	XUI       XUISpec    `json:"xui"`
}

// WDTTSpec controls the optional WDTT server.
type WDTTSpec struct {
	Enabled  bool   `json:"enabled"`
	DTLSPort int    `json:"dtls_port"`
	WGPort   int    `json:"wg_port"`
	Password string `json:"password,omitempty"`
	DNS      string `json:"dns,omitempty"`
	TProxy   int    `json:"tproxy_port"`
	// MTU of the tunnel sent to clients; 0 means the default (1280).
	MTU int `json:"mtu,omitempty"`
	// Keys are extra access passwords; each binds to the first device
	// that connects with it. Password is the owner password.
	Keys []WDTTKey `json:"keys,omitempty"`
}

// WDTTKey is an access password of the WDTT server.
type WDTTKey struct {
	ID          string `json:"id"`
	Password    string `json:"password"`
	ExpiresAt   int64  `json:"expires_at,omitempty"`
	Disabled    bool   `json:"disabled,omitempty"`
	DeviceEpoch int    `json:"device_epoch,omitempty"`
}

// WDTTRuntime is what the running WDTT server reports.
type WDTTRuntime struct {
	Version           string                    `json:"version"`
	StartedAt         int64                     `json:"started_at"`
	UpdatedAt         int64                     `json:"updated_at"`
	Sessions          int                       `json:"sessions"`
	Devices           int                       `json:"devices"`
	HandshakeFailures int64                     `json:"handshake_failures"`
	AuthFailures      int64                     `json:"auth_failures"`
	StaleResets       int64                     `json:"stale_resets"`
	Keys              map[string]WDTTKeyRuntime `json:"keys"`
}

// WDTTKeyRuntime describes one password of the running server.
type WDTTKeyRuntime struct {
	Sessions int    `json:"sessions"`
	DeviceID string `json:"device_id,omitempty"`
	DeviceIP string `json:"device_ip,omitempty"`
	Up       int64  `json:"up_bytes"`
	Down     int64  `json:"down_bytes"`
	LastSeen int64  `json:"last_seen,omitempty"`
}

// XUISpec controls the optional 3x-ui panel.
type XUISpec struct {
	Enabled bool `json:"enabled"`
	// RouteViaChain makes the chain the default outbound of 3x-ui.
	RouteViaChain bool `json:"route_via_chain"`
}

// FirewallSpec is the input policy of the node. Everything not listed is
// dropped. Outbound traffic is unrestricted.
type FirewallSpec struct {
	Enabled bool `json:"enabled"`
	SSHPort int  `json:"ssh_port"`
	// SSHPublic allows SSH from the Internet (restricted to SSHAllow when it
	// is not empty). When false SSH is reachable only through Mesh.
	SSHPublic bool     `json:"ssh_public"`
	SSHAllow  []string `json:"ssh_allow,omitempty"`
	// PanelPort is opened on the entry for the web panel; 0 disables.
	PanelPort  int      `json:"panel_port,omitempty"`
	PanelAllow []string `json:"panel_allow,omitempty"`
	// PanelMesh are Mesh addresses allowed to the panel port (the bot).
	PanelMesh []string `json:"panel_mesh,omitempty"`
	AllowPing bool     `json:"allow_ping"`
	ExtraTCP  []int    `json:"extra_tcp,omitempty"`
	ExtraUDP  []int    `json:"extra_udp,omitempty"`
}

var (
	reUUID  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	reKey   = regexp.MustCompile(`^mlkem768x25519plus\.(native|xorpub|random)\.[0-9a-z-]+\.[A-Za-z0-9_-]{43,}$`)
	reName  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	rePass  = regexp.MustCompile(`^[A-Za-z0-9._-]{16,128}$`)
	reKeyID = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	// ReBotToken matches a Telegram bot token ("123456:ABC-...").
	reBotToken    = regexp.MustCompile(`^[0-9]{5,15}:[A-Za-z0-9_-]{30,64}$`)
	reFingerprint = regexp.MustCompile(`^([0-9A-F]{2}:){31}[0-9A-F]{2}$`)
)

func validPort(p int) bool { return p >= 1 && p <= 65535 }

// ValidCIDR accepts an IPv4/IPv6 address or prefix.
func ValidCIDR(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(s)
	return err == nil
}

// MeshIP reports whether addr is inside the Cloudflare Mesh range.
func MeshIP(addr string) bool {
	ip := net.ParseIP(addr).To4()
	_, mesh, _ := net.ParseCIDR("100.96.0.0/12")
	return ip != nil && mesh.Contains(ip)
}

// Validate checks the spec before the agent touches the host.
func (s *NodeSpec) Validate() error {
	if s.Version != Version {
		return fmt.Errorf("unsupported spec version %d", s.Version)
	}
	switch s.Role {
	case RoleEntry, RoleRelay, RoleExit, RoleIdle:
	default:
		return fmt.Errorf("invalid role %q", s.Role)
	}
	if s.Mesh.Enabled {
		if !reName.MatchString(s.Mesh.NodeName) || s.Mesh.Token == "" || strings.ContainsAny(s.Mesh.Token, " \r\n'\"") {
			return errors.New("invalid Mesh enrolment")
		}
	}
	if (s.Role == RoleRelay || s.Role == RoleExit) != (s.Hop != nil) {
		return errors.New("hop settings must be present exactly on relay and exit nodes")
	}
	if s.Role != RoleIdle && s.Role != RoleEntry && !s.Mesh.Enabled {
		return errors.New("chain nodes must be enrolled in Mesh")
	}
	if s.Hop != nil {
		h := s.Hop
		if !validPort(h.Port) || !reUUID.MatchString(h.UUID) || !reKey.MatchString(h.Decryption) {
			return errors.New("invalid hop inbound")
		}
		if (s.Role == RoleRelay) != (h.Next != nil) {
			return errors.New("only relays have a next hop")
		}
		if h.Next != nil && (!MeshIP(h.Next.Addr) || !validPort(h.Next.Port)) {
			return errors.New("next hop must be a Mesh address")
		}
	}
	if (s.Role == RoleEntry) != (s.Entry != nil) {
		return errors.New("entry settings must be present exactly on the entry node")
	}
	if e := s.Entry; e != nil {
		for i, h := range e.Chain {
			if !MeshIP(h.Addr) || !validPort(h.Port) || !reUUID.MatchString(h.UUID) || !reKey.MatchString(h.Encryption) {
				return fmt.Errorf("invalid chain hop %d", i+1)
			}
		}
		if !validPort(e.SocksPort) || !reName.MatchString(e.SocksUser) || !rePass.MatchString(e.SocksPass) {
			return errors.New("invalid local proxy settings")
		}
	}
	if b := s.Bot; b != nil {
		u, err := url.Parse(b.PanelURL)
		if !reBotToken.MatchString(b.Token) || err != nil || u.Scheme != "https" || u.Host == "" || !reFingerprint.MatchString(b.PanelFingerprint) || len(b.APIToken) < 32 {
			return errors.New("invalid Telegram bot settings")
		}
	}
	for _, k := range s.Hardening.AdminKeys {
		if !ValidAuthorizedKey(k) {
			return errors.New("invalid administrator SSH key")
		}
	}
	if e := s.Entry; e != nil {
		if w := e.WDTT; w.Enabled {
			if !validPort(w.DTLSPort) || !validPort(w.WGPort) || !validPort(w.TProxy) || w.DTLSPort == w.WGPort || !rePass.MatchString(w.Password) {
				return errors.New("invalid WDTT settings")
			}
			for _, d := range strings.Split(w.DNS, ",") {
				if d != "" && net.ParseIP(strings.TrimSpace(d)) == nil {
					return errors.New("invalid WDTT DNS")
				}
			}
			if w.MTU != 0 && (w.MTU < 1200 || w.MTU > 1340) {
				return errors.New("WDTT MTU must be 1200..1340")
			}
			ids := map[string]bool{"main": true}
			pws := map[string]bool{w.Password: true}
			for _, k := range w.Keys {
				if !reKeyID.MatchString(k.ID) || ids[k.ID] || !rePass.MatchString(k.Password) || pws[k.Password] || k.DeviceEpoch < 0 {
					return fmt.Errorf("invalid WDTT key %q", k.ID)
				}
				ids[k.ID], pws[k.Password] = true, true
			}
		}
	}
	f := s.Firewall
	if f.Enabled {
		if !validPort(f.SSHPort) {
			return errors.New("invalid SSH port")
		}
		if !f.SSHPublic && !s.Mesh.Enabled {
			return errors.New("SSH must stay public on a node without Mesh")
		}
		for _, ip := range f.PanelMesh {
			if !MeshIP(ip) {
				return errors.New("invalid panel Mesh address")
			}
		}
		for _, c := range append(append([]string{}, f.SSHAllow...), f.PanelAllow...) {
			if !ValidCIDR(c) {
				return fmt.Errorf("invalid address %q", c)
			}
		}
		if f.PanelPort != 0 && !validPort(f.PanelPort) {
			return errors.New("invalid panel port")
		}
		for _, p := range append(append([]int{}, f.ExtraTCP...), f.ExtraUDP...) {
			if !validPort(p) {
				return errors.New("invalid extra port")
			}
		}
	}
	return nil
}

// Status is what the agent reports back to the controller.
type Status struct {
	AgentVersion string  `json:"agent_version"`
	Hostname     string  `json:"hostname"`
	OS           string  `json:"os"`
	Arch         string  `json:"arch"`
	Kernel       string  `json:"kernel"`
	PublicIface  string  `json:"public_iface"`
	PublicIPv4   string  `json:"public_ipv4"`
	UptimeSec    int64   `json:"uptime_sec"`
	Load1        float64 `json:"load1"`
	MemTotalMB   int64   `json:"mem_total_mb"`
	MemAvailMB   int64   `json:"mem_avail_mb"`
	DiskFreeMB   int64   `json:"disk_free_mb"`
	NetRxBytes   int64   `json:"net_rx_bytes"`
	NetTxBytes   int64   `json:"net_tx_bytes"`

	SpecRole    string `json:"spec_role"`
	SpecApplied string `json:"spec_applied"`
	SpecHash    string `json:"spec_hash"`

	MeshInstalled bool   `json:"mesh_installed"`
	MeshStatus    string `json:"mesh_status"`
	MeshIP        string `json:"mesh_ip"`
	MeshVersion   string `json:"mesh_version"`

	XrayInstalled bool   `json:"xray_installed"`
	XrayVersion   string `json:"xray_version"`
	XrayActive    string `json:"xray_active"`

	FirewallActive bool     `json:"firewall_active"`
	FirewallPorts  []string `json:"firewall_ports"`
	RevertPending  bool     `json:"revert_pending"`

	WDTTInstalled bool         `json:"wdtt_installed"`
	WDTTActive    string       `json:"wdtt_active"`
	WDTTIface     bool         `json:"wdtt_iface"`
	WDTTPeers     int          `json:"wdtt_peers"`
	WDTT          *WDTTRuntime `json:"wdtt,omitempty"`

	XUIInstalled bool   `json:"xui_installed"`
	XUIActive    string `json:"xui_active"`
	XUIPorts     []int  `json:"xui_ports"`

	Hardening *HardeningStatus `json:"hardening,omitempty"`

	Problems []string `json:"problems"`
}

// ApplyResult is returned by "agent apply".
type ApplyResult struct {
	Changed       []string          `json:"changed"`
	RevertPending bool              `json:"revert_pending"`
	Status        Status            `json:"status"`
	Secrets       map[string]string `json:"secrets,omitempty"`
}

// ProbeResult is the end-to-end check of the chain run on the entry node.
type ProbeResult struct {
	OK     bool   `json:"ok"`
	ExitIP string `json:"exit_ip"`
	Colo   string `json:"colo"`
	TCPms  int64  `json:"tcp_ms"`
	UDPOK  bool   `json:"udp_ok"`
	UDPms  int64  `json:"udp_ms"`
	Error  string `json:"error,omitempty"`
}

// ValidBotToken reports whether s looks like a Telegram bot token.
func ValidBotToken(s string) bool { return reBotToken.MatchString(s) }
