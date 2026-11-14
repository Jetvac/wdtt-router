package wdtt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"crypto/rand"
	"golang.org/x/crypto/curve25519"
)

// MainKeyID identifies the owner password, which is not bound to a device.
const MainKeyID = "main"

// Client kinds a server is set up for. Both speak the same protocol today;
// the kind lets the TurnVK server change it without touching the server
// that standard WDTT clients use.
const (
	KindStandard = "standard"
	KindTurnVK   = "turnvk"
)

// Config is written by the agent and re-read on SIGHUP.
type Config struct {
	Listen       string `json:"listen"`
	DNS          string `json:"dns"`
	DataDir      string `json:"data_dir"`
	StatusFile   string `json:"status_file"`
	MainPassword string `json:"main_password"`
	Keys         []Key  `json:"keys"`
	// MTU of the tunnel (the interface and the clients' config); 0 means TunMTU.
	MTU int `json:"mtu,omitempty"`
	// Kind of clients the server is for; "" means KindStandard.
	Kind string `json:"kind,omitempty"`
	// Iface is the TUN interface ("" means wdtt0) and Network its /24
	// ("" means 10.66.66.0/24); the server takes the .1 address.
	Iface   string `json:"iface,omitempty"`
	Network string `json:"network,omitempty"`
}

// Key is an access password issued from the panel. It binds to the first
// MaxDevices devices that connect with it (0 = any number of devices).
type Key struct {
	ID          string `json:"id"`
	Password    string `json:"password"`
	ExpiresAt   int64  `json:"expires_at,omitempty"` // Unix seconds, 0 = never
	Disabled    bool   `json:"disabled,omitempty"`
	DeviceEpoch int    `json:"device_epoch,omitempty"` // raising it unbinds every device
	MaxDevices  int    `json:"max_devices,omitempty"`
	// Unbind frees single devices: a device bound no later than At loses
	// its binding (and its address). Later bindings are not affected, so
	// the list can stay in the configuration.
	Unbind []Unbind `json:"unbind,omitempty"`
}

// Unbind asks the server to forget one device of a key.
type Unbind struct {
	Device string `json:"device"`
	At     int64  `json:"at"`
}

func (k Key) active(now time.Time) bool {
	return !k.Disabled && (k.ExpiresAt == 0 || now.Unix() < k.ExpiresAt)
}

var reKeyID = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// LoadConfig reads and validates the configuration file.
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if c.DNS == "" {
		c.DNS = "1.1.1.1"
	}
	if c.MTU == 0 {
		c.MTU = TunMTU
	}
	if c.Kind == "" {
		c.Kind = KindStandard
	}
	if c.Iface == "" {
		c.Iface = DefaultIface
	}
	if c.Network == "" {
		c.Network = DefaultNetwork
	}
	return &c, c.Validate()
}

// Defaults of the first (standard) server.
const (
	DefaultIface   = "wdtt0"
	DefaultNetwork = "10.66.66.0/24"
)

var reIface = regexp.MustCompile(`^[a-z][a-z0-9]{0,14}$`)

// subnet is the /24 of the clients as "a.b.c." (the prefix of every address).
func (c *Config) subnet() string {
	p, err := netip.ParsePrefix(c.Network)
	if err != nil {
		p = netip.MustParsePrefix(DefaultNetwork)
	}
	a := p.Addr().As4()
	return fmt.Sprintf("%d.%d.%d.", a[0], a[1], a[2])
}

// ServerAddr is the server's address on the TUN interface.
func (c *Config) ServerAddr() string { return c.subnet() + "1" }

// Validate checks the configuration.
func (c *Config) Validate() error {
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	if c.DataDir == "" {
		return errors.New("data_dir is required")
	}
	if c.MTU != 0 && (c.MTU < MinMTU || c.MTU > MaxMTU) {
		return fmt.Errorf("mtu must be %d..%d", MinMTU, MaxMTU)
	}
	if c.Kind != "" && c.Kind != KindStandard && c.Kind != KindTurnVK {
		return fmt.Errorf("unknown kind %q", c.Kind)
	}
	if c.Iface != "" && !reIface.MatchString(c.Iface) {
		return fmt.Errorf("invalid interface name %q", c.Iface)
	}
	if c.Network != "" {
		p, err := netip.ParsePrefix(c.Network)
		if err != nil || p.Bits() != 24 || !p.Addr().Is4() || p.Masked() != p {
			return fmt.Errorf("network must be an IPv4 /24, got %q", c.Network)
		}
	}
	for _, d := range strings.Split(c.DNS, ",") {
		if net.ParseIP(strings.TrimSpace(d)) == nil {
			return fmt.Errorf("invalid DNS %q", d)
		}
	}
	if c.MainPassword == "" && len(c.Keys) == 0 {
		return errors.New("no passwords configured")
	}
	seen := map[string]bool{c.MainPassword: c.MainPassword != ""}
	ids := map[string]bool{MainKeyID: true}
	for _, k := range c.Keys {
		if !reKeyID.MatchString(k.ID) || ids[k.ID] {
			return fmt.Errorf("invalid or duplicate key id %q", k.ID)
		}
		if k.Password == "" || seen[k.Password] {
			return fmt.Errorf("key %s: empty or duplicate password", k.ID)
		}
		if k.MaxDevices < 0 || k.MaxDevices > maxClients {
			return fmt.Errorf("key %s: max_devices must be 0..%d", k.ID, maxClients)
		}
		ids[k.ID], seen[k.Password] = true, true
	}
	return nil
}

// state is what the server keeps between restarts.
type state struct {
	ServerPrivate string                  `json:"server_private"`
	ServerPublic  string                  `json:"server_public"`
	Devices       map[string]*deviceState `json:"devices"`
	Keys          map[string]*keyState    `json:"keys"`
}

type deviceState struct {
	IP       string `json:"ip"`
	Private  string `json:"private_key"`
	Public   string `json:"public_key"`
	LastSeen int64  `json:"last_seen,omitempty"`
	Key      string `json:"key,omitempty"` // password it last connected with
	Up       int64  `json:"up_bytes,omitempty"`
	Down     int64  `json:"down_bytes,omitempty"`
}

type keyState struct {
	// DeviceID is the single bound device of earlier versions; it moves
	// into Devices when the state is read.
	DeviceID    string        `json:"device_id,omitempty"`
	Devices     []boundDevice `json:"devices,omitempty"`
	DeviceEpoch int           `json:"device_epoch,omitempty"`
	Up          int64         `json:"up_bytes"`
	Down        int64         `json:"down_bytes"`
	LastSeen    int64         `json:"last_seen,omitempty"`
}

type boundDevice struct {
	ID string `json:"id"`
	At int64  `json:"at"` // Unix seconds the device was bound
}

func (k *keyState) has(dev string) bool {
	for _, d := range k.Devices {
		if d.ID == dev {
			return true
		}
	}
	return false
}

func newKeyPair() (priv, pub string, err error) {
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		return "", "", err
	}
	k[0] &= 248
	k[31] = k[31]&127 | 64
	p, err := curve25519.X25519(k[:], curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(k[:]), base64.StdEncoding.EncodeToString(p), nil
}

func validKey(b64 string) bool {
	b, err := base64.StdEncoding.DecodeString(b64)
	return err == nil && len(b) == 32
}

// loadState reads state.json. On first start it takes over the server keys
// and devices of an original WDTT server (wg-keys.dat, passwords.json) from
// the same directory, so existing clients keep their addresses.
func loadState(dir, subnet string) (*state, bool, error) {
	st := &state{Devices: map[string]*deviceState{}, Keys: map[string]*keyState{}}
	b, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err == nil {
		if err := json.Unmarshal(b, st); err != nil {
			return nil, false, fmt.Errorf("state.json: %w", err)
		}
		if st.Devices == nil {
			st.Devices = map[string]*deviceState{}
		}
		if st.Keys == nil {
			st.Keys = map[string]*keyState{}
		}
		for _, k := range st.Keys {
			if k.DeviceID != "" {
				if !k.has(k.DeviceID) {
					k.Devices = append(k.Devices, boundDevice{ID: k.DeviceID})
				}
				k.DeviceID = ""
			}
		}
	} else if !os.IsNotExist(err) {
		return nil, false, err
	}
	migrated := false
	if st.ServerPrivate == "" {
		if b, err := os.ReadFile(filepath.Join(dir, "wg-keys.dat")); err == nil {
			l := strings.Fields(string(b))
			if len(l) >= 2 && validKey(l[0]) && validKey(l[1]) {
				st.ServerPrivate, st.ServerPublic = l[0], l[1]
				migrated = true
			}
		}
		var old struct {
			Devices map[string]struct {
				IP      string `json:"ip"`
				PrivKey string `json:"priv_key"`
				PubKey  string `json:"pub_key"`
			} `json:"devices"`
		}
		if b, err := os.ReadFile(filepath.Join(dir, "passwords.json")); err == nil && json.Unmarshal(b, &old) == nil {
			for id, d := range old.Devices {
				if validKey(d.PrivKey) && validKey(d.PubKey) && ipIndex(subnet, d.IP) > 0 {
					st.Devices[id] = &deviceState{IP: d.IP, Private: d.PrivKey, Public: d.PubKey}
					migrated = true
				}
			}
		}
	}
	if st.ServerPrivate == "" {
		st.ServerPrivate, st.ServerPublic, err = newKeyPair()
		if err != nil {
			return nil, false, err
		}
		migrated = true
	}
	return st, migrated, nil
}

func saveState(dir string, st *state) error {
	b, err := json.MarshalIndent(st, "", " ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, "state.json.tmp")
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, "state.json"))
}

// Client addresses are .2 – .250 of the server's /24, the server is .1.
const maxClients = 249

func ipIndex(subnet, ip string) int {
	rest, ok := strings.CutPrefix(ip, subnet)
	if !ok {
		return 0
	}
	var n int
	if _, err := fmt.Sscanf(rest, "%d", &n); err != nil || fmt.Sprint(n) != rest || n < 2 || n > 250 {
		return 0
	}
	return n
}

func (st *state) freeIP(subnet string) string {
	used := map[int]bool{}
	for _, d := range st.Devices {
		used[ipIndex(subnet, d.IP)] = true
	}
	for i := 2; i <= 250; i++ {
		if !used[i] {
			return fmt.Sprintf("%s%d", subnet, i)
		}
	}
	return ""
}

// clientConfig is the WireGuard configuration returned to GETCONF, in the
// exact form the standard client parses.
func clientConfig(serverPublic, clientPrivate, clientIP, dns, localPort string, mtu int) string {
	return fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/32
DNS = %s
MTU = %d

[Peer]
PublicKey = %s
AllowedIPs = 0.0.0.0/0
Endpoint = 127.0.0.1:%s
PersistentKeepalive = 25`, clientPrivate, clientIP, dns, mtu, serverPublic, localPort)
}

// TunMTU is the default MTU of wdtt0 and of the client tunnel.
//
// A full tunnel packet grows by about 155 bytes on the way (WireGuard 32,
// DTLS 37, RTP wrap 28 + padding up to 24 for audio or 60 for video, UDP/IP
// 28, TURN 4), so 1340 is the most that still fits a 1500-byte path in
// audio mode. The original client raises anything below 1280 to 1280 on
// its own interface; the server still sends no more than MTU.
const (
	TunMTU = 1280
	MinMTU = 1200
	MaxMTU = 1340
)
