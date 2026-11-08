package wdtt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
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

// Config is written by the agent and re-read on SIGHUP.
type Config struct {
	Listen       string `json:"listen"`
	DNS          string `json:"dns"`
	DataDir      string `json:"data_dir"`
	StatusFile   string `json:"status_file"`
	MainPassword string `json:"main_password"`
	Keys         []Key  `json:"keys"`
}

// Key is an access password issued from the panel. Like in the original
// server it is bound to the first device that connects with it.
type Key struct {
	ID          string `json:"id"`
	Password    string `json:"password"`
	ExpiresAt   int64  `json:"expires_at,omitempty"` // Unix seconds, 0 = never
	Disabled    bool   `json:"disabled,omitempty"`
	DeviceEpoch int    `json:"device_epoch,omitempty"` // raising it unbinds the device
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
	return &c, c.Validate()
}

// Validate checks the configuration.
func (c *Config) Validate() error {
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	if c.DataDir == "" {
		return errors.New("data_dir is required")
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
}

type keyState struct {
	DeviceID    string `json:"device_id,omitempty"`
	DeviceEpoch int    `json:"device_epoch,omitempty"`
	Up          int64  `json:"up_bytes"`
	Down        int64  `json:"down_bytes"`
	LastSeen    int64  `json:"last_seen,omitempty"`
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
func loadState(dir string) (*state, bool, error) {
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
				if validKey(d.PrivKey) && validKey(d.PubKey) && ipIndex(d.IP) > 0 {
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

// Client addresses: 10.66.66.2 – 10.66.66.250, the server is .1.
const (
	netPrefix = "10.66.66."
	ServerIP  = netPrefix + "1"
)

func ipIndex(ip string) int {
	rest, ok := strings.CutPrefix(ip, netPrefix)
	if !ok {
		return 0
	}
	var n int
	if _, err := fmt.Sscanf(rest, "%d", &n); err != nil || fmt.Sprint(n) != rest || n < 2 || n > 250 {
		return 0
	}
	return n
}

func (st *state) freeIP() string {
	used := map[int]bool{}
	for _, d := range st.Devices {
		used[ipIndex(d.IP)] = true
	}
	for i := 2; i <= 250; i++ {
		if !used[i] {
			return fmt.Sprintf("%s%d", netPrefix, i)
		}
	}
	return ""
}

// clientConfig is the WireGuard configuration returned to GETCONF, in the
// exact form the standard client parses.
func clientConfig(serverPublic, clientPrivate, clientIP, dns, localPort string) string {
	return fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/32
DNS = %s
MTU = %d

[Peer]
PublicKey = %s
AllowedIPs = 0.0.0.0/0
Endpoint = 127.0.0.1:%s
PersistentKeepalive = 25`, clientPrivate, clientIP, dns, TunMTU, serverPublic, localPort)
}

// TunMTU is the MTU of wdtt0 and of the client tunnel.
const TunMTU = 1280
