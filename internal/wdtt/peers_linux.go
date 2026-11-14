package wdtt

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

type wgPeers struct {
	iface string
	mu    sync.Mutex
	dev   *device.Device
	have  map[string]string
}

func b64hex(k string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(k)
	if err != nil || len(b) != 32 {
		return "", fmt.Errorf("bad key")
	}
	return hex.EncodeToString(b), nil
}

func ipcmd(args ...string) error {
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %s", strings.Join(args, " "), strings.TrimSpace(string(out)))
	}
	return nil
}

// NewLinuxPeers creates the TUN interface with a userspace WireGuard
// device that talks to clients through the bind.
func NewLinuxPeers(b *bind, o PeerOptions) (Peers, error) {
	iface, serverPrivate, mtu := o.Iface, o.Private, o.MTU
	_ = exec.Command("ip", "link", "del", iface).Run()
	t, err := tun.CreateTUN(iface, mtu)
	if err != nil {
		return nil, fmt.Errorf("create %s: %w", iface, err)
	}
	logger := &device.Logger{Verbosef: device.DiscardLogf, Errorf: func(f string, a ...any) {
		// Peers have no endpoint until their client connects; WireGuard
		// reports every attempt to reach them, which is expected noise.
		// Likewise when the session it last used has closed: the client
		// reconnects and WireGuard picks up the new session by itself.
		msg := f
		if len(a) > 0 {
			msg += fmt.Sprint(a[len(a)-1])
		}
		if strings.Contains(msg, "no known endpoint") || strings.Contains(msg, "use of closed network connection") {
			return
		}
		log.Printf("wireguard: "+f, a...)
	}}
	dev := device.NewDevice(t, b, logger)
	priv, err := b64hex(serverPrivate)
	if err != nil {
		dev.Close()
		return nil, err
	}
	if err := dev.IpcSet("private_key=" + priv + "\n"); err != nil {
		dev.Close()
		return nil, err
	}
	for _, args := range [][]string{
		{"addr", "replace", o.Addr, "dev", iface},
		{"link", "set", iface, "mtu", fmt.Sprint(mtu), "up"},
	} {
		if err := ipcmd(args...); err != nil {
			dev.Close()
			return nil, err
		}
	}
	// Clients get IPv4 only; no IPv6 link-local chatter on the interface.
	_ = os.WriteFile("/proc/sys/net/ipv6/conf/"+iface+"/disable_ipv6", []byte("1"), 0644)
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, err
	}
	return &wgPeers{iface: iface, dev: dev, have: map[string]string{}}, nil
}

func (p *wgPeers) Set(want map[string]string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	var b strings.Builder
	for pub := range p.have {
		if _, ok := want[pub]; !ok {
			h, err := b64hex(pub)
			if err == nil {
				fmt.Fprintf(&b, "public_key=%s\nremove=true\n", h)
			}
		}
	}
	for pub, ip := range want {
		if p.have[pub] == ip {
			continue
		}
		h, err := b64hex(pub)
		if err != nil {
			continue
		}
		fmt.Fprintf(&b, "public_key=%s\nreplace_allowed_ips=true\nallowed_ip=%s/32\n", h, ip)
	}
	if b.Len() == 0 {
		return nil
	}
	if err := p.dev.IpcSet(b.String()); err != nil {
		return err
	}
	p.have = make(map[string]string, len(want))
	for k, v := range want {
		p.have[k] = v
	}
	return nil
}

// Kick points the peer at the session endpoint and has WireGuard initiate
// a handshake: turning the persistent keepalive on sends a keepalive, and
// with no current keys that starts a handshake. The keepalive is turned
// off again right away. Peers with a handshake in the last freshHandshake
// are left alone.
func (p *wgPeers) Kick(pub, ep string, retry bool) error {
	h, err := b64hex(pub)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	ip, ok := p.have[pub]
	if !ok {
		return nil
	}
	if last, ok := p.lastHandshake(h); ok && time.Since(last) < freshHandshake {
		return nil
	}
	if retry {
		// Re-create the peer: this clears the handshake state, so the new
		// initiation is sent now rather than after WireGuard's 5 s pause.
		if err := p.dev.IpcSet(fmt.Sprintf("public_key=%s\nremove=true\npublic_key=%s\nallowed_ip=%s/32\n", h, h, ip)); err != nil {
			return err
		}
	}
	if err := p.dev.IpcSet(fmt.Sprintf("public_key=%s\nupdate_only=true\nendpoint=%s\npersistent_keepalive_interval=0\n", h, ep)); err != nil {
		return err
	}
	if err := p.dev.IpcSet(fmt.Sprintf("public_key=%s\nupdate_only=true\npersistent_keepalive_interval=1\n", h)); err != nil {
		return err
	}
	return p.dev.IpcSet(fmt.Sprintf("public_key=%s\nupdate_only=true\npersistent_keepalive_interval=0\n", h))
}

// Fresh reports whether the peer completed a handshake recently.
func (p *wgPeers) Fresh(pub string) bool {
	h, err := b64hex(pub)
	if err != nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	last, ok := p.lastHandshake(h)
	return ok && time.Since(last) < freshHandshake
}

// freshHandshake: WireGuard re-keys every 2 minutes while in use, so a
// handshake younger than this means the session with the peer works.
const freshHandshake = 150 * time.Second

func (p *wgPeers) lastHandshake(hexKey string) (time.Time, bool) {
	cfg, err := p.dev.IpcGet()
	if err != nil {
		return time.Time{}, false
	}
	in := false
	for _, line := range strings.Split(cfg, "\n") {
		k, v, _ := strings.Cut(line, "=")
		switch {
		case k == "public_key":
			in = v == hexKey
		case in && k == "last_handshake_time_sec":
			sec, err := strconv.ParseInt(v, 10, 64)
			if err != nil || sec == 0 {
				return time.Time{}, false
			}
			return time.Unix(sec, 0), true
		}
	}
	return time.Time{}, false
}

// SetMTU changes the MTU of the interface in place.
func (p *wgPeers) SetMTU(mtu int) error {
	return ipcmd("link", "set", p.iface, "mtu", fmt.Sprint(mtu))
}

func (p *wgPeers) Close() error {
	p.dev.Close()
	_ = exec.Command("ip", "link", "del", p.iface).Run()
	return nil
}
