package wdtt

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// Iface is the TUN interface of the WDTT clients.
const Iface = "wdtt0"

type wgPeers struct {
	mu   sync.Mutex
	dev  *device.Device
	have map[string]string
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

// NewLinuxPeers creates the wdtt0 interface with a userspace WireGuard
// device that talks to clients through the bind.
func NewLinuxPeers(b *bind, serverPrivate string) (Peers, error) {
	_ = exec.Command("ip", "link", "del", Iface).Run()
	t, err := tun.CreateTUN(Iface, TunMTU)
	if err != nil {
		return nil, fmt.Errorf("create %s: %w", Iface, err)
	}
	logger := &device.Logger{Verbosef: device.DiscardLogf, Errorf: func(f string, a ...any) {
		// Peers have no endpoint until their client connects; WireGuard
		// reports every attempt to reach them, which is expected noise.
		if strings.Contains(f, "no known endpoint") || (len(a) > 0 && strings.Contains(fmt.Sprint(a[len(a)-1]), "no known endpoint")) {
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
		{"addr", "replace", ServerIP + "/24", "dev", Iface},
		{"link", "set", Iface, "mtu", fmt.Sprint(TunMTU), "up"},
	} {
		if err := ipcmd(args...); err != nil {
			dev.Close()
			return nil, err
		}
	}
	// Clients get IPv4 only; no IPv6 link-local chatter on the interface.
	_ = os.WriteFile("/proc/sys/net/ipv6/conf/"+Iface+"/disable_ipv6", []byte("1"), 0644)
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, err
	}
	return &wgPeers{dev: dev, have: map[string]string{}}, nil
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

func (p *wgPeers) Close() error {
	p.dev.Close()
	_ = exec.Command("ip", "link", "del", Iface).Run()
	return nil
}
