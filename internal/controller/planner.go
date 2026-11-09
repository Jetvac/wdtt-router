package controller

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/Jetvac/wdtt-router/internal/spec"
)

// Settings of the entry services, stored in the settings table.
type EntrySettings struct {
	WDTTEnabled  bool     `json:"wdtt_enabled"`
	WDTTDTLSPort int      `json:"wdtt_dtls_port"`
	WDTTWGPort   int      `json:"wdtt_wg_port"`
	WDTTDNS      string   `json:"wdtt_dns"`
	WDTTMTU      int      `json:"wdtt_mtu"`
	XUIEnabled   bool     `json:"xui_enabled"`
	XUIRoute     bool     `json:"xui_route_via_chain"`
	PanelPort    int      `json:"panel_port"`
	PanelAllow   []string `json:"panel_allow"`
	// PanelMeshOnly: the panel is reachable only through Cloudflare Mesh.
	PanelMeshOnly bool `json:"panel_mesh_only"`
}

func atoi(s string, def int) int {
	if v, err := strconv.Atoi(s); err == nil {
		return v
	}
	return def
}

func (a *App) entrySettings() EntrySettings {
	s := EntrySettings{
		WDTTEnabled:  a.Store.Setting("wdtt_enabled", "0") == "1",
		WDTTDTLSPort: atoi(a.Store.Setting("wdtt_dtls_port", "56000"), 56000),
		WDTTWGPort:   atoi(a.Store.Setting("wdtt_wg_port", "56001"), 56001),
		WDTTDNS:      a.Store.Setting("wdtt_dns", "1.1.1.1"),
		WDTTMTU:      atoi(a.Store.Setting("wdtt_mtu", "1280"), 1280),
		XUIEnabled:   a.Store.Setting("xui_enabled", "0") == "1",
		XUIRoute:     a.Store.Setting("xui_route", "1") == "1",
		PanelPort:    a.PanelPort,
		PanelAllow:   []string{},
	}
	for _, c := range strings.Split(a.Store.Setting("panel_allow", ""), ",") {
		if c = strings.TrimSpace(c); c != "" {
			s.PanelAllow = append(s.PanelAllow, c)
		}
	}
	s.PanelMeshOnly = a.Store.Setting("panel_mesh_only", "0") == "1"
	return s
}

// chainIDs returns the ordered node IDs of the chain, entry first.
func (a *App) chainIDs() []int64 {
	var ids []int64
	_ = json.Unmarshal([]byte(a.Store.Setting("chain", "[]")), &ids)
	return ids
}

// secret returns a stored secret, generating it with gen on first use.
func (a *App) secret(name string, gen func() (string, error)) (string, error) {
	if v, err := a.Store.Secret(name); err == nil && v != "" {
		return v, nil
	}
	v, err := gen()
	if err != nil {
		return "", err
	}
	return v, a.Store.PutSecret(name, v)
}

type hopSecrets struct{ UUID, Dec, Enc string }

func (a *App) hopSecrets(id int64) (hopSecrets, error) {
	p := fmt.Sprintf("node:%d:", id)
	if u, err := a.Store.Secret(p + "hop_uuid"); err == nil {
		d, e1 := a.Store.Secret(p + "hop_dec")
		e, e2 := a.Store.Secret(p + "hop_enc")
		if e1 == nil && e2 == nil {
			return hopSecrets{u, d, e}, nil
		}
	}
	k, err := spec.NewHopKeys()
	if err != nil {
		return hopSecrets{}, err
	}
	h := hopSecrets{spec.NewUUID(), k.Decryption, k.Encryption}
	for k, v := range map[string]string{"hop_uuid": h.UUID, "hop_dec": h.Dec, "hop_enc": h.Enc} {
		if err := a.Store.PutSecret(p+k, v); err != nil {
			return h, err
		}
	}
	return h, nil
}

// Plan computes the desired spec of every node.
func (a *App) Plan() (map[int64]*spec.NodeSpec, error) {
	nodes, err := a.nodes()
	if err != nil {
		return nil, err
	}
	byID := map[int64]Node{}
	for _, n := range nodes {
		byID[n.ID] = n
	}
	chain := a.chainIDs()
	pos := map[int64]int{}
	for i, id := range chain {
		if _, ok := byID[id]; !ok {
			return nil, fmt.Errorf("сервер #%d из цепочки не найден", id)
		}
		pos[id] = i
	}
	if len(chain) > 0 && !byID[chain[0]].Local {
		return nil, errors.New("цепочка должна начинаться с сервера панели")
	}
	es := a.entrySettings()
	plans := map[int64]*spec.NodeSpec{}
	var entry Node
	for _, n := range nodes {
		if n.Local {
			entry = n
		}
	}
	botNode, hasBot := byID[a.botNodeID()]
	for _, n := range nodes {
		s := &spec.NodeSpec{Version: spec.Version, NodeID: n.ID, Role: spec.RoleIdle}
		if n.CFNodeID != "" {
			tok, err := a.Store.Secret(fmt.Sprintf("node:%d:mesh_token", n.ID))
			if err != nil {
				return nil, fmt.Errorf("%s: нет токена Mesh-узла", n.Name)
			}
			s.Mesh = spec.MeshSpec{Enabled: true, NodeName: n.CFNodeName, CFNodeID: n.CFNodeID, Token: tok}
		}
		s.Firewall = spec.FirewallSpec{Enabled: n.Firewall, SSHPort: n.SSHPort, SSHPublic: n.SSHPublic || n.Local || !s.Mesh.Enabled || a.meshPending(n.ID), SSHAllow: n.SSHAllow, AllowPing: n.AllowPing}
		s.Hardening = n.Hardening
		i, inChain := pos[n.ID]
		switch {
		case n.Local:
			s.Role = spec.RoleEntry
			s.Firewall.PanelPort = es.PanelPort
			s.Firewall.PanelAllow = es.PanelAllow
			s.Firewall.PanelMeshOnly = es.PanelMeshOnly
			e, err := a.entrySpec(es)
			if err != nil {
				return nil, err
			}
			if len(chain) > 1 && !s.Mesh.Enabled {
				return nil, fmt.Errorf("%s (сервер панели) ещё не подключён к Mesh", n.Name)
			}
			for _, id := range chain[min(1, len(chain)):] {
				d := byID[id]
				if d.MeshIP == "" || d.HopPort == 0 {
					return nil, fmt.Errorf("%s ещё не подключён к Mesh", d.Name)
				}
				h, err := a.hopSecrets(id)
				if err != nil {
					return nil, err
				}
				e.Chain = append(e.Chain, spec.OnionHop{Addr: d.MeshIP, Port: d.HopPort, UUID: h.UUID, Encryption: h.Enc})
			}
			s.Entry = e
		case inChain && i > 0:
			if !s.Mesh.Enabled || n.MeshIP == "" {
				return nil, fmt.Errorf("%s ещё не подключён к Mesh", n.Name)
			}
			h, err := a.hopSecrets(n.ID)
			if err != nil {
				return nil, err
			}
			s.Hop = &spec.HopSpec{Port: n.HopPort, UUID: h.UUID, Decryption: h.Dec}
			if i == len(chain)-1 {
				s.Role = spec.RoleExit
			} else {
				s.Role = spec.RoleRelay
				next := byID[chain[i+1]]
				s.Hop.Next = &spec.NextHop{Addr: next.MeshIP, Port: next.HopPort}
			}
		}
		if hasBot && n.ID == botNode.ID {
			b, err := a.botSpec(n, entry)
			if err != nil {
				return nil, err
			}
			s.Bot = b
		}
		if err := s.Validate(); err != nil {
			return nil, fmt.Errorf("%s: %w", n.Name, err)
		}
		plans[n.ID] = s
	}
	return plans, nil
}

func (a *App) entrySpec(es EntrySettings) (*spec.EntrySpec, error) {
	port := atoi(a.Store.Setting("socks_port", ""), 0)
	if port == 0 {
		port = spec.RandomPort()
		_ = a.Store.SetSetting("socks_port", strconv.Itoa(port))
	}
	tproxy := atoi(a.Store.Setting("tproxy_port", ""), 0)
	if tproxy == 0 || tproxy == port {
		tproxy = port + 1
		_ = a.Store.SetSetting("tproxy_port", strconv.Itoa(tproxy))
	}
	user, err := a.secret("socks_user", func() (string, error) { return "u" + spec.NewPassword(10), nil })
	if err != nil {
		return nil, err
	}
	pass, err := a.secret("socks_pass", func() (string, error) { return spec.NewPassword(32), nil })
	if err != nil {
		return nil, err
	}
	e := &spec.EntrySpec{Chain: []spec.OnionHop{}, SocksPort: port, SocksUser: user, SocksPass: pass,
		XUI: spec.XUISpec{Enabled: es.XUIEnabled, RouteViaChain: es.XUIRoute}}
	if es.WDTTEnabled {
		wp, err := a.secret("wdtt_password", func() (string, error) { return spec.NewPassword(20), nil })
		if err != nil {
			return nil, err
		}
		keys, err := a.wdttKeySpecs()
		if err != nil {
			return nil, err
		}
		e.WDTT = spec.WDTTSpec{Enabled: true, DTLSPort: es.WDTTDTLSPort, WGPort: es.WDTTWGPort, Password: wp, DNS: es.WDTTDNS, TProxy: tproxy, Keys: keys, MTU: wdttMTU(es.WDTTMTU)}
	}
	return e, nil
}

// planHash mirrors the agent's hash of the saved spec, so the UI can show
// which nodes have pending changes.
func planHash(s *spec.NodeSpec) string {
	b, _ := json.MarshalIndent(s, "", "  ")
	return specHashBytes(b)
}

// wdttMTU leaves the default (1280) out of the spec, so that servers set up
// before the setting existed keep an unchanged configuration.
func wdttMTU(v int) int {
	if v == 1280 {
		return 0
	}
	return v
}
