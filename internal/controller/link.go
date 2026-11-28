package controller

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"os"
	"slices"
	"strconv"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/Jetvac/wdtt-router/internal/agent"
	"github.com/Jetvac/wdtt-router/internal/auth"
	"github.com/Jetvac/wdtt-router/internal/spec"
)

// The chain tunnel (docs/chain-link.md): its mode is a panel setting;
// the planner gives each chain server its part (keys, ports, next hop).
// Modes: off (Xray only, as before), check (the tunnel is up and measured,
// client traffic stays on Xray), udp (client UDP and ICMP on the tunnel,
// falling back to Xray by itself).
const linkOff = "off"

func validLinkMode(m string) bool { return m == linkOff || m == spec.LinkCheck || m == spec.LinkUDP }

func (a *App) linkMode() string {
	if m := a.Store.Setting("chain_link", linkOff); validLinkMode(m) {
		return m
	}
	return linkOff
}

// newWGKey returns a WireGuard private key (base64).
func newWGKey() (string, error) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return "", err
	}
	k[0] &= 248
	k[31] = k[31]&127 | 64
	return base64.StdEncoding.EncodeToString(k), nil
}

func wgPublic(priv string) (string, error) {
	k, err := base64.StdEncoding.DecodeString(priv)
	if err != nil || len(k) != 32 {
		return "", fmt.Errorf("bad key")
	}
	pub, err := curve25519.X25519(k, curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pub), nil
}

func newPSK() (string, error) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(k), nil
}

// linkMissing lists the chain servers whose agent has no tunnel yet (an
// older version): the tunnel is offered once every server has it.
func linkMissing(chain []int64, byID map[int64]Node) []string {
	var out []string
	for _, id := range chain {
		if n := byID[id]; !slices.Contains(n.Status.Features, spec.FeatureLink) {
			out = append(out, n.Name)
		}
	}
	return out
}

// linkMTU: the smallest client MTU of the entry's WDTT servers, so that
// nothing the tunnel brings back is too big for a client.
func linkMTU(es EntrySettings) int {
	mtu := 0
	pick := func(on bool, v int) {
		if !on {
			return
		}
		if v == 0 {
			v = 1280
		}
		if mtu == 0 || v < mtu {
			mtu = v
		}
	}
	pick(es.WDTTEnabled, es.WDTTMTU)
	pick(es.TurnVK.Enabled, es.TurnVK.MTU)
	if mtu == 0 {
		mtu = 1280
	}
	return min(max(mtu, 1200), 1340)
}

// planLink gives the chain servers their part of the tunnel.
func (a *App) planLink(plans map[int64]*spec.NodeSpec, chain []int64, byID map[int64]Node, es EntrySettings) error {
	mode := a.linkMode()
	if mode == linkOff || len(chain) < 2 || len(linkMissing(chain, byID)) > 0 {
		return nil
	}
	exitID := chain[len(chain)-1]
	entryPriv, err := a.secret("link_priv", newWGKey)
	if err != nil {
		return err
	}
	exitPriv, err := a.secret(fmt.Sprintf("node:%d:link_priv", exitID), newWGKey)
	if err != nil {
		return err
	}
	psk, err := a.secret(fmt.Sprintf("node:%d:link_psk", exitID), newPSK)
	if err != nil {
		return err
	}
	entryPub, err := wgPublic(entryPriv)
	if err != nil {
		return err
	}
	exitPub, err := wgPublic(exitPriv)
	if err != nil {
		return err
	}
	mtu := linkMTU(es)
	next := func(i int) *spec.NextHop {
		n := byID[chain[i+1]]
		return &spec.NextHop{Addr: n.MeshIP, Port: n.HopPort}
	}
	for i, id := range chain {
		p := plans[id]
		if p == nil {
			continue
		}
		switch {
		case i == 0:
			p.Link = &spec.LinkSpec{Mode: mode, Next: next(i), PrivateKey: entryPriv, PeerKey: exitPub, PSK: psk, MTU: mtu}
		case i == len(chain)-1:
			p.Link = &spec.LinkSpec{Mode: spec.LinkOn, Port: byID[id].HopPort, PrivateKey: exitPriv, PeerKey: entryPub, PSK: psk, MTU: mtu}
		default:
			p.Link = &spec.LinkSpec{Mode: spec.LinkOn, Port: byID[id].HopPort, Next: next(i)}
		}
		if err := p.Validate(); err != nil {
			return fmt.Errorf("%s: %w", byID[id].Name, err)
		}
	}
	return nil
}

// LinkView is the tunnel's state for the interface.
type LinkView struct {
	Mode    string           `json:"mode"`
	Missing []string         `json:"missing,omitempty"` // servers to update first
	Entry   *spec.LinkStatus `json:"entry,omitempty"`
	Exit    *spec.LinkStatus `json:"exit,omitempty"`
	// Ready: the check passed, "udp" may be chosen; Why: what is missing.
	Ready bool   `json:"ready"`
	Why   string `json:"why,omitempty"`
}

// localLinkStatus reads the entry's tunnel state straight from the service
// (the panel runs on the entry), falling back to the last status report.
func (a *App) localLinkStatus(n Node) *spec.LinkStatus {
	if b, err := os.ReadFile(agent.LinkStatusPath); err == nil {
		var st spec.LinkStatus
		if json.Unmarshal(b, &st) == nil && st.Role == spec.RoleEntry {
			return &st
		}
	}
	return n.Status.Link
}

func (a *App) linkView() LinkView {
	v := LinkView{Mode: a.linkMode()}
	nodes, _ := a.nodes()
	byID := map[int64]Node{}
	for _, n := range nodes {
		byID[n.ID] = n
	}
	chain := a.chainIDs()
	if len(chain) < 2 {
		v.Why = "цепочка не задана"
		return v
	}
	v.Missing = linkMissing(chain, byID)
	v.Entry = a.localLinkStatus(byID[chain[0]])
	v.Exit = byID[chain[len(chain)-1]].Status.Link
	v.Ready, v.Why = linkReady(v)
	return v
}

// linkReady: client UDP may move to the tunnel only after the check mode
// has shown it working: answers to probes, a fresh handshake, DNS through
// it, and a full-size datagram across the path.
func linkReady(v LinkView) (bool, string) {
	e := v.Entry
	switch {
	case len(v.Missing) > 0:
		return false, "обновите серверы: " + fmt.Sprint(v.Missing)
	case v.Mode == linkOff:
		return false, "сначала включите проверку"
	case e == nil || time.Since(time.Unix(e.UpdatedAt, 0)) > time.Minute:
		return false, "служба туннеля на входе не отвечает"
	case !e.Healthy:
		if why := linkStuck(v); why != "" {
			return false, why
		}
		return false, "туннель неисправен: " + e.Problem
	case e.DNSAt == 0 || e.DNSError != "":
		return false, "DNS через туннель ещё не проверен"
	case e.Confirmed == 0:
		return false, "ещё не проверено, проходят ли большие пакеты"
	}
	return true, ""
}

// linkStuck names where the tunnel's packets stop, when the ends can tell:
// a server's kernel or firewall would drop them, or the packet counts of
// the two ends show which side never passes them on.
func linkStuck(v LinkView) string {
	e, x := v.Entry, v.Exit
	switch {
	case x != nil && x.PathProblem != "":
		return "выход: " + x.PathProblem
	case e != nil && e.PathProblem != "":
		return "вход: " + e.PathProblem
	case e == nil || x == nil || x.Role != spec.RoleExit:
		return ""
	case e.TunOut > 0 && x.TunIn == 0:
		return "пакеты уходят в туннель на входе, но не выходят из него на выходе"
	case x.TunIn > 0 && x.TunOut == 0:
		return "пакеты доходят до выхода, но из Интернета через него ничего не возвращается: проверьте межсетевой экран выхода и сеть хостера"
	case x.TunOut > 0 && e.TunIn == 0:
		return "ответы уходят с выхода в туннель, но не выходят из него на входе"
	}
	return ""
}

func (a *App) getLink(w http.ResponseWriter, r *http.Request, s auth.Session) {
	writeJSON(w, 200, a.linkView())
}

func (a *App) putLink(w http.ResponseWriter, r *http.Request, s auth.Session) {
	var body struct {
		Mode string `json:"mode"`
	}
	if !decode(w, r, &body) {
		return
	}
	if !validLinkMode(body.Mode) {
		apiError(w, 400, "неизвестный режим")
		return
	}
	v := a.linkView()
	if body.Mode != linkOff {
		if len(a.chainIDs()) < 2 {
			apiError(w, 409, "цепочка не задана")
			return
		}
		if len(v.Missing) > 0 {
			apiError(w, 409, "сначала обновите серверы цепочки: "+fmt.Sprint(v.Missing))
			return
		}
	}
	if body.Mode == spec.LinkUDP && v.Mode != spec.LinkUDP {
		if ok, why := linkReady(v); !ok {
			apiError(w, 409, "туннель ещё не прошёл проверку: "+why)
			return
		}
	}
	if err := a.Store.SetSetting("chain_link", body.Mode); err != nil {
		apiError(w, 500, err.Error())
		return
	}
	a.audit(r, s, "chain.link", body.Mode)
	if _, err := a.Plan(); err != nil {
		apiError(w, 409, err.Error())
		return
	}
	id, err := a.Enqueue("apply.all", 0, "Применение конфигурации ко всем серверам", s.Username, nil)
	if err != nil {
		apiError(w, 500, err.Error())
		return
	}
	writeJSON(w, 202, map[string]any{"job_id": id, "link": a.linkView()})
}

// observeLink turns the entry tunnel's path changes into events and keeps
// its round trip for the graphs. Called with the monitor's lock held.
func (a *App) observeLink(n Node) {
	st := a.localLinkStatus(n)
	if st == nil || a.linkMode() == linkOff {
		return
	}
	if st.RTT50 > 0 {
		_, _ = a.Store.DB.Exec(`INSERT INTO metrics(node_id,at,ping_ms) VALUES(-1,?,?)`, time.Now().Unix(), int64(st.RTT50+0.5))
	}
	if out, _ := strconv.ParseInt(a.Store.Setting("link_mesh_out_seen", "0"), 10, 64); st.MeshOutAt > out {
		_ = a.Store.SetSetting("link_mesh_out_seen", strconv.FormatInt(st.MeshOutAt, 10))
		a.event(EventChain, "⚪ Mesh до следующего сервера пропадал на %.0f с: туннель переждал, UDP клиентов не переключался (Xray тоже идёт через Mesh)", math.Max(1, st.MeshOutSec))
	}
	seen, _ := strconv.ParseInt(a.Store.Setting("link_switch_seen", "0"), 10, 64)
	if st.SwitchAt == 0 || st.SwitchAt <= seen {
		return
	}
	_ = a.Store.SetSetting("link_switch_seen", strconv.FormatInt(st.SwitchAt, 10))
	switch st.SwitchTo {
	case "xray":
		a.event(EventChain, "🟠 UDP клиентов переключён на Xray: %s", short(st.SwitchWhy, 200))
	case "link":
		a.event(EventChain, "🟢 UDP клиентов снова идёт через туннель цепочки")
	}
}

// linkSummary is the tunnel's line of /status.
func (a *App) linkSummary(n Node) string {
	mode := a.linkMode()
	if mode == linkOff {
		return ""
	}
	st := a.localLinkStatus(n)
	if st == nil {
		return "Туннель цепочки: 🔴 служба не работает"
	}
	path := "UDP через Xray"
	if st.Routing {
		path = "UDP через туннель"
	}
	icon := "🟢"
	if !st.Healthy {
		icon = "🔴"
	}
	return fmt.Sprintf("Туннель цепочки: %s %s, круг %.0f мс, потери %.1f%%, %s", icon, map[string]string{spec.LinkCheck: "проверка", spec.LinkUDP: "UDP"}[mode], st.RTT50, st.Loss*100, path)
}
