package controller

import (
	"strings"
	"testing"
	"time"

	"github.com/Jetvac/wdtt-router/internal/spec"
)

func TestPlanLink(t *testing.T) {
	a := testApp(t)
	entry, _ := a.localNode()
	_, _ = a.Store.DB.Exec(`UPDATE nodes SET cf_node_id='id-e', cf_node_name='wdttr-e', mesh_ip='100.96.0.1' WHERE id=?`, entry.ID)
	_ = a.Store.PutSecret(spec_tokenName(entry.ID), "token-e")
	r := addNode(t, a, "relay", "100.96.0.2", 31000)
	x := addNode(t, a, "exit", "100.96.0.3", 32000)
	_ = a.Store.SetSetting("chain", "["+itoa(entry.ID)+","+itoa(r)+","+itoa(x)+"]")
	_ = a.Store.SetSetting("chain_link", spec.LinkCheck)

	// Servers on an agent without the tunnel get none: nothing changes.
	plans, err := a.Plan()
	if err != nil {
		t.Fatal(err)
	}
	for id, p := range plans {
		if p.Link != nil {
			t.Fatalf("node %d got the tunnel before its agent supports it", id)
		}
	}
	if v := a.linkView(); len(v.Missing) != 3 || v.Ready {
		t.Fatalf("view %+v", v)
	}

	_, _ = a.Store.DB.Exec(`UPDATE nodes SET status_json='{"features":["link"]}'`)
	plans, err = a.Plan()
	if err != nil {
		t.Fatal(err)
	}
	e, rl, ex := plans[entry.ID].Link, plans[r].Link, plans[x].Link
	if e == nil || rl == nil || ex == nil {
		t.Fatal("no tunnel in the plans")
	}
	if e.Mode != spec.LinkCheck || e.Next.Addr != "100.96.0.2" || e.Next.Port != 31000 || e.MTU != 1280 {
		t.Fatalf("entry %+v", e)
	}
	if rl.Port != 31000 || rl.Next.Addr != "100.96.0.3" || rl.Next.Port != 32000 || rl.PrivateKey != "" || rl.PSK != "" {
		t.Fatalf("relay %+v", rl)
	}
	if ex.Port != 32000 || ex.Mode != spec.LinkOn {
		t.Fatalf("exit %+v", ex)
	}
	ePub, _ := wgPublic(e.PrivateKey)
	xPub, _ := wgPublic(ex.PrivateKey)
	if e.PeerKey != xPub || ex.PeerKey != ePub || e.PSK != ex.PSK || e.PrivateKey == ex.PrivateKey {
		t.Fatal("keys do not pair up")
	}
	again, _ := a.Plan()
	if again[entry.ID].Link.PrivateKey != e.PrivateKey || again[x].Link.PSK != ex.PSK {
		t.Fatal("keys change between plans")
	}
	if planHash(again[x]) != planHash(plans[x]) {
		t.Fatal("the exit's spec changes between plans")
	}

	// Off again: no tunnel anywhere.
	_ = a.Store.SetSetting("chain_link", linkOff)
	plans, _ = a.Plan()
	for _, p := range plans {
		if p.Link != nil {
			t.Fatal("the tunnel stays after it was turned off")
		}
	}
}

func TestLinkMTU(t *testing.T) {
	es := EntrySettings{WDTTEnabled: true, WDTTMTU: 1340, TurnVK: WDTTServerSettings{Enabled: true, MTU: 1280}}
	if linkMTU(es) != 1280 {
		t.Fatal("the smallest client MTU")
	}
	es.TurnVK.Enabled = false
	if linkMTU(es) != 1340 {
		t.Fatal("the only server's MTU")
	}
	if linkMTU(EntrySettings{}) != 1280 {
		t.Fatal("default")
	}
}

func TestLinkReady(t *testing.T) {
	now := time.Now().Unix()
	good := &spec.LinkStatus{Role: spec.RoleEntry, UpdatedAt: now, Healthy: true, DNSAt: now, Confirmed: 1252}
	if ok, why := linkReady(LinkView{Mode: spec.LinkCheck, Entry: good}); !ok {
		t.Fatal(why)
	}
	for name, v := range map[string]LinkView{
		"off":       {Mode: linkOff, Entry: good},
		"no status": {Mode: spec.LinkCheck},
		"stale":     {Mode: spec.LinkCheck, Entry: &spec.LinkStatus{UpdatedAt: now - 300, Healthy: true, DNSAt: now, Confirmed: 1252}},
		"unhealthy": {Mode: spec.LinkCheck, Entry: &spec.LinkStatus{UpdatedAt: now, Problem: "нет ответа", DNSAt: now, Confirmed: 1252}},
		"no DNS":    {Mode: spec.LinkCheck, Entry: &spec.LinkStatus{UpdatedAt: now, Healthy: true, Confirmed: 1252}},
		"DNS fails": {Mode: spec.LinkCheck, Entry: &spec.LinkStatus{UpdatedAt: now, Healthy: true, DNSAt: now, DNSError: "timeout", Confirmed: 1252}},
		"no MTU":    {Mode: spec.LinkCheck, Entry: &spec.LinkStatus{UpdatedAt: now, Healthy: true, DNSAt: now}},
		"old agent": {Mode: spec.LinkCheck, Entry: good, Missing: []string{"exit"}},
	} {
		if ok, why := linkReady(v); ok || why == "" {
			t.Fatalf("%s: ready", name)
		}
	}
}

func TestLinkNamesWherePacketsStop(t *testing.T) {
	now := time.Now().Unix()
	sick := func() *spec.LinkStatus {
		return &spec.LinkStatus{Role: spec.RoleEntry, UpdatedAt: now, Problem: "DNS через туннель не отвечает", DNSAt: now, Confirmed: 1252, TunOut: 12, TunIn: 0}
	}
	exit := func(in, out uint64, problem string) *spec.LinkStatus {
		return &spec.LinkStatus{Role: spec.RoleExit, TunIn: in, TunOut: out, PathProblem: problem}
	}
	for _, c := range []struct {
		name string
		exit *spec.LinkStatus
		want string
	}{
		// exit-de, 26 Nov: Docker's FORWARD DROP, the agent saw it.
		{"exit firewall", exit(12, 0, "iptables FORWARD на выходе отбрасывает пакеты туннеля"), "выход: iptables"},
		{"no answers from the Internet", exit(12, 0, ""), "пакеты доходят до выхода"},
		{"lost inside the tunnel", exit(0, 0, ""), "не выходят из него на выходе"},
		{"answers lost on the way back", exit(12, 12, ""), "не выходят из него на входе"},
		{"no exit status", nil, "туннель неисправен"},
	} {
		_, why := linkReady(LinkView{Mode: spec.LinkCheck, Entry: sick(), Exit: c.exit})
		if !strings.Contains(why, c.want) {
			t.Errorf("%s: %q, want %q in it", c.name, why, c.want)
		}
	}
}

func TestLinkSwitchEvents(t *testing.T) {
	a := testApp(t)
	_ = a.Store.SetSetting("chain_link", spec.LinkUDP)
	n, _ := a.localNode()
	n.Status.Link = &spec.LinkStatus{Role: spec.RoleEntry, SwitchAt: 100, SwitchTo: "xray", SwitchWhy: "нет ответа 4s", RTT50: 52}
	a.observeLink(n)
	a.observeLink(n) // the same switch is told once
	n.Status.Link = &spec.LinkStatus{Role: spec.RoleEntry, SwitchAt: 200, SwitchTo: "link"}
	a.observeLink(n)
	// A Mesh outage the tunnel waited out is told once too.
	n.Status.Link = &spec.LinkStatus{Role: spec.RoleEntry, SwitchAt: 200, SwitchTo: "link", MeshOuts: 1, MeshOutAt: 300, MeshOutSec: 4.4}
	a.observeLink(n)
	a.observeLink(n)
	ev := a.recentEvents(10)
	var msgs []string
	for _, e := range ev {
		msgs = append(msgs, e.Text)
	}
	all := strings.Join(msgs, "\n")
	if strings.Count(all, "переключён на Xray") != 1 || strings.Count(all, "снова идёт через туннель") != 1 ||
		strings.Count(all, "пропадал на 4 с: туннель переждал") != 1 {
		t.Fatalf("events:\n%s", all)
	}
}
