package controller

import (
	"testing"
	"testing/fstest"

	"github.com/Jetvac/wdtt-router/internal/spec"
	"github.com/Jetvac/wdtt-router/internal/store"
)

func testApp(t *testing.T) *App {
	t.Helper()
	a, err := Open(t.TempDir(), 8443, "203.0.113.1", fstest.MapFS{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Store.Close() })
	if _, _, err := a.Init("203.0.113.1"); err != nil {
		t.Fatal(err)
	}
	return a
}

func addNode(t *testing.T, a *App, name, mesh string, port int) int64 {
	t.Helper()
	res, err := a.Store.DB.Exec(`INSERT INTO nodes(name,host,mesh_ip,cf_node_id,cf_node_name,hop_port,ssh_public,firewall,created_at) VALUES(?,?,?,?,?,?,0,1,?)`,
		name, name+".example", mesh, "id-"+name, "wdttr-"+name, port, now())
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	if err := a.Store.PutSecret(spec_tokenName(id), "token-"+name); err != nil {
		t.Fatal(err)
	}
	return id
}

func spec_tokenName(id int64) string { return "node:" + itoa(id) + ":mesh_token" }

func itoa(i int64) string {
	b := []byte{}
	for i > 0 || len(b) == 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func TestPlanThreeHops(t *testing.T) {
	a := testApp(t)
	entry, _ := a.localNode()
	_, _ = a.Store.DB.Exec(`UPDATE nodes SET cf_node_id='id-e', cf_node_name='wdttr-e', mesh_ip='100.96.0.1' WHERE id=?`, entry.ID)
	_ = a.Store.PutSecret(spec_tokenName(entry.ID), "token-e")
	r := addNode(t, a, "relay", "100.96.0.2", 31000)
	x := addNode(t, a, "exit", "100.96.0.3", 32000)
	idle := addNode(t, a, "spare", "100.96.0.4", 33000)
	_ = a.Store.SetSetting("chain", "["+itoa(entry.ID)+","+itoa(r)+","+itoa(x)+"]")

	plans, err := a.Plan()
	if err != nil {
		t.Fatal(err)
	}
	if plans[entry.ID].Role != spec.RoleEntry || plans[r].Role != spec.RoleRelay || plans[x].Role != spec.RoleExit || plans[idle].Role != spec.RoleIdle {
		t.Fatal("wrong roles")
	}
	e := plans[entry.ID].Entry
	if len(e.Chain) != 2 || e.Chain[0].Addr != "100.96.0.2" || e.Chain[1].Addr != "100.96.0.3" {
		t.Fatalf("onion order wrong: %+v", e.Chain)
	}
	if plans[r].Hop.Next.Addr != "100.96.0.3" || plans[r].Hop.Next.Port != 32000 {
		t.Fatal("relay must point at the exit")
	}
	if plans[r].Firewall.SSHPublic || plans[x].Firewall.SSHPublic {
		t.Fatal("downstream SSH must be Mesh-only by default")
	}
	if !plans[entry.ID].Firewall.SSHPublic {
		t.Fatal("entry SSH stays public")
	}
	// Keys are stable between plans and pair up correctly.
	again, _ := a.Plan()
	if planHash(again[x]) != planHash(plans[x]) || planHash(again[entry.ID]) != planHash(plans[entry.ID]) {
		t.Fatal("plan must be deterministic")
	}
	hx, _ := a.hopSecrets(x)
	if e.Chain[1].UUID != hx.UUID || e.Chain[1].Encryption != hx.Enc || plans[x].Hop.Decryption != hx.Dec {
		t.Fatal("entry and exit keys do not match")
	}
}

func TestPlanRejectsUnenrolledHop(t *testing.T) {
	a := testApp(t)
	entry, _ := a.localNode()
	_, _ = a.Store.DB.Exec(`UPDATE nodes SET cf_node_id='id-e', cf_node_name='wdttr-e', mesh_ip='100.96.0.1' WHERE id=?`, entry.ID)
	_ = a.Store.PutSecret(spec_tokenName(entry.ID), "token-e")
	res, _ := a.Store.DB.Exec(`INSERT INTO nodes(name,host,created_at) VALUES('raw','raw.example',?)`, now())
	id, _ := res.LastInsertId()
	_ = a.Store.SetSetting("chain", "["+itoa(entry.ID)+","+itoa(id)+"]")
	if _, err := a.Plan(); err == nil {
		t.Fatal("a server outside Mesh cannot be part of the chain")
	}
}

// A server that has just joined Mesh keeps public SSH until the panel has
// reached it through Mesh; then it closes.
func TestMeshPendingKeepsPublicSSH(t *testing.T) {
	a := testApp(t)
	id := addNode(t, a, "exit", "100.96.0.9", 40001)
	sshPublic := func() bool {
		plans, err := a.Plan()
		if err != nil {
			t.Fatal(err)
		}
		return plans[id].Firewall.SSHPublic
	}
	if sshPublic() {
		t.Fatal("enrolled server keeps public SSH without a pending Mesh check")
	}
	a.setMeshPending(id, true)
	if !sshPublic() || !a.meshPending(id) {
		t.Fatal("public SSH closed before the panel reached the server via Mesh")
	}
	a.setMeshPending(id, false)
	if sshPublic() {
		t.Fatal("public SSH still open after the Mesh check passed")
	}
}

// Both WDTT servers: each gets its own keys, ports and owner password, and
// they share the traffic port.
func TestPlanTwoWDTTServers(t *testing.T) {
	a := testApp(t)
	entry, _ := a.localNode()
	_ = a.Store.SetSetting("wdtt_enabled", "1")
	_ = a.Store.SetSetting("wdtt_turnvk_enabled", "1")
	// A key stored by 1.2 (no kind, one device) belongs to the standard server.
	if _, err := a.Store.DB.Exec(`INSERT INTO wdtt_keys(id,name,password_cipher,created_at) VALUES('kold','old',?,'2026-01-01T00:00:00Z')`, mustSeal(t, a, "old-key-password-0123")); err != nil {
		t.Fatal(err)
	}
	for _, k := range []store.WDTTKey{
		{ID: "kstd", Name: "std", Password: "std-key-password-0123", Kind: spec.WDTTStandard, MaxDevices: 3},
		{ID: "ktvk", Name: "tvk", Password: "tvk-key-password-0123", Kind: spec.WDTTTurnVK,
			Unbind: []store.WDTTUnbind{{Device: "phone", At: 1800000000}}},
	} {
		if err := a.Store.PutWDTTKey(k); err != nil {
			t.Fatal(err)
		}
	}
	plans, err := a.Plan()
	if err != nil {
		t.Fatal(err)
	}
	e := plans[entry.ID].Entry
	if e == nil || !e.WDTT.Enabled || e.TurnVK == nil || !e.TurnVK.Enabled {
		t.Fatalf("both servers must be on: %+v", e)
	}
	if e.WDTT.DTLSPort != 56000 || e.TurnVK.DTLSPort != 56010 || e.TurnVK.WGPort != 56011 || e.WDTT.TProxy != e.TurnVK.TProxy {
		t.Fatalf("ports: %+v / %+v", e.WDTT, *e.TurnVK)
	}
	if e.WDTT.Password == e.TurnVK.Password {
		t.Fatal("each server has its own owner password")
	}
	ids := func(ks []spec.WDTTKey) map[string]spec.WDTTKey {
		m := map[string]spec.WDTTKey{}
		for _, k := range ks {
			m[k.ID] = k
		}
		return m
	}
	std, tvk := ids(e.WDTT.Keys), ids(e.TurnVK.Keys)
	if len(std) != 2 || len(tvk) != 1 || std["kold"].MaxDevices != 1 || std["kstd"].MaxDevices != 3 || tvk["ktvk"].MaxDevices != 0 {
		t.Fatalf("keys: %+v / %+v", std, tvk)
	}
	if u := tvk["ktvk"].Unbind; len(u) != 1 || u[0].Device != "phone" || u[0].At != 1800000000 {
		t.Fatalf("unbind: %+v", u)
	}
	if got := e.WDTTServers(); len(got) != 2 || got[0].Kind != spec.WDTTStandard || got[1].Kind != spec.WDTTTurnVK {
		t.Fatalf("servers: %+v", got)
	}

	// The TurnVK server alone: the standard one stays off.
	_ = a.Store.SetSetting("wdtt_enabled", "0")
	plans, _ = a.Plan()
	if e := plans[entry.ID].Entry; e.WDTT.Enabled || e.TurnVK == nil || len(e.WDTTServers()) != 1 {
		t.Fatalf("turnvk only: %+v", e)
	}
	// Both off: no TurnVK block in the spec, so its hash is the one of 1.2.
	_ = a.Store.SetSetting("wdtt_turnvk_enabled", "0")
	plans, _ = a.Plan()
	if e := plans[entry.ID].Entry; e.TurnVK != nil {
		t.Fatal("a disabled TurnVK server must not appear in the spec")
	}
}

func mustSeal(t *testing.T, a *App, s string) string {
	t.Helper()
	c, err := a.Store.Seal(s)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
