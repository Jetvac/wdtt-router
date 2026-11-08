package controller

import (
	"testing"
	"testing/fstest"

	"github.com/Jetvac/wdtt-router/internal/spec"
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
