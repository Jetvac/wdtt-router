package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/Jetvac/wdtt-router/internal/sshx"
)

// A server that has just joined Mesh is not reachable through Mesh at once:
// the Cloudflare node needs some seconds (sometimes a minute) to come up.
// Closing its public SSH in the same step would lock the panel out, so a
// newly enrolled server keeps public SSH until the panel has actually
// logged in through its Mesh address ("Mesh pending").

func meshPendingKey(id int64) string { return fmt.Sprintf("node:%d:mesh_pending", id) }

// meshPending reports a server whose Mesh path the panel has not verified
// yet; its public SSH stays open.
func (a *App) meshPending(id int64) bool {
	return a.Store.Setting(meshPendingKey(id), "") != ""
}

func (a *App) setMeshPending(id int64, on bool) {
	v := ""
	if on {
		v = now()
	}
	_ = a.Store.SetSetting(meshPendingKey(id), v)
}

// meshReachable tries to log in to the server through its Mesh address
// until it works or wait runs out.
func (a *App) meshReachable(ctx context.Context, n Node, wait time.Duration) error {
	t := sshx.Target{Host: n.MeshIP, Port: n.SSHPort, User: "root", Fingerprint: n.Fingerprint}
	deadline := time.Now().Add(wait)
	var last error
	for {
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		_, last = a.SSH.Run(cctx, t, "true", nil, nil)
		cancel()
		if last == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return last
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

// finishMesh closes public SSH on a server once the panel reaches it
// through Mesh. If Mesh does not work yet, the server stays reachable over
// public SSH and a later apply tries again.
func (a *App) finishMesh(ctx context.Context, j *jobRun, n Node) {
	if n.Local || n.MeshIP == "" || !a.meshPending(n.ID) {
		return
	}
	wait := 15 * time.Second
	if since, err := time.Parse(time.RFC3339, a.Store.Setting(meshPendingKey(n.ID), "")); err == nil && time.Since(since) < 15*time.Minute {
		wait = 90 * time.Second // just enrolled: the Mesh node is still coming up
	}
	j.Log("%s: проверяю связь с сервером через Mesh (%s)…", n.Name, n.MeshIP)
	if err := a.meshReachable(ctx, n, wait); err != nil {
		j.Log("%s: через Mesh сервер пока недоступен (%v). Публичный SSH оставлен открытым, чтобы не потерять доступ; панель закроет его при следующем применении настроек, когда Mesh-связь заработает. Если так и не заработает — проверьте в Cloudflare Zero Trust, что включён параметр «Allow all Cloudflare One traffic to reach enrolled devices»", n.Name, err)
		a.event(EventServer, "⚠️ %s: нет связи через Mesh — публичный SSH пока оставлен открытым", n.Name)
		return
	}
	j.Log("%s: связь через Mesh работает — закрываю публичный SSH", n.Name)
	a.setMeshPending(n.ID, false)
	if err := a.applyPlanned(ctx, j, n.ID); err != nil {
		// The firewall confirm failed: the agent reverts it on its own.
		j.Log("%s: не удалось закрыть публичный SSH (%v); правила вернутся автоматически", n.Name, err)
		a.setMeshPending(n.ID, true)
	}
}
