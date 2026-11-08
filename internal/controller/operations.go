package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/Jetvac/wdtt-router/internal/cfapi"
	"github.com/Jetvac/wdtt-router/internal/spec"
	"github.com/Jetvac/wdtt-router/internal/sshx"
)

type addNodeInput struct {
	Name     string `json:"name"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Password string `json:"password"`
}

type removeInput struct {
	Force bool `json:"force"`
}

func (a *App) handlers() map[string]jobFunc {
	return map[string]jobFunc{
		"node.add":     a.jobAddNode,
		"node.enroll":  a.jobEnroll,
		"node.leave":   a.jobLeave,
		"node.remove":  a.jobRemove,
		"node.apply":   a.jobApplyNode,
		"apply.all":    a.jobApplyAll,
		"chain.probe":  a.jobProbe,
		"ssh.rotate":   a.jobRotateSSH,
		"xui.reset":    a.jobXUIReset,
		"status.all":   a.jobRefreshAll,
		"agent.update": a.jobAgentUpdate,
	}
}

func (a *App) jobAddNode(ctx context.Context, j *jobRun) error {
	var in addNodeInput
	if err := a.jobInput(j.id, &in); err != nil {
		return err
	}
	t := sshx.Target{Host: in.Host, Port: in.Port, User: "root"}
	j.Log("Подключение к %s:%d по паролю (однократно, пароль не сохраняется)", in.Host, in.Port)
	fp, err := a.SSH.Bootstrap(ctx, t, in.Password)
	if err != nil {
		return fmt.Errorf("SSH: %w", err)
	}
	j.Log("Ключ панели добавлен. Отпечаток сервера: %s", fp)
	res, err := a.Store.DB.Exec(`INSERT INTO nodes(name,host,ssh_port,fingerprint,ssh_public,firewall,created_at) VALUES(?,?,?,?,0,1,?)`, in.Name, in.Host, in.Port, fp, now())
	if err != nil {
		return fmt.Errorf("сервер с таким именем уже есть: %w", err)
	}
	id, _ := res.LastInsertId()
	n, err := a.node(id)
	if err != nil {
		return err
	}
	cleanup := func() { _, _ = a.Store.DB.Exec(`DELETE FROM nodes WHERE id=?`, id) }
	if err := a.ensureAgent(ctx, n, j.progress); err != nil {
		cleanup()
		return err
	}
	n, err = a.refreshStatus(ctx, n)
	if err != nil {
		cleanup()
		return err
	}
	if !strings.Contains(strings.ToLower(n.Status.OS), "ubuntu") && !strings.Contains(strings.ToLower(n.Status.OS), "debian") {
		j.Log("ВНИМАНИЕ: поддерживаются Debian и Ubuntu, обнаружено: %s", n.Status.OS)
	}
	j.Log("Сервер добавлен: %s, %s, %d МБ ОЗУ", n.Status.OS, n.Status.Arch, n.Status.MemTotalMB)
	if a.cfConfigured() {
		j.Log("Подключаю сервер к Cloudflare Mesh")
		return a.enroll(ctx, j, n)
	}
	j.Log("Cloudflare не настроен: подключите сервер к Mesh после настройки аккаунта")
	return nil
}

func (a *App) cfClient() (*cfapi.Client, error) {
	acc := a.Store.Setting("cf_account", "")
	team := a.Store.Setting("cf_team", "")
	tok, err := a.Store.Secret("cf_token")
	if acc == "" || err != nil {
		return nil, errors.New("Cloudflare не настроен")
	}
	return cfapi.New(acc, tok, team)
}

func (a *App) cfConfigured() bool {
	_, err := a.cfClient()
	return err == nil
}

var reSlug = regexp.MustCompile(`[^a-z0-9-]+`)

func (a *App) jobEnroll(ctx context.Context, j *jobRun) error {
	n, err := a.node(jobNode(ctx))
	if err != nil {
		return err
	}
	return a.enroll(ctx, j, n)
}

// enroll creates the Mesh node in Cloudflare and connects the server. It is
// idempotent: an already enrolled server is simply re-applied.
func (a *App) enroll(ctx context.Context, j *jobRun, n Node) error {
	cf, err := a.cfClient()
	if err != nil {
		return err
	}
	checks, err := cf.Preflight(ctx)
	if err != nil {
		return err
	}
	for _, c := range checks {
		if !c.OK {
			return fmt.Errorf("Cloudflare не готов: %s — %s", c.Title, c.Detail)
		}
	}
	created := false
	if n.CFNodeID == "" {
		name := "wdttr-" + strings.Trim(reSlug.ReplaceAllString(strings.ToLower(n.Name), "-"), "-") + "-" + strings.ToLower(spec.NewPassword(4))
		j.Log("Создаю Mesh-узел %s в Cloudflare", name)
		c, err := cf.CreateConnector(ctx, name)
		if err != nil {
			return err
		}
		_, _ = a.Store.DB.Exec(`INSERT OR REPLACE INTO cf_resources(id,kind,name,node_id,created_at) VALUES(?,?,?,?,?)`, c.ID, "connector", name, n.ID, now())
		tok, err := cf.ConnectorToken(ctx, c.ID)
		if err != nil {
			_ = cf.DeleteConnector(context.Background(), c.ID)
			return err
		}
		if err := a.Store.PutSecret(fmt.Sprintf("node:%d:mesh_token", n.ID), tok); err != nil {
			return err
		}
		n.CFNodeID, n.CFNodeName = c.ID, name
		if n.HopPort == 0 {
			n.HopPort = spec.RandomPort()
		}
		if err := a.saveNode(n); err != nil {
			return err
		}
		created = true
	}
	if err := a.applyPlanned(ctx, j, n.ID); err != nil {
		if created {
			j.Log("Откат: удаляю созданный Mesh-узел")
			n, _ = a.node(n.ID)
			a.forgetMesh(context.Background(), cf, n)
			_ = a.applyPlanned(context.Background(), j, n.ID)
		}
		return err
	}
	n, _ = a.node(n.ID)
	if n.MeshIP == "" {
		return errors.New("сервер подключился, но Mesh-адрес не получен")
	}
	j.Log("Mesh-адрес сервера: %s", n.MeshIP)
	return nil
}

func (a *App) forgetMesh(ctx context.Context, cf *cfapi.Client, n Node) {
	if n.CFNodeID != "" && cf != nil {
		if err := cf.DeleteConnector(ctx, n.CFNodeID); err == nil {
			_, _ = a.Store.DB.Exec(`DELETE FROM cf_resources WHERE id=?`, n.CFNodeID)
		}
	}
	_ = a.Store.DeleteSecret(fmt.Sprintf("node:%d:mesh_token", n.ID))
	n.CFNodeID, n.CFNodeName, n.MeshIP = "", "", ""
	_ = a.saveNode(n)
}

func (a *App) inChain(id int64) bool { return slices.Contains(a.chainIDs(), id) }

func (a *App) jobLeave(ctx context.Context, j *jobRun) error {
	n, err := a.node(jobNode(ctx))
	if err != nil {
		return err
	}
	if a.inChain(n.ID) {
		return errors.New("сначала уберите сервер из цепочки")
	}
	if !n.Local && !n.SSHPublic && n.Firewall {
		return errors.New("SSH этого сервера доступен только через Mesh. Сначала разрешите публичный SSH, иначе доступ будет потерян")
	}
	cf, _ := a.cfClient()
	old := n
	n.CFNodeID, n.CFNodeName = "", ""
	if err := a.saveNode(n); err != nil {
		return err
	}
	if err := a.applyPlanned(ctx, j, n.ID); err != nil {
		_ = a.saveNode(old)
		return err
	}
	old.MeshIP = ""
	a.forgetMesh(ctx, cf, old)
	return nil
}

func (a *App) jobRemove(ctx context.Context, j *jobRun) error {
	n, err := a.node(jobNode(ctx))
	if err != nil {
		return err
	}
	if n.Local {
		return errors.New("сервер панели удалить нельзя")
	}
	if a.inChain(n.ID) {
		return errors.New("сначала уберите сервер из цепочки и примените изменения")
	}
	var in removeInput
	_ = a.jobInput(j.id, &in)
	j.Log("Удаляю компоненты с %s", n.Name)
	if _, err := a.agentCall(ctx, n, nil, j.progress, "uninstall", "--purge"); err != nil {
		if !in.Force {
			return fmt.Errorf("%w (можно удалить принудительно — тогда сервер нужно очистить вручную)", err)
		}
		j.Log("Сервер недоступен, удаляю только из панели: %v", err)
	}
	cf, _ := a.cfClient()
	a.forgetMesh(ctx, cf, n)
	for _, k := range []string{"hop_uuid", "hop_dec", "hop_enc", "mesh_token"} {
		_ = a.Store.DeleteSecret(fmt.Sprintf("node:%d:%s", n.ID, k))
	}
	_, err = a.Store.DB.Exec(`DELETE FROM nodes WHERE id=?`, n.ID)
	return err
}

func (a *App) jobApplyNode(ctx context.Context, j *jobRun) error {
	return a.applyPlanned(ctx, j, jobNode(ctx))
}

// applyPlanned applies the current plan to one node.
func (a *App) applyPlanned(ctx context.Context, j *jobRun, id int64) error {
	plans, err := a.Plan()
	if err != nil {
		return err
	}
	n, err := a.node(id)
	if err != nil {
		return err
	}
	return a.applyNode(ctx, j, n, plans[id])
}

func (a *App) applyNode(ctx context.Context, j *jobRun, n Node, s *spec.NodeSpec) error {
	j.Log("── %s: роль «%s»", n.Name, roleName(s.Role))
	if err := a.ensureAgent(ctx, n, j.progress); err != nil {
		return err
	}
	b, _ := json.Marshal(s)
	out, err := a.agentCall(ctx, n, b, j.progress, "apply")
	var res spec.ApplyResult
	if len(out) > 0 {
		_ = json.Unmarshal(out, &res)
	}
	if res.Status.AgentVersion != "" {
		n.Status = res.Status
		n.LastSeen = now()
		if res.Status.MeshIP != "" {
			n.MeshIP = res.Status.MeshIP
		}
	}
	if err != nil {
		n.LastError = err.Error()
		_ = a.saveObserved(n)
		return fmt.Errorf("%s: %w", n.Name, err)
	}
	n.LastError = ""
	if err := a.saveObserved(n); err != nil {
		return err
	}
	for k, v := range res.Secrets {
		_ = a.Store.PutSecret("xui:"+k, v)
	}
	for _, c := range res.Changed {
		j.Log("%s: %s", n.Name, c)
	}
	if len(res.Changed) == 0 {
		j.Log("%s: изменений нет", n.Name)
	}
	if res.RevertPending {
		j.Log("%s: проверяю доступ после смены firewall новым соединением", n.Name)
		n, _ = a.node(n.ID)
		if _, err := a.agentCall(ctx, n, nil, nil, "confirm"); err != nil {
			return fmt.Errorf("%s: после изменения firewall панель не смогла подключиться заново (%v). Правила будут автоматически откатаны через 2 минуты", n.Name, err)
		}
		j.Log("%s: доступ подтверждён, правила firewall закреплены", n.Name)
	}
	return nil
}

func roleName(r string) string {
	switch r {
	case spec.RoleEntry:
		return "вход"
	case spec.RoleRelay:
		return "промежуточный"
	case spec.RoleExit:
		return "выход"
	}
	return "не в цепочке"
}

// jobApplyAll applies the plan to every node: downstream hops first, so each
// hop is listening before the previous one points at it, then idle nodes and
// finally the entry. It ends with an end-to-end probe.
func (a *App) jobApplyAll(ctx context.Context, j *jobRun) error {
	plans, err := a.Plan()
	if err != nil {
		return err
	}
	chain := a.chainIDs()
	order := []int64{}
	for i := len(chain) - 1; i >= 1; i-- {
		order = append(order, chain[i])
	}
	nodes, _ := a.nodes()
	var entry int64
	for _, n := range nodes {
		if n.Local {
			entry = n.ID
			continue
		}
		if !slices.Contains(order, n.ID) {
			order = append(order, n.ID)
		}
	}
	order = append(order, entry)
	for _, id := range order {
		n, err := a.node(id)
		if err != nil {
			return err
		}
		if err := a.applyNode(ctx, j, n, plans[id]); err != nil {
			return err
		}
	}
	if len(chain) > 1 {
		return a.probe(ctx, j)
	}
	j.Log("Цепочка не задана: трафик WDTT и 3x-ui никуда не направляется")
	return nil
}

func (a *App) jobProbe(ctx context.Context, j *jobRun) error { return a.probe(ctx, j) }

// ProbeRecord is the saved result of the last end-to-end check.
type ProbeRecord struct {
	spec.ProbeResult
	At         string `json:"at"`
	ExitNode   string `json:"exit_node"`
	ExpectedIP string `json:"expected_ip"`
	Match      bool   `json:"match"`
}

func (a *App) probe(ctx context.Context, j *jobRun) error {
	chain := a.chainIDs()
	if len(chain) < 2 {
		return errors.New("цепочка не задана")
	}
	entry, err := a.localNode()
	if err != nil {
		return err
	}
	exit, err := a.node(chain[len(chain)-1])
	if err != nil {
		return err
	}
	j.Log("Проверка цепочки: TCP и UDP через все узлы")
	var r spec.ProbeResult
	var out []byte
	for attempt := 1; attempt <= 3; attempt++ {
		out, err = a.agentCall(ctx, entry, nil, nil, "probe")
		if err != nil {
			return err
		}
		r = spec.ProbeResult{}
		_ = json.Unmarshal(out, &r)
		if r.OK {
			break
		}
		j.Log("Попытка %d: %s", attempt, r.Error)
		time.Sleep(3 * time.Second)
	}
	rec := ProbeRecord{ProbeResult: r, At: now(), ExitNode: exit.Name, ExpectedIP: exit.Status.PublicIPv4}
	rec.Match = r.OK && r.ExitIP == exit.Status.PublicIPv4
	b, _ := json.Marshal(rec)
	_ = a.Store.SetSetting("last_probe", string(b))
	if !r.OK {
		return errors.New("проверка цепочки не прошла: " + r.Error)
	}
	j.Log("Выход в Интернет: %s (Cloudflare %s), TCP %d мс, UDP %d мс", r.ExitIP, r.Colo, r.TCPms, r.UDPms)
	if !rec.Match {
		return fmt.Errorf("трафик выходит с адреса %s, а ожидался %s (%s)", r.ExitIP, exit.Status.PublicIPv4, exit.Name)
	}
	return nil
}

func (a *App) jobXUIReset(ctx context.Context, j *jobRun) error {
	n, err := a.localNode()
	if err != nil {
		return err
	}
	user := "admin" + strings.ToLower(spec.NewPassword(4))
	pass := spec.NewPassword(24)
	out, err := a.agentCall(ctx, n, []byte(user+"\n"+pass+"\n"), j.progress, "xui-reset")
	if err != nil {
		return err
	}
	var creds map[string]string
	if err := json.Unmarshal(out, &creds); err != nil {
		return err
	}
	for k, v := range creds {
		_ = a.Store.PutSecret("xui:"+k, v)
	}
	j.Log("Новые учётные данные 3x-ui сохранены")
	return nil
}

func (a *App) jobRefreshAll(ctx context.Context, j *jobRun) error {
	nodes, err := a.nodes()
	if err != nil {
		return err
	}
	var failed []string
	for _, n := range nodes {
		if _, err := a.refreshStatus(ctx, n); err != nil {
			failed = append(failed, n.Name)
			j.Log("%s: %v", n.Name, err)
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("недоступны: %s", strings.Join(failed, ", "))
	}
	return nil
}

func (a *App) jobAgentUpdate(ctx context.Context, j *jobRun) error {
	nodes, err := a.nodes()
	if err != nil {
		return err
	}
	for _, n := range nodes {
		if err := a.ensureAgent(ctx, n, j.progress); err != nil {
			return fmt.Errorf("%s: %w", n.Name, err)
		}
	}
	return nil
}

// refresher keeps node status fresh for the dashboard.
func (a *App) refresher(ctx context.Context) {
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for {
		nodes, _ := a.nodes()
		for _, n := range nodes {
			cctx, cancel := context.WithTimeout(ctx, 40*time.Second)
			fresh, err := a.refreshStatus(cctx, n)
			cancel()
			if ctx.Err() == nil {
				a.observe(ctx, fresh, err)
			}
		}
		a.checkChain(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
