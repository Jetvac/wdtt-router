package controller

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/Jetvac/wdtt-router/internal/agent"
	"github.com/Jetvac/wdtt-router/internal/spec"
	"github.com/Jetvac/wdtt-router/internal/sshx"
)

// Node is a managed server.
type Node struct {
	ID          int64       `json:"id"`
	Name        string      `json:"name"`
	Host        string      `json:"host"`
	SSHPort     int         `json:"ssh_port"`
	Fingerprint string      `json:"fingerprint"`
	Local       bool        `json:"local"`
	MeshIP      string      `json:"mesh_ip"`
	CFNodeID    string      `json:"cf_node_id"`
	CFNodeName  string      `json:"cf_node_name"`
	HopPort     int         `json:"hop_port"`
	SSHPublic   bool        `json:"ssh_public"`
	SSHAllow    []string    `json:"ssh_allow"`
	AllowPing   bool        `json:"allow_ping"`
	Firewall    bool        `json:"firewall"`
	Status      spec.Status `json:"status"`
	LastSeen    string      `json:"last_seen"`
	LastError   string      `json:"last_error"`
	CreatedAt   string      `json:"created_at"`
}

const nodeCols = `id,name,host,ssh_port,fingerprint,local,mesh_ip,cf_node_id,cf_node_name,hop_port,ssh_public,ssh_allow,allow_ping,firewall,status_json,last_seen,last_error,created_at`

func scanNode(r interface{ Scan(...any) error }) (Node, error) {
	var n Node
	var local, pub, ping, fw int
	var allow, status string
	err := r.Scan(&n.ID, &n.Name, &n.Host, &n.SSHPort, &n.Fingerprint, &local, &n.MeshIP, &n.CFNodeID, &n.CFNodeName, &n.HopPort, &pub, &allow, &ping, &fw, &status, &n.LastSeen, &n.LastError, &n.CreatedAt)
	if err != nil {
		return n, err
	}
	n.Local, n.SSHPublic, n.AllowPing, n.Firewall = local == 1, pub == 1, ping == 1, fw == 1
	n.SSHAllow = []string{}
	for _, a := range strings.Split(allow, ",") {
		if a = strings.TrimSpace(a); a != "" {
			n.SSHAllow = append(n.SSHAllow, a)
		}
	}
	_ = json.Unmarshal([]byte(status), &n.Status)
	return n, nil
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (a *App) nodes() ([]Node, error) {
	rows, err := a.Store.DB.Query(`SELECT ` + nodeCols + ` FROM nodes ORDER BY local DESC, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Node{}
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (a *App) node(id int64) (Node, error) {
	n, err := scanNode(a.Store.DB.QueryRow(`SELECT `+nodeCols+` FROM nodes WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return n, errors.New("сервер не найден")
	}
	return n, err
}

func (a *App) saveNode(n Node) error {
	st, _ := json.Marshal(n.Status)
	_, err := a.Store.DB.Exec(`UPDATE nodes SET name=?,host=?,ssh_port=?,fingerprint=?,mesh_ip=?,cf_node_id=?,cf_node_name=?,hop_port=?,ssh_public=?,ssh_allow=?,allow_ping=?,firewall=?,status_json=?,last_seen=?,last_error=? WHERE id=?`,
		n.Name, n.Host, n.SSHPort, n.Fingerprint, n.MeshIP, n.CFNodeID, n.CFNodeName, n.HopPort, b2i(n.SSHPublic), strings.Join(n.SSHAllow, ","), b2i(n.AllowPing), b2i(n.Firewall), string(st), n.LastSeen, n.LastError, n.ID)
	return err
}

// saveObserved stores only what was observed on the server, so it never
// overwrites settings a user changed in the meantime.
func (a *App) saveObserved(n Node) error {
	st, _ := json.Marshal(n.Status)
	_, err := a.Store.DB.Exec(`UPDATE nodes SET status_json=?, last_seen=?, last_error=?, mesh_ip=? WHERE id=?`, string(st), n.LastSeen, n.LastError, n.MeshIP, n.ID)
	return err
}

func (a *App) localNode() (Node, error) {
	return scanNode(a.Store.DB.QueryRow(`SELECT ` + nodeCols + ` FROM nodes WHERE local=1`))
}

// targets lists the addresses to reach a node, Mesh first. Downstream nodes
// are managed through Mesh so their public SSH can stay closed.
func (a *App) targets(n Node) []sshx.Target {
	t := []sshx.Target{}
	if n.MeshIP != "" {
		t = append(t, sshx.Target{Host: n.MeshIP, Port: n.SSHPort, User: "root", Fingerprint: n.Fingerprint})
	}
	t = append(t, sshx.Target{Host: n.Host, Port: n.SSHPort, User: "root", Fingerprint: n.Fingerprint})
	return t
}

// agentCall runs "wdtt-router agent <args>" on the node.
func (a *App) agentCall(ctx context.Context, n Node, input []byte, progress func(string), args ...string) ([]byte, error) {
	if n.Local {
		self, err := os.Executable()
		if err != nil {
			return nil, err
		}
		c := exec.CommandContext(ctx, self, append([]string{"agent"}, args...)...)
		if input != nil {
			c.Stdin = bytes.NewReader(input)
		}
		var out bytes.Buffer
		c.Stdout = &out
		stderr, err := c.StderrPipe()
		if err != nil {
			return nil, err
		}
		if err := c.Start(); err != nil {
			return nil, err
		}
		var errBuf strings.Builder
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			if errBuf.Len() < 64<<10 {
				errBuf.WriteString(sc.Text() + "\n")
			}
			if progress != nil {
				progress(sc.Text())
			}
		}
		_, _ = io.Copy(io.Discard, stderr)
		if err := c.Wait(); err != nil {
			return out.Bytes(), errors.New(lastLines(errBuf.String(), err))
		}
		return out.Bytes(), nil
	}
	var lastErr error
	for i, t := range a.targets(n) {
		cctx, cancel := context.WithTimeout(ctx, 12*time.Second)
		_, err := a.SSH.Probe(cctx, t)
		cancel()
		if err != nil {
			lastErr = err
			if i == 0 && n.MeshIP != "" && progress != nil {
				progress(fmt.Sprintf("Mesh-адрес %s недоступен, пробую публичный адрес", n.MeshIP))
			}
			continue
		}
		out, err := a.SSH.Run(ctx, t, agent.SelfPath+" agent "+strings.Join(args, " "), input, progress)
		if err != nil {
			var re *sshx.RemoteError
			if errors.As(err, &re) {
				return out, errors.New(lastLines(re.Stderr, re.Err))
			}
		}
		return out, err
	}
	return nil, fmt.Errorf("сервер %s недоступен по SSH: %v", n.Name, lastErr)
}

func lastLines(s string, err error) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		l := strings.TrimSpace(lines[i])
		if strings.HasPrefix(l, "error: ") {
			return strings.TrimPrefix(l, "error: ")
		}
	}
	if len(lines) > 0 && lines[len(lines)-1] != "" {
		return lines[len(lines)-1]
	}
	return err.Error()
}

// ensureAgent uploads the controller's own binary when the node runs a
// different version.
func (a *App) ensureAgent(ctx context.Context, n Node, log func(string)) error {
	if n.Local {
		return nil
	}
	out, err := a.agentCall(ctx, n, nil, nil, "version")
	if err == nil && strings.TrimSpace(string(out)) == agent.Version {
		return nil
	}
	log("Устанавливаю агент " + agent.Version + " на " + n.Name)
	self, err := os.Executable()
	if err != nil {
		return err
	}
	bin, err := os.ReadFile(self)
	if err != nil {
		return err
	}
	var last error
	for _, t := range a.targets(n) {
		if last = a.SSH.Upload(ctx, t, agent.SelfPath, "0755", bin); last == nil {
			return nil
		}
	}
	return fmt.Errorf("не удалось установить агент: %w", last)
}

func (a *App) refreshStatus(ctx context.Context, n Node) (Node, error) {
	out, err := a.agentCall(ctx, n, nil, nil, "status")
	if err != nil {
		_, _ = a.Store.DB.Exec(`UPDATE nodes SET last_error=? WHERE id=?`, err.Error(), n.ID)
		return n, err
	}
	var st spec.Status
	if err := json.Unmarshal(out, &st); err != nil {
		return n, fmt.Errorf("агент вернул некорректный ответ: %w", err)
	}
	b, _ := json.Marshal(st)
	// Only status columns: a concurrent job may be changing the rest.
	_, err = a.Store.DB.Exec(`UPDATE nodes SET status_json=?, last_seen=?, last_error='', mesh_ip=CASE WHEN ?<>'' AND cf_node_id<>'' THEN ? ELSE mesh_ip END WHERE id=?`, string(b), now(), st.MeshIP, st.MeshIP, n.ID)
	if err != nil {
		return n, err
	}
	return a.node(n.ID)
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }
