package controller

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Job is one queued operation. All operations that change servers run on a
// single worker, so concurrent or repeated clicks can never interleave.
type Job struct {
	ID         int64  `json:"id"`
	Kind       string `json:"kind"`
	NodeID     int64  `json:"node_id"`
	Title      string `json:"title"`
	Status     string `json:"status"`
	Log        string `json:"log,omitempty"`
	Error      string `json:"error"`
	CreatedBy  string `json:"created_by"`
	CreatedAt  string `json:"created_at"`
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at"`
}

type jobFunc func(ctx context.Context, j *jobRun) error

type jobRun struct {
	a  *App
	id int64
	mu sync.Mutex
}

func (j *jobRun) Log(format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	line = strings.TrimPrefix(line, "• ")
	if strings.TrimSpace(line) == "" {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	ts := time.Now().UTC().Format("15:04:05")
	_, _ = j.a.Store.DB.Exec(`UPDATE jobs SET log = substr(log || ?, -65536) WHERE id=?`, ts+"  "+line+"\n", j.id)
}

func (j *jobRun) progress(line string) { j.Log("%s", line) }

// Enqueue adds a job unless an identical one is already waiting.
func (a *App) Enqueue(kind string, nodeID int64, title, user string, input any) (int64, error) {
	var existing int64
	err := a.Store.DB.QueryRow(`SELECT id FROM jobs WHERE kind=? AND node_id=? AND status='queued'`, kind, nodeID).Scan(&existing)
	if err == nil && input == nil {
		return existing, nil
	}
	cipher := ""
	if input != nil {
		b, _ := json.Marshal(input)
		if cipher, err = a.Store.Seal(string(b)); err != nil {
			return 0, err
		}
	}
	res, err := a.Store.DB.Exec(`INSERT INTO jobs(kind,node_id,title,status,input_cipher,created_by,created_at) VALUES(?,?,?,'queued',?,?,?)`, kind, nodeID, title, cipher, user, now())
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	select {
	case a.wake <- struct{}{}:
	default:
	}
	return id, nil
}

func (a *App) jobInput(id int64, v any) error {
	var c string
	if err := a.Store.DB.QueryRow(`SELECT input_cipher FROM jobs WHERE id=?`, id).Scan(&c); err != nil {
		return err
	}
	if c == "" {
		return errors.New("job has no input")
	}
	p, err := a.Store.OpenSecret(c)
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(p), v)
}

// worker runs queued jobs one at a time.
func (a *App) worker(ctx context.Context) {
	// Jobs that were running when the panel stopped did not finish.
	_, _ = a.Store.DB.Exec(`UPDATE jobs SET status='failed', error='Панель была перезапущена во время выполнения', finished_at=? WHERE status='running'`, now())
	for {
		var id, nodeID int64
		var kind string
		err := a.Store.DB.QueryRow(`SELECT id,kind,node_id FROM jobs WHERE status='queued' ORDER BY id LIMIT 1`).Scan(&id, &kind, &nodeID)
		if errors.Is(err, sql.ErrNoRows) {
			select {
			case <-ctx.Done():
				return
			case <-a.wake:
			case <-time.After(5 * time.Second):
			}
			continue
		}
		if err != nil {
			time.Sleep(time.Second)
			continue
		}
		a.runJob(ctx, id, kind, nodeID)
	}
}

func (a *App) runJob(ctx context.Context, id int64, kind string, nodeID int64) {
	_, _ = a.Store.DB.Exec(`UPDATE jobs SET status='running', started_at=? WHERE id=?`, now(), id)
	j := &jobRun{a: a, id: id}
	fn, ok := a.handlers()[kind]
	var err error
	if !ok {
		err = fmt.Errorf("unknown job kind %s", kind)
	} else {
		jctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
		func() {
			defer func() {
				if r := recover(); r != nil {
					err = fmt.Errorf("внутренняя ошибка: %v", r)
				}
			}()
			err = fn(context.WithValue(jctx, nodeKey{}, nodeID), j)
		}()
		cancel()
	}
	status, msg := "success", ""
	if err != nil {
		status, msg = "failed", err.Error()
		j.Log("ОШИБКА: %s", msg)
		var title string
		_ = a.Store.DB.QueryRow(`SELECT title FROM jobs WHERE id=?`, id).Scan(&title)
		a.event(EventJobs, "❗ Задача «%s» завершилась с ошибкой: %s", title, short(msg, 300))
	} else {
		j.Log("Готово")
	}
	// Input may hold passwords; drop it once the job is done.
	_, _ = a.Store.DB.Exec(`UPDATE jobs SET status=?, error=?, finished_at=?, input_cipher='' WHERE id=?`, status, msg, now(), id)
}

type nodeKey struct{}

func jobNode(ctx context.Context) int64 {
	v, _ := ctx.Value(nodeKey{}).(int64)
	return v
}

func (a *App) jobs(limit int) ([]Job, error) {
	rows, err := a.Store.DB.Query(`SELECT id,kind,node_id,title,status,error,created_by,created_at,started_at,finished_at FROM jobs ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Job{}
	for rows.Next() {
		var j Job
		if err := rows.Scan(&j.ID, &j.Kind, &j.NodeID, &j.Title, &j.Status, &j.Error, &j.CreatedBy, &j.CreatedAt, &j.StartedAt, &j.FinishedAt); err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, nil
}

func (a *App) job(id int64) (Job, error) {
	var j Job
	err := a.Store.DB.QueryRow(`SELECT id,kind,node_id,title,status,log,error,created_by,created_at,started_at,finished_at FROM jobs WHERE id=?`, id).
		Scan(&j.ID, &j.Kind, &j.NodeID, &j.Title, &j.Status, &j.Log, &j.Error, &j.CreatedBy, &j.CreatedAt, &j.StartedAt, &j.FinishedAt)
	return j, err
}

func specHashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}
