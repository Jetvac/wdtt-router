package desktop

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// op is a background operation whose log the launcher shows as it goes.
type op struct {
	mu     sync.Mutex
	log    []string
	done   bool
	err    string
	result any
}

func (o *op) Log(format string, args ...any) {
	o.mu.Lock()
	o.log = append(o.log, fmt.Sprintf(format, args...))
	if len(o.log) > 2000 {
		o.log = o.log[len(o.log)-2000:]
	}
	o.mu.Unlock()
}

func (o *op) view() map[string]any {
	o.mu.Lock()
	defer o.mu.Unlock()
	return map[string]any{"done": o.done, "error": o.err, "result": o.result, "log": append([]string(nil), o.log...)}
}

func (a *App) startOp(f func(context.Context, *op) (any, error)) string {
	id := randomHex(8)
	o := &op{}
	a.mu.Lock()
	a.ops[id] = o
	a.mu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
		defer cancel()
		res, err := f(ctx, o)
		o.mu.Lock()
		o.done, o.result = true, res
		if err != nil {
			o.err = err.Error()
		}
		o.mu.Unlock()
		// Forget finished operations after a while.
		time.AfterFunc(30*time.Minute, func() {
			a.mu.Lock()
			delete(a.ops, id)
			a.mu.Unlock()
		})
	}()
	return id
}

// Server states the launcher understands.
const (
	stateReady       = "ready"       // the panel runs and supports the app
	stateOld         = "old_panel"   // the panel needs an update first
	stateStopped     = "stopped"     // the panel is installed but not running
	stateNoPanel     = "no_panel"    // nothing installed: offer to install
	stateAgentOnly   = "agent_only"  // a server managed by a panel elsewhere
	stateUnsupported = "unsupported" // not Debian or Ubuntu
	stateNeedLogin   = "need_login"  // the server does not know the app's key yet
)

type checkResult struct {
	ServerID string `json:"server_id"`
	State    string `json:"state"`
	Version  string `json:"version,omitempty"`
	OS       string `json:"os,omitempty"`
	Login    string `json:"login,omitempty"`    // after an install: the browser login
	Password string `json:"password,omitempty"` // after an install, shown once
}

const detectScript = `echo "uid=$(id -u)"
. /etc/os-release 2>/dev/null; echo "os=${PRETTY_NAME:-$ID}"; echo "osid=${ID:-} ${ID_LIKE:-}"
if command -v wdtt-router >/dev/null 2>&1; then
  echo "version=$(wdtt-router version 2>/dev/null)"
  wdtt-router desktop-login -h >/dev/null 2>&1 && echo "desktop=1"
fi
[ -f /etc/systemd/system/wdtt-router.service ] && echo "unit=1" && echo "active=$(systemctl is-active wdtt-router 2>/dev/null)"
true`

// detect looks at what is installed on the server.
func detect(ctx context.Context, cl *ssh.Client) (checkResult, error) {
	out, err := run(ctx, cl, detectScript)
	if err != nil {
		return checkResult{}, fmt.Errorf("проверка сервера: %w", err)
	}
	kv := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(l), "="); ok {
			kv[k] = v
		}
	}
	r := checkResult{Version: kv["version"], OS: kv["os"]}
	if kv["uid"] != "0" {
		return r, errors.New("нужен вход под пользователем root: приложение устанавливает и обслуживает панель от его имени")
	}
	switch {
	case kv["unit"] == "1" && kv["active"] != "active":
		r.State = stateStopped
	case kv["unit"] == "1" && kv["desktop"] == "1":
		r.State = stateReady
	case kv["unit"] == "1":
		r.State = stateOld
	case kv["version"] != "":
		r.State = stateAgentOnly
	case !strings.Contains(" "+kv["osid"]+" ", " debian ") && !strings.Contains(" "+kv["osid"]+" ", " ubuntu "):
		r.State = stateUnsupported
	default:
		r.State = stateNoPanel
	}
	return r, nil
}

// addServer adds a server to the list: it connects (with the app's key or
// the one-time login), puts the app's key on the server and checks that the
// key alone works, then reports what is installed.
func (a *App) addServer(ctx context.Context, o *op, srv Server, login *Login) (any, error) {
	for _, s := range a.store.List() {
		if s.Host == srv.Host && s.Port == srv.Port {
			srv.ID, srv.HostKey, srv.Added = s.ID, s.HostKey, s.Added
			if srv.Name == srv.Host && s.Name != "" {
				srv.Name = s.Name
			}
		}
	}
	if srv.ID == "" {
		srv.ID = randomHex(6)
	}
	o.Log("Подключаюсь к %s:%d…", srv.Host, srv.Port)
	cl, hostKey, err := dial(ctx, srv, a.store.Signer(), login)
	if errors.Is(err, errAuth) {
		o.Log("Сервер ещё не знает ключ приложения — нужен пароль root (один раз)")
		return checkResult{State: stateNeedLogin}, nil
	}
	if err != nil {
		return nil, err
	}
	defer cl.Close()
	if pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(hostKey)); err == nil {
		o.Log("Подключено. Отпечаток ключа сервера: %s", ssh.FingerprintSHA256(pk))
	}
	srv.HostKey = hostKey
	res, err := detect(ctx, cl)
	if err != nil {
		return nil, err
	}
	o.Log("Система: %s", res.OS)
	if login != nil {
		o.Log("Добавляю ключ приложения на сервер")
		pub := a.store.PublicKey(a.device)
		b64 := strings.Fields(pub)[1]
		cmd := fmt.Sprintf(`umask 077; mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys && (grep -qF %s ~/.ssh/authorized_keys || echo %s >> ~/.ssh/authorized_keys)`, shellQuote(b64), shellQuote(pub))
		if _, err := run(ctx, cl, cmd); err != nil {
			return nil, fmt.Errorf("не удалось добавить ключ: %w", err)
		}
		check, _, err := dial(ctx, srv, a.store.Signer(), nil)
		if err != nil {
			return nil, fmt.Errorf("ключ добавлен, но вход по нему не работает (%v). Проверьте, что в sshd разрешён вход по ключу (PubkeyAuthentication)", err)
		}
		check.Close()
		o.Log("Вход по ключу работает. Пароль больше не нужен и не сохранён")
	}
	if srv.Added == "" {
		srv.Added = time.Now().UTC().Format(time.RFC3339)
	}
	saved, err := a.store.Update(srv.ID, func(s *Server) {
		lastUsed, lastEvent := s.LastUsed, s.LastEvent
		*s = srv
		s.LastUsed, s.LastEvent, s.Version = lastUsed, lastEvent, res.Version
	})
	if err != nil {
		return nil, err
	}
	res.ServerID = saved.ID
	logState(o, res)
	return res, nil
}

func logState(o *op, r checkResult) {
	switch r.State {
	case stateReady:
		o.Log("Панель %s работает — можно подключаться", r.Version)
	case stateOld:
		o.Log("Панель %s нужно обновить: эта версия не поддерживает приложение", r.Version)
	case stateStopped:
		o.Log("Панель установлена, но не запущена")
	case stateNoPanel:
		o.Log("Панель на сервере не установлена")
	case stateAgentOnly:
		o.Log("На сервере только агент: им управляет панель на другом сервере")
	case stateUnsupported:
		o.Log("Система не поддерживается: нужен Debian или Ubuntu")
	}
}

const installerURL = "https://github.com/Jetvac/wdtt-router/releases/latest/download/install.sh"

// serverOp installs, updates or restarts the panel on a saved server, or
// just checks it again.
func (a *App) serverOp(ctx context.Context, o *op, srv Server, action, publicHost string) (any, error) {
	o.Log("Подключаюсь к %s…", srv.Name)
	cl, _, err := dial(ctx, srv, a.store.Signer(), nil)
	if err != nil {
		return nil, err
	}
	defer cl.Close()
	var res checkResult
	switch action {
	case "install", "update":
		args := "update"
		if action == "install" {
			if publicHost = strings.TrimSpace(publicHost); publicHost == "" {
				publicHost = srv.Host
			}
			if _, err := cleanServer(publicHost, 0, "", ""); err != nil {
				return nil, errors.New("некорректный публичный адрес")
			}
			args = "install --public-host " + shellQuote(publicHost)
			// The panel and the app use the same certificate check; nothing to
			// remember here, the app reads the fingerprint over SSH.
		}
		o.Log("Загружаю установщик с GitHub (релиз подписан, установщик проверяет подпись)")
		script := `set -e
export DEBIAN_FRONTEND=noninteractive
command -v curl >/dev/null 2>&1 || { apt-get update -qq && apt-get install -y -qq curl ca-certificates; }
f=$(mktemp)
trap 'rm -f "$f"' EXIT
curl -fsSL --retry 3 -o "$f" ` + shellQuote(installerURL) + `
bash "$f" ` + args
		err = stream(ctx, cl, script, func(line string) {
			switch {
			case strings.HasPrefix(line, "Password:"):
				res.Password = strings.TrimSpace(strings.TrimPrefix(line, "Password:"))
				o.Log("Password:     (показан ниже, один раз)")
			case strings.HasPrefix(line, "Login:"):
				res.Login = strings.TrimSpace(strings.TrimPrefix(line, "Login:"))
				o.Log("%s", line)
			default:
				o.Log("%s", line)
			}
		})
		if err != nil {
			return res, fmt.Errorf("установщик завершился с ошибкой — подробности в журнале выше")
		}
	case "restart":
		o.Log("Перезапускаю панель")
		if out, err := run(ctx, cl, "systemctl restart wdtt-router && sleep 3 && systemctl is-active wdtt-router"); err != nil {
			o.Log("%s", strings.TrimSpace(out))
			jr, _ := run(ctx, cl, "journalctl -u wdtt-router -n 15 --no-pager")
			for _, l := range strings.Split(strings.TrimSpace(jr), "\n") {
				o.Log("%s", l)
			}
			return nil, errors.New("панель не запустилась — журнал выше")
		}
	}
	d, err := detect(ctx, cl)
	if err != nil {
		return nil, err
	}
	res.State, res.Version, res.OS, res.ServerID = d.State, d.Version, d.OS, srv.ID
	_, _ = a.store.Update(srv.ID, func(s *Server) { s.Version = d.Version })
	logState(o, res)
	return res, nil
}

func itoa(n int) string { return strconv.Itoa(n) }

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
