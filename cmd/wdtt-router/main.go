// Command wdtt-router is both the control panel (serve) and the node agent
// (agent ...). The panel uploads this same binary to every managed server.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime/pprof"
	"strings"
	"syscall"
	"time"

	"github.com/Jetvac/wdtt-router/internal/agent"
	"github.com/Jetvac/wdtt-router/internal/auth"
	"github.com/Jetvac/wdtt-router/internal/backup"
	"github.com/Jetvac/wdtt-router/internal/bot"
	"github.com/Jetvac/wdtt-router/internal/controller"
	"github.com/Jetvac/wdtt-router/internal/sshx"
	"github.com/Jetvac/wdtt-router/internal/wdtt"
	"github.com/Jetvac/wdtt-router/web"
)

const defaultData = "/var/lib/wdtt-router/panel"

func usage() {
	fmt.Fprintf(os.Stderr, `wdtt-router %s — VPN chain over Cloudflare Mesh

Panel:
  wdtt-router init  --public-host IP [--port 8443]   create state and the admin user
  wdtt-router serve [--listen :8443]                  run the web panel
  wdtt-router reset-password                          set a new admin password
  wdtt-router fingerprint                             print the panel certificate fingerprint
  wdtt-router desktop-login [--device NAME]           panel session for the Windows app (JSON)

Agent (run by the panel on every server):
  wdtt-router agent status|apply|confirm|probe|boot|uninstall [--purge]|version

WDTT server (run by systemd on the entry server):
  wdtt-router wdtt-server [--config /etc/wdtt-router/wdtt.json]   SIGHUP reloads passwords
  wdtt-router restore [--public-host ADDR] FILE.wbk   restore a backup made in the panel
  wdtt-router ssh-key                     print the panel public SSH key
`, agent.Version)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	var err error
	switch os.Args[1] {
	case "agent":
		err = agentMain(ctx, os.Args[2:])
	case "serve":
		err = serve(ctx, os.Args[2:])
	case "wdtt-server":
		err = wdttServer(ctx, os.Args[2:])
	case "telegram-bot":
		err = telegramBot(ctx, os.Args[2:])
	case "restore":
		err = restore(ctx, os.Args[2:])
	case "ssh-key":
		// The panel's public SSH key, to add to a server by hand.
		var pub string
		if pub, err = sshx.EnsureKey(defaultData + "/ssh_ed25519"); err == nil {
			fmt.Println(pub + " wdtt-router-panel")
		}
	case "init":
		err = initPanel(os.Args[2:])
	case "reset-password":
		err = resetPassword(os.Args[2:])
	case "desktop-login":
		// Run over SSH by the Windows app: a panel session as JSON.
		fl := flag.NewFlagSet("desktop-login", flag.ExitOnError)
		device := fl.String("device", "", "computer name, for the audit log")
		_ = fl.Parse(os.Args[2:])
		a, e := openApp(defaultData, 8443, "")
		if e != nil {
			err = e
			break
		}
		var s controller.DesktopSession
		if s, err = a.DesktopLogin(*device); err == nil {
			err = json.NewEncoder(os.Stdout).Encode(s)
		}
	case "fingerprint":
		a, e := openApp(defaultData, 8443, "")
		if e != nil {
			err = e
			break
		}
		fmt.Println(a.CertFingerprint())
	case "version", "--version":
		fmt.Println(agent.Version)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		// One line, so the panel can show it as the job error.
		fmt.Fprintln(os.Stderr, "error: "+strings.Join(strings.Fields(err.Error()), " "))
		os.Exit(1)
	}
}

func ui() fs.FS {
	sub, err := fs.Sub(web.Dist, "dist")
	if err != nil {
		panic(err)
	}
	return sub
}

func openApp(data string, port int, host string) (*controller.App, error) {
	if host == "" {
		if b, err := os.ReadFile(data + "/public_host"); err == nil {
			host = strings.TrimSpace(string(b))
		}
	}
	return controller.Open(data, port, host, ui())
}

func wdttServer(ctx context.Context, args []string) error {
	fl := flag.NewFlagSet("wdtt-server", flag.ExitOnError)
	cfg := fl.String("config", agent.WDTTConfigPath, "configuration file")
	_ = fl.Parse(args)
	s := wdtt.NewServer(*cfg, wdtt.NewLinuxPeers)
	s.Version = agent.Version
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			if err := s.Reload(); err != nil {
				fmt.Fprintln(os.Stderr, "reload failed:", err)
			}
		}
	}()
	// SIGUSR1 records a 20 s CPU profile next to the status file, for
	// performance work on a live server.
	usr1 := make(chan os.Signal, 1)
	signal.Notify(usr1, syscall.SIGUSR1)
	go func() {
		for range usr1 {
			path := filepath.Join(filepath.Dir(agent.WDTTStatusPath), "wdtt-cpu.pprof")
			f, err := os.Create(path)
			if err != nil {
				fmt.Fprintln(os.Stderr, "profile:", err)
				continue
			}
			if err := pprof.StartCPUProfile(f); err != nil {
				f.Close()
				fmt.Fprintln(os.Stderr, "profile:", err)
				continue
			}
			time.Sleep(20 * time.Second)
			pprof.StopCPUProfile()
			f.Close()
			fmt.Fprintln(os.Stderr, "CPU profile written to", path)
		}
	}()
	return s.Run(ctx)
}

func telegramBot(ctx context.Context, args []string) error {
	fl := flag.NewFlagSet("telegram-bot", flag.ExitOnError)
	cfg := fl.String("config", "/etc/wdtt-router/bot.json", "configuration file")
	_ = fl.Parse(args)
	c, err := bot.LoadConfig(*cfg)
	if err != nil {
		return err
	}
	return bot.New(c).Run(ctx)
}

// restore puts a backup made in the panel back into place: on the same
// server, or on a new one after "install.sh install".
func restore(ctx context.Context, args []string) error {
	fl := flag.NewFlagSet("restore", flag.ExitOnError)
	data := fl.String("data", defaultData, "panel state directory")
	host := fl.String("public-host", "", "public address of this server, if it differs from the backed-up one")
	_ = fl.Parse(args)
	if fl.NArg() != 1 {
		return fmt.Errorf("usage: wdtt-router restore [--public-host ADDR] FILE.wbk")
	}
	raw, err := os.ReadFile(fl.Arg(0))
	if err != nil {
		return err
	}
	pass := os.Getenv("WDTT_ROUTER_BACKUP_PASSPHRASE")
	if pass == "" {
		fmt.Fprint(os.Stderr, "Пароль резервной копии: ")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		pass = strings.TrimRight(line, "\r\n")
	}
	entries, err := backup.Open(raw, pass)
	if err != nil {
		return err
	}
	for _, unit := range []string{"wdtt-router", "wdtt-router-wdtt"} {
		_ = exec.CommandContext(ctx, "systemctl", "stop", unit).Run()
	}
	if err := backup.Restore(entries, *data, agent.WDTTDataDir); err != nil {
		return err
	}
	if *host != "" {
		if err := os.WriteFile(*data+"/public_host", []byte(*host+"\n"), 0600); err != nil {
			return err
		}
		// The certificate names the old address; a new one is made at start.
		_ = os.Rename(*data+"/panel.crt", *data+"/panel.crt.before-restore")
		_ = os.Rename(*data+"/panel.key", *data+"/panel.key.before-restore")
	}
	if err := exec.CommandContext(ctx, "systemctl", "start", "wdtt-router").Run(); err != nil {
		return fmt.Errorf("start the panel: %w", err)
	}
	// The WDTT server, if this server runs one, with the restored keys.
	if exec.CommandContext(ctx, "systemctl", "is-enabled", "--quiet", "wdtt-router-wdtt").Run() == nil {
		_ = exec.CommandContext(ctx, "systemctl", "start", "wdtt-router-wdtt").Run()
	}
	fmt.Printf("Восстановлено файлов: %d. Панель запущена.\nОткройте её и нажмите «Применить ко всем серверам», чтобы вернуть серверы к сохранённому состоянию.\n", len(entries))
	return nil
}

func initPanel(args []string) error {
	f := flag.NewFlagSet("init", flag.ExitOnError)
	host := f.String("public-host", "", "public IPv4 or DNS name of this server")
	port := f.Int("port", 8443, "panel HTTPS port")
	data := f.String("data", defaultData, "state directory")
	_ = f.Parse(args)
	if *host == "" {
		return fmt.Errorf("--public-host is required")
	}
	if err := os.MkdirAll(*data, 0700); err != nil {
		return err
	}
	if err := os.WriteFile(*data+"/public_host", []byte(*host+"\n"), 0600); err != nil {
		return err
	}
	a, err := openApp(*data, *port, *host)
	if err != nil {
		return err
	}
	user, pass, err := a.Init(*host)
	if err != nil {
		return err
	}
	fmt.Printf("Panel:        https://%s:%d/\n", *host, *port)
	fmt.Printf("Certificate:  %s\n", a.CertFingerprint())
	if pass != "" {
		fmt.Printf("Login:        %s\nPassword:     %s\n(The password is shown only once.)\n", user, pass)
	}
	return nil
}

func serve(ctx context.Context, args []string) error {
	f := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := f.String("listen", ":8443", "listen address")
	data := f.String("data", defaultData, "state directory")
	_ = f.Parse(args)
	port := 8443
	if i := strings.LastIndex(*listen, ":"); i >= 0 {
		fmt.Sscanf((*listen)[i+1:], "%d", &port)
	}
	a, err := openApp(*data, port, "")
	if err != nil {
		return err
	}
	if _, _, err := a.Init(""); err != nil {
		return err
	}
	return a.Serve(ctx, *listen)
}

func resetPassword(args []string) error {
	a, err := openApp(defaultData, 8443, "")
	if err != nil {
		return err
	}
	pass, err := auth.Random(24)
	if err != nil {
		return err
	}
	hash, err := auth.HashPassword(pass)
	if err != nil {
		return err
	}
	res, err := a.Store.DB.Exec(`UPDATE users SET password_hash=? WHERE username='admin'`, hash)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("user admin not found")
	}
	_, _ = a.Store.DB.Exec(`DELETE FROM sessions`)
	fmt.Printf("Login: admin\nPassword: %s\n", pass)
	return nil
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func agentMain(ctx context.Context, args []string) error {
	if len(args) == 0 {
		usage()
		return fmt.Errorf("agent command required")
	}
	if os.Geteuid() != 0 && args[0] != "version" {
		return fmt.Errorf("the agent must run as root")
	}
	// On the panel server the agent is a child of the panel service
	// (UMask=0077); elsewhere it runs over SSH with 022. Files the agent
	// installs for other programs (apt keyrings, package files) must be
	// readable as on any other server; secrets are written with explicit
	// 0600 modes regardless.
	syscall.Umask(0o022)
	switch args[0] {
	case "version":
		fmt.Println(agent.Version)
		return nil
	case "status":
		return printJSON(agent.Inspect(ctx))
	case "apply":
		b, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
		if err != nil {
			return err
		}
		s, err := agent.DecodeSpec(b)
		if err != nil {
			return err
		}
		res, err := agent.Apply(ctx, s)
		_ = printJSON(res)
		return err
	case "confirm":
		return agent.Confirm(ctx)
	case "diag":
		fmt.Print(agent.Diagnostics(ctx))
		return nil
	case "boot":
		return agent.Boot(ctx)
	case "maintain":
		return agent.Maintain(ctx)
	case "tproxy-routes":
		return agent.TProxyRoutes(ctx)
	case "probe":
		pctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		return printJSON(agent.Probe(pctx))
	case "xui-reset":
		b, _ := io.ReadAll(io.LimitReader(os.Stdin, 4096))
		parts := strings.Split(strings.TrimSpace(string(b)), "\n")
		if len(parts) != 2 {
			return fmt.Errorf("expected login and password on stdin")
		}
		creds, err := agent.ResetXUICredentials(ctx, parts[0], parts[1])
		if err != nil {
			return err
		}
		return printJSON(creds)
	case "uninstall":
		purge := len(args) > 1 && args[1] == "--purge"
		changed, err := agent.Uninstall(ctx, purge)
		for _, c := range changed {
			agent.Logf("%s", c)
		}
		return err
	}
	return fmt.Errorf("unknown agent command %q", args[0])
}
