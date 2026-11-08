// Command wdtt-router is both the control panel (serve) and the node agent
// (agent ...). The panel uploads this same binary to every managed server.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Jetvac/wdtt-router/internal/agent"
	"github.com/Jetvac/wdtt-router/internal/auth"
	"github.com/Jetvac/wdtt-router/internal/controller"
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

Agent (run by the panel on every server):
  wdtt-router agent status|apply|confirm|probe|boot|uninstall [--purge]|version
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
	case "init":
		err = initPanel(os.Args[2:])
	case "reset-password":
		err = resetPassword(os.Args[2:])
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
	case "wdtt-post-start":
		agent.WDTTPostStart(ctx)
		return nil
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
