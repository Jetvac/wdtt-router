package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Jetvac/wdtt-router/internal/controller"
	"github.com/Jetvac/wdtt-router/internal/node"
)

var version = "dev"

func main() {
	syscall.Umask(0077)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: wdtt-panel [init|serve|status|selftest|node|version]")
	}
	switch args[0] {
	case "version":
		fmt.Println(version)
		return nil
	case "init":
		flags := flag.NewFlagSet("init", flag.ContinueOnError)
		dataDir := flags.String("data-dir", "/var/lib/wdtt-panel", "private panel data directory")
		publicHost := flags.String("public-host", "", "public IP address or hostname of this server")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		user, password, err := controller.Initialize(*dataDir, *publicHost)
		if err != nil {
			return err
		}
		fmt.Printf("Initial user: %s\nInitial password: %s\n", user, password)
		return nil
	case "serve":
		flags := flag.NewFlagSet("serve", flag.ContinueOnError)
		dataDir := flags.String("data-dir", "/var/lib/wdtt-panel", "private panel data directory")
		listen := flags.String("listen", ":8443", "HTTPS listen address")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		app, err := controller.New(*dataDir, os.Args[0])
		if err != nil {
			return err
		}
		app.Version = version
		defer app.Close()
		return app.Serve(ctx, *listen)
	case "status":
		return printJSON(node.Inspect(ctx))
	case "selftest":
		r := node.Selftest(ctx)
		if err := printJSON(r); err != nil {
			return err
		}
		if !r.Passed {
			return fmt.Errorf("selftest failed")
		}
		return nil
	case "node":
		return nodeCLI(ctx, args[1:])
	default:
		return fmt.Errorf("unknown command: %s", args[0])
	}
}

func nodeCLI(ctx context.Context, args []string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("node operations require root")
	}
	if len(args) == 0 {
		return fmt.Errorf("node subcommand required")
	}
	switch args[0] {
	case "status":
		return printJSON(node.Inspect(ctx))
	case "selftest":
		return printJSON(node.Selftest(ctx))
	case "apply":
		b, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
		if err != nil {
			return err
		}
		var req node.Request
		if err := json.Unmarshal(b, &req); err != nil {
			return err
		}
		longCtx, cancel := context.WithTimeout(ctx, 20*time.Minute)
		defer cancel()
		result, err := node.Apply(longCtx, req)
		if err != nil {
			return err
		}
		return printJSON(result)
	case "commit":
		if len(args) != 2 {
			return fmt.Errorf("recovery ID required")
		}
		return node.CommitRecovery(ctx, args[1])
	case "recover":
		if len(args) != 2 {
			return fmt.Errorf("recovery ID required")
		}
		return node.Recover(ctx, args[1])
	case "restore-routing":
		return node.RestoreRouting(ctx)
	case "restore-firewall":
		return node.RestoreFirewall(ctx)
	case "route-keeper":
		return node.RouteKeeper(ctx)
	case "vless-relay":
		return node.VLESSRelay(ctx)
	case "wait-mesh-bridge":
		return node.WaitMeshBridge(ctx)
	case "restore-vless-client":
		return node.RestoreVLESSClient(ctx)
	case "probe-traffic":
		result, err := node.ProbeTraffic(ctx)
		if err != nil {
			return err
		}
		return printJSON(result)
	case "probe-vless-client":
		probe, err := node.ProbeVLESSClientTraffic(ctx)
		if err != nil {
			return err
		}
		fmt.Printf("transparent TCP and UDP probe passed; egress IP: %s\n", probe.IP)
		return nil
	case "probe-vless-client-json":
		probe, err := node.ProbeVLESSClientTraffic(ctx)
		if err != nil {
			return err
		}
		return printJSON(probe)
	default:
		return fmt.Errorf("unknown node subcommand: %s", args[0])
	}
}

func printJSON(v any) error { return json.NewEncoder(os.Stdout).Encode(v) }
