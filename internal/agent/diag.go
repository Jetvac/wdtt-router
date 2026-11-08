package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// Diagnostics collects what is useful to understand a problem with this
// server: versions, service states, recent logs, firewall and routing. It
// never includes the spec or configuration files (they hold keys), and
// values that look like secrets are masked.
func Diagnostics(ctx context.Context) string {
	var b strings.Builder
	section := func(title string, name string, args ...string) {
		cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		out, err := exec.CommandContext(cctx, name, args...).CombinedOutput()
		fmt.Fprintf(&b, "\n===== %s (%s %s)\n", title, name, strings.Join(args, " "))
		if err != nil {
			fmt.Fprintf(&b, "[%v]\n", err)
		}
		b.Write(out)
	}
	st, _ := json.MarshalIndent(Inspect(ctx), "", "  ")
	fmt.Fprintf(&b, "wdtt-router agent %s, collected %s\n\n===== status\n%s\n", Version, time.Now().UTC().Format(time.RFC3339), st)
	section("services", "systemctl", "--no-pager", "--plain", "list-units", "wdtt-router*", "warp-svc*", "x-ui*")
	section("failed units", "systemctl", "--no-pager", "--plain", "--failed")
	section("logs, last hour", "journalctl", "--no-pager", "-o", "short-iso", "--since", "-1h", "-u", "wdtt-router*", "-u", "warp-svc", "-n", "600")
	section("firewall", "nft", "list", "ruleset")
	section("addresses", "ip", "-brief", "address")
	section("routes", "ip", "route")
	section("policy rules", "ip", "rule")
	section("listening sockets", "ss", "-lntup")
	section("Mesh", "warp-cli", "--accept-tos", "status")
	section("disk", "df", "-h", "/")
	section("memory", "free", "-m")
	return Redact(b.String())
}

var secretRe = regexp.MustCompile(`(?i)("?(?:password|passwd|pass|token|secret|private[_ ]?key|privatekey|api[_ ]?key|uuid|decryption|encryption|credential)"?\s*[:=]\s*)("[^"]*"|[^\s,}]+)`)

// Redact masks values that look like secrets.
func Redact(s string) string {
	return secretRe.ReplaceAllString(s, `${1}"[скрыто]"`)
}
