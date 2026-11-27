package agent

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Hosts with ufw or Docker drop forwarded packets by default: the FORWARD
// chain of iptables has policy DROP. In nftables a drop in any chain of a
// hook is final, so the exit's own accept (table wdtt_router_link) cannot
// let the tunnel's traffic through on such a host; it takes an accept in
// that chain as well. The filtering (no private ranges, no port 25) stays
// in nftables, which runs first. Nothing is added where FORWARD passes.

const linkFwdComment = "wdtt-router-link"

// iptablesFronts are the iptables commands whose FORWARD chain is in use:
// the nftables one when its table exists, the legacy one when its tables
// are loaded. Neither is listed otherwise: that would create the table or
// load the legacy modules.
func iptablesFronts(ctx context.Context) []string {
	var fronts []string
	nftBacked := func(p string) bool {
		out, _ := output(ctx, p, "-V")
		return strings.Contains(out, "nf_tables")
	}
	if run(ctx, "nft", "list", "chain", "ip", "filter", "FORWARD") == nil {
		for _, c := range []string{"iptables-nft", "iptables"} {
			if p, err := exec.LookPath(c); err == nil && nftBacked(p) {
				fronts = append(fronts, p)
				break
			}
		}
	}
	if b, _ := os.ReadFile("/proc/net/ip_tables_names"); strings.Contains(string(b), "filter") {
		for _, c := range []string{"iptables-legacy", "iptables"} {
			if p, err := exec.LookPath(c); err == nil && !nftBacked(p) {
				fronts = append(fronts, p)
				break
			}
		}
	}
	return fronts
}

// forwardDrops: the chain drops what no rule accepts, or has a rule that
// drops or rejects.
func forwardDrops(rules string) bool {
	for _, l := range strings.Split(rules, "\n") {
		l = strings.TrimSpace(l)
		if l == "-P FORWARD DROP" || strings.HasSuffix(l, "-j DROP") || strings.Contains(l, "-j REJECT") {
			return true
		}
	}
	return false
}

// linkForwardRules: what comes out of the tunnel from the entry goes to
// the Internet; the answers come back.
func linkForwardRules(pub string) [][]string {
	c := []string{"-m", "comment", "--comment", linkFwdComment, "-j", "ACCEPT"}
	return [][]string{
		append([]string{"-i", LinkIface, "-o", pub, "-s", linkEntryAddr + "/32"}, c...),
		append([]string{"-i", pub, "-o", LinkIface, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED"}, c...),
	}
}

// ensureLinkForward adds the exit's rules where FORWARD drops, and removes
// ones left for another Internet interface. It reports what it added.
func ensureLinkForward(ctx context.Context, pub string) (bool, error) {
	added := false
	for _, ipt := range iptablesFronts(ctx) {
		rules, err := output(ctx, ipt, "-w", "5", "-S", "FORWARD")
		if err != nil {
			continue
		}
		for _, l := range ownForwardRules(rules) {
			if !strings.Contains(l, " "+pub+" ") {
				deleteForwardRule(ctx, ipt, l)
			}
		}
		if !forwardDrops(rules) {
			continue
		}
		for _, r := range linkForwardRules(pub) {
			if run(ctx, ipt, append([]string{"-w", "5", "-C", "FORWARD"}, r...)...) == nil {
				continue
			}
			if err := run(ctx, ipt, append([]string{"-w", "5", "-I", "FORWARD", "1"}, r...)...); err != nil {
				return added, fmt.Errorf("%s: %w", filepath.Base(ipt), err)
			}
			added = true
		}
	}
	return added, nil
}

// linkForwardNote says, without changing anything, whether the host's
// iptables drops forwarded packets (note), and whether the tunnel's rules
// are missing there (problem).
func linkForwardNote(ctx context.Context, pub string) (note, problem string) {
	for _, ipt := range iptablesFronts(ctx) {
		rules, err := output(ctx, ipt, "-w", "5", "-S", "FORWARD")
		if err != nil || !forwardDrops(rules) {
			continue
		}
		note = "iptables FORWARD отбрасывает пересылаемые пакеты (ufw, Docker): туннель пропущен"
		for _, r := range linkForwardRules(pub) {
			if run(ctx, ipt, append([]string{"-w", "5", "-C", "FORWARD"}, r...)...) != nil {
				return "", "iptables FORWARD на выходе отбрасывает пакеты туннеля (ufw, Docker): нажмите «Применить»"
			}
		}
	}
	return note, ""
}

// removeLinkForward removes the exit's rules from every FORWARD chain.
func removeLinkForward(ctx context.Context) bool {
	removed := false
	for _, ipt := range iptablesFronts(ctx) {
		rules, err := output(ctx, ipt, "-w", "5", "-S", "FORWARD")
		if err != nil {
			continue
		}
		for _, l := range ownForwardRules(rules) {
			if deleteForwardRule(ctx, ipt, l) {
				removed = true
			}
		}
	}
	return removed
}

func ownForwardRules(rules string) []string {
	var own []string
	for _, l := range strings.Split(rules, "\n") {
		if strings.HasPrefix(l, "-A FORWARD ") && strings.Contains(l, linkFwdComment) {
			own = append(own, l+" ")
		}
	}
	return own
}

func deleteForwardRule(ctx context.Context, ipt, line string) bool {
	args := []string{"-w", "5", "-D"}
	for _, f := range strings.Fields(strings.TrimPrefix(line, "-A ")) {
		args = append(args, strings.Trim(f, "\""))
	}
	return run(ctx, ipt, args...) == nil
}
