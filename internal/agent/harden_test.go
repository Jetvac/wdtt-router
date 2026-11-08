package agent

import (
	"strings"
	"testing"

	"github.com/Jetvac/wdtt-router/internal/spec"
)

func TestWithTopBlock(t *testing.T) {
	conf := "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\n"
	on := withTopBlock(conf, sshdHardened)
	if on[:len(sshdBegin)] != sshdBegin || withTopBlock(on, sshdHardened) != on {
		t.Fatalf("block not at the top or not idempotent:\n%s", on)
	}
	if off := withTopBlock(on, ""); off != conf {
		t.Fatalf("removing the block changed the rest:\n%q", off)
	}
}

func TestPanelMeshRules(t *testing.T) {
	f := spec.FirewallSpec{Enabled: true, SSHPort: 22, SSHPublic: true, PanelPort: 8443}
	r := RenderFirewall(f, FirewallInputs{})
	mesh := `iifname "CloudflareWARP" ip saddr 100.96.0.0/12 tcp dport 8443 accept`
	public := "\t\ttcp dport 8443 accept"
	if !strings.Contains(r, mesh) || !strings.Contains(r, public) {
		t.Fatalf("Mesh or public panel rule missing:\n%s", r)
	}
	if strings.Index(r, mesh) > strings.Index(r, `iifname "CloudflareWARP" drop`) {
		t.Fatal("panel rule after the Mesh drop")
	}
	f.PanelMeshOnly = true
	r = RenderFirewall(f, FirewallInputs{})
	if !strings.Contains(r, mesh) || strings.Contains(r, public) {
		t.Fatalf("Mesh-only panel rules wrong:\n%s", r)
	}
}

func TestRedact(t *testing.T) {
	in := `"password": "s3cr3t", token=abc123 "uuid":"1234-5678" Mesh ok PrivateKey = YNqHbf=`
	out := Redact(in)
	for _, leak := range []string{"s3cr3t", "abc123", "1234-5678", "YNqHbf"} {
		if strings.Contains(out, leak) {
			t.Fatalf("%q leaked: %s", leak, out)
		}
	}
	if !strings.Contains(out, "Mesh ok") {
		t.Fatal("ordinary text removed")
	}
}
