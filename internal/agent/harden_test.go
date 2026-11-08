package agent

import "testing"

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
