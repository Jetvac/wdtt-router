package agent

import (
	"os"
	"path/filepath"
	"testing"
)

// A provider's leftover install script on a timer (Hostkey's firstscript)
// is found; appending a key, ordinary daemons and stderr redirects are not.
func TestFindKeyWipers(t *testing.T) {
	dir := t.TempDir()
	units := filepath.Join(dir, "units")
	bin := filepath.Join(dir, "bin")
	cron := filepath.Join(dir, "cron.d")
	for _, d := range []string{units, bin, cron} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(p, s string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	first := filepath.Join(bin, "firstscript.sh")
	write(first, "#!/bin/bash\nhostnamectl set-hostname x\necho \"\" > /root/.ssh/authorized_keys\n")
	write(filepath.Join(units, "firstscript.service"), "[Service]\nType=oneshot\nExecStart=/bin/bash -c 'exec "+first+" >/tmp/firstscript.log'\nExecStartPost=-/bin/rm -f "+first+"\n")
	write(filepath.Join(units, "firstscript.timer"), "[Timer]\nOnStartupSec=5s\nOnUnitActiveSec=3600\n")
	// Appends a key: fine.
	adds := filepath.Join(bin, "addkey.sh")
	write(adds, "#!/bin/sh\necho ssh-ed25519 AAAA >> /root/.ssh/authorized_keys 2>/root/.ssh/authorized_keys.err\n")
	write(filepath.Join(units, "addkey.service"), "[Service]\nExecStart="+adds+"\n[Install]\nWantedBy=multi-user.target\n")
	// A daemon that is neither on a timer nor started at boot: not looked at.
	write(filepath.Join(units, "manual.service"), "[Service]\nExecStart=/bin/sh -c ': > /root/.ssh/authorized_keys'\n")
	write(filepath.Join(cron, "cleanup"), "# m h dom mon dow user command\n0 * * * * root rm -f ~/.ssh/authorized_keys\n")

	defer func(u, f, d []string) { unitDirs, cronFiles, cronDirs = u, f, d }(unitDirs, cronFiles, cronDirs)
	unitDirs, cronFiles, cronDirs = []string{units}, nil, []string{cron}

	got := findKeyWipers()
	want := []string{
		filepath.Join(cron, "cleanup") + " → 0 * * * * root rm -f ~/.ssh/authorized_keys",
		"firstscript.timer → " + first,
	}
	if len(got) != len(want) {
		t.Fatalf("got %q", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %q, want %q", got[i], want[i])
		}
	}
}
