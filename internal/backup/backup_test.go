package backup

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	in := []Entry{{Name: "panel/state.db", Mode: 0600, Data: []byte("db")}, {Name: "wdtt/state.json", Mode: 0600, Data: []byte("{}")}}
	sealed, err := Seal(in, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("state.db")) {
		t.Fatal("file names visible in the backup")
	}
	if _, err := Open(sealed, "wrong passphrase!!"); err == nil {
		t.Fatal("opened with a wrong passphrase")
	}
	out, err := Open(sealed, "correct horse battery")
	if err != nil || len(out) != 2 || string(out[1].Data) != "{}" {
		t.Fatalf("%v %+v", err, out)
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := Open(sealed, "correct horse battery"); err == nil {
		t.Fatal("tampered backup opened")
	}
	if _, err := Seal(in, "short"); err == nil {
		t.Fatal("short passphrase accepted")
	}
}

func TestRestoreKeepsOldFiles(t *testing.T) {
	dir := t.TempDir()
	panel, wdtt := filepath.Join(dir, "panel"), filepath.Join(dir, "wdtt")
	_ = os.MkdirAll(panel, 0700)
	_ = os.WriteFile(filepath.Join(panel, "state.db"), []byte("old"), 0600)
	if err := Restore([]Entry{{Name: "panel/state.db", Data: []byte("new")}, {Name: "wdtt/state.json", Data: []byte("{}")}}, panel, wdtt); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(panel, "state.db")); string(b) != "new" {
		t.Fatal("not restored")
	}
	if b, _ := os.ReadFile(filepath.Join(panel, "state.db.before-restore")); string(b) != "old" {
		t.Fatal("old file not kept")
	}
	if _, err := os.Stat(filepath.Join(wdtt, "state.json")); err != nil {
		t.Fatal(err)
	}
}

func TestUnsafeNames(t *testing.T) {
	for _, n := range []string{"../x", "panel/../x", "/etc/passwd", "other/x", "panel/", "panel/a/b"} {
		if safeName(n) {
			t.Errorf("%q accepted", n)
		}
	}
}
