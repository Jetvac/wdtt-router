package controller

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestVerifyReleaseAsset(t *testing.T) {
	dir := t.TempDir()
	content := []byte("verified installer")
	sum := sha256.Sum256(content)
	if err := os.WriteFile(filepath.Join(dir, "install.sh"), content, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(hex.EncodeToString(sum[:])+"  install.sh\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyReleaseAsset(dir, "install.sh"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "install.sh"), []byte("tampered installer"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyReleaseAsset(dir, "install.sh"); err == nil {
		t.Fatal("tampered installer passed checksum verification")
	}
}

func TestUpdateInProgress(t *testing.T) {
	dir := t.TempDir()
	a := App{DataDir: dir, Version: "v0.1.2"}
	last := panelUpdateState{Target: "v0.1.3", StartedAt: time.Now().UTC().Format(time.RFC3339)}
	b, _ := json.Marshal(last)
	if err := os.WriteFile(filepath.Join(dir, "last-app-update.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	if !a.updateInProgress() {
		t.Fatal("running update was not detected")
	}
	a.Version = "v0.1.3"
	if a.updateInProgress() {
		t.Fatal("completed update still blocks new operations")
	}
	a.Version = "v0.1.2"
	last.StartedAt = time.Now().Add(-6 * time.Minute).UTC().Format(time.RFC3339)
	b, _ = json.Marshal(last)
	if err := os.WriteFile(filepath.Join(dir, "last-app-update.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	if a.updateInProgress() {
		t.Fatal("stale update still blocks new operations")
	}
}
