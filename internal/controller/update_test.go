package controller

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
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
