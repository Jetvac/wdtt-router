package update

import (
	"encoding/hex"
	"testing"
)

// A SHA256SUMS signed by `openssl pkeyutl -sign -rawin` with the release
// key, as the release workflow does: Go must accept exactly that.
const (
	sampleSums = "deadbeef  wdtt-router-linux-amd64.tar.gz\n"
	sampleSig  = "1ca69e9b599d029d00c3ed99701ee9fed70eee547d6ec75d85f3d1418a3786326664f5ae98507876d8e225b30ba30e04382d9309183b00623d791ad209ecb80d"
)

func TestVerifyOpenSSLSignature(t *testing.T) {
	sig, _ := hex.DecodeString(sampleSig)
	if err := Verify([]byte(sampleSums), sig); err != nil {
		t.Fatal(err)
	}
	if err := Verify([]byte(sampleSums+"x"), sig); err == nil {
		t.Fatal("tampered list accepted")
	}
	sig[0] ^= 1
	if err := Verify([]byte(sampleSums), sig); err == nil {
		t.Fatal("tampered signature accepted")
	}
}

func TestCheckSum(t *testing.T) {
	sums := []byte("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  install.sh\n")
	if err := CheckSum(sums, "install.sh", []byte("abc")); err != nil {
		t.Fatal(err)
	}
	if err := CheckSum(sums, "install.sh", []byte("abd")); err == nil {
		t.Fatal("wrong data accepted")
	}
	if err := CheckSum(sums, "other", []byte("abc")); err == nil {
		t.Fatal("missing name accepted")
	}
}

func TestNewer(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"v1.2.0", "1.1.0", true},
		{"v1.2.0", "1.2.0-dev11", true},
		{"v1.2.0", "1.2.0", false},
		{"v1.1.9", "1.2.0-dev1", false},
		{"v1.10.0", "1.9.3", true},
	} {
		if got := Newer(c.a, c.b); got != c.want {
			t.Errorf("Newer(%q, %q) = %v", c.a, c.b, got)
		}
	}
}
