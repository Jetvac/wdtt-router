// Package update finds new releases and fetches a verified installer.
//
// Every release carries SHA256SUMS and SHA256SUMS.sig, an Ed25519
// signature made with the project's release key. Only an installer whose
// checksum is in a correctly signed SHA256SUMS is ever run; the installer
// then checks the archive the same way.
package update

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// PublicKey is the release signing key (also embedded in install.sh).
const PublicKey = "7e34764b2637016cabdb0a21fcb9d592543bde5289ffd1784068d8bd5e131c72"

// Repo is the GitHub repository of releases.
const Repo = "Jetvac/wdtt-router"

// Verify checks the signature of a SHA256SUMS file.
func Verify(sums, sig []byte) error {
	pub, _ := hex.DecodeString(PublicKey)
	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, sums, sig) {
		return errors.New("release signature does not match the project's key")
	}
	return nil
}

// Release is a published release.
type Release struct {
	Tag       string `json:"tag"`
	Name      string `json:"name"`
	Notes     string `json:"notes"`
	URL       string `json:"url"`
	Published string `json:"published"`
}

var client = &http.Client{Timeout: 60 * time.Second}

// Latest returns the newest published release.
func Latest(ctx context.Context) (Release, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/repos/"+Repo+"/releases/latest", nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return Release{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Release{}, fmt.Errorf("GitHub: HTTP %d", resp.StatusCode)
	}
	var r struct {
		Tag       string `json:"tag_name"`
		Name      string `json:"name"`
		Body      string `json:"body"`
		URL       string `json:"html_url"`
		Published string `json:"published_at"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&r); err != nil {
		return Release{}, err
	}
	notes := r.Body
	if len(notes) > 4000 {
		notes = notes[:4000] + "…"
	}
	return Release{Tag: r.Tag, Name: r.Name, Notes: notes, URL: r.URL, Published: r.Published}, nil
}

func get(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

// Installer downloads install.sh of a release and returns it only if its
// checksum is listed in the release's correctly signed SHA256SUMS.
func Installer(ctx context.Context, tag string) ([]byte, error) {
	base := "https://github.com/" + Repo + "/releases/download/" + tag + "/"
	sums, err := get(ctx, base+"SHA256SUMS", 64<<10)
	if err != nil {
		return nil, err
	}
	sig, err := get(ctx, base+"SHA256SUMS.sig", 1<<10)
	if err != nil {
		return nil, fmt.Errorf("the release has no signature: %w", err)
	}
	if err := Verify(sums, sig); err != nil {
		return nil, err
	}
	script, err := get(ctx, base+"install.sh", 1<<20)
	if err != nil {
		return nil, err
	}
	if err := CheckSum(sums, "install.sh", script); err != nil {
		return nil, err
	}
	return script, nil
}

// CheckSum finds name in a SHA256SUMS file and compares the checksum.
func CheckSum(sums []byte, name string, data []byte) error {
	sum := sha256.Sum256(data)
	want := hex.EncodeToString(sum[:])
	sc := bufio.NewScanner(bytes.NewReader(sums))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name {
			if f[0] == want {
				return nil
			}
			return fmt.Errorf("%s: checksum does not match the signed list", name)
		}
	}
	return fmt.Errorf("%s is not in the signed list", name)
}

// Newer reports whether release tag a is newer than version b. Versions
// are "vX.Y.Z" or "X.Y.Z[-suffix]"; a suffixed (pre-release or development)
// version is older than the same X.Y.Z without one.
func Newer(a, b string) bool {
	pa, sa := parse(a)
	pb, sb := parse(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			return pa[i] > pb[i]
		}
	}
	return sa == "" && sb != ""
}

func parse(v string) ([3]int, string) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	core, suffix, _ := strings.Cut(v, "-")
	var out [3]int
	for i, p := range strings.SplitN(core, ".", 3) {
		out[i], _ = strconv.Atoi(p)
	}
	return out, suffix
}
