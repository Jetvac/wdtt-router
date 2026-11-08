// Package agent reconciles a Linux host to a spec.NodeSpec. Every component
// is idempotent: it inspects the host, changes only what differs and can be
// run any number of times. All mutating entry points hold an exclusive lock.
package agent

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	EtcDir   = "/etc/wdtt-router"
	VarDir   = "/var/lib/wdtt-router"
	LibDir   = "/usr/local/lib/wdtt-router"
	SelfPath = "/usr/local/bin/wdtt-router"
	lockPath = "/run/wdtt-router.lock"
)

// Version is set at build time.
var Version = "dev"

// Logf prints a progress line for the controller's job log.
var Logf = func(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "• "+format+"\n", args...)
}

// Lock takes the host-wide agent lock, waiting up to timeout.
func Lock(timeout time.Duration) (func(), error) {
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
		}
		if time.Now().After(deadline) {
			f.Close()
			return nil, errors.New("another agent operation is still running on this server")
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// run executes a command and returns a trimmed error that includes output.
func run(ctx context.Context, name string, args ...string) error {
	_, err := output(ctx, name, args...)
	return err
}

func output(ctx context.Context, name string, args ...string) (string, error) {
	c := exec.CommandContext(ctx, name, args...)
	c.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive", "LC_ALL=C")
	var buf bytes.Buffer
	c.Stdout = &buf
	c.Stderr = &buf
	err := c.Run()
	out := strings.TrimSpace(buf.String())
	if err != nil {
		return out, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, tail(out, 600))
	}
	return out, nil
}

func runStdin(ctx context.Context, stdin string, name string, args ...string) (string, error) {
	c := exec.CommandContext(ctx, name, args...)
	c.Stdin = strings.NewReader(stdin)
	var buf bytes.Buffer
	c.Stdout = &buf
	c.Stderr = &buf
	err := c.Run()
	out := strings.TrimSpace(buf.String())
	if err != nil {
		return out, fmt.Errorf("%s: %w: %s", name, err, tail(out, 600))
	}
	return out, nil
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func have(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

// writeIfChanged atomically replaces path when content differs and reports
// whether anything was written.
func writeIfChanged(path string, data []byte, mode os.FileMode) (bool, error) {
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, data) {
		if st, err := os.Stat(path); err == nil && st.Mode().Perm() != mode {
			return false, os.Chmod(path, mode)
		}
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return false, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return false, err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return false, err
	}
	return true, os.Rename(tmp, path)
}

func removeIfExists(paths ...string) bool {
	changed := false
	for _, p := range paths {
		if exists(p) {
			_ = os.RemoveAll(p)
			changed = true
		}
	}
	return changed
}

// fetch downloads url (max 64 MiB) and verifies its SHA-256.
func fetch(ctx context.Context, url, sha string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "wdtt-router/"+Version)
	resp, err := (&http.Client{Timeout: 5 * time.Minute}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	if sha != "" {
		sum := sha256.Sum256(b)
		if got := hex.EncodeToString(sum[:]); got != sha {
			return nil, fmt.Errorf("checksum mismatch for %s: got %s", url, got)
		}
	}
	return b, nil
}

// fetchToFile streams url into path while hashing it; the file is removed
// when the checksum does not match.
func fetchToFile(ctx context.Context, url, sha, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "wdtt-router/"+Version)
	resp, err := (&http.Client{Timeout: 15 * time.Minute}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, 512<<20))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && hex.EncodeToString(h.Sum(nil)) != sha {
		err = fmt.Errorf("checksum mismatch for %s", url)
	}
	if err != nil {
		_ = os.Remove(path)
	}
	return err
}

func unzipFile(archive []byte, name string) ([]byte, error) {
	r, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return nil, err
	}
	for _, f := range r.File {
		if f.Name == name {
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			defer rc.Close()
			return io.ReadAll(io.LimitReader(rc, 128<<20))
		}
	}
	return nil, fmt.Errorf("%s not found in archive", name)
}

func systemctl(ctx context.Context, args ...string) error {
	return run(ctx, "systemctl", args...)
}

func unitState(name string) string {
	out, _ := exec.Command("systemctl", "is-active", name).Output()
	s := strings.TrimSpace(string(out))
	if s == "" {
		return "unknown"
	}
	return s
}

func unitExists(name string) bool {
	out, _ := exec.Command("systemctl", "show", "-p", "LoadState", "--value", name).Output()
	return strings.TrimSpace(string(out)) == "loaded"
}

// installUnit writes a unit file, reloads systemd when it changed and makes
// sure the unit is enabled. It reports whether the file changed.
func installUnit(ctx context.Context, name, content string) (bool, error) {
	changed, err := writeIfChanged("/etc/systemd/system/"+name, []byte(content), 0644)
	if err != nil {
		return false, err
	}
	if changed {
		if err := systemctl(ctx, "daemon-reload"); err != nil {
			return false, err
		}
	}
	if err := systemctl(ctx, "enable", name); err != nil {
		return false, err
	}
	return changed, nil
}

func removeUnit(ctx context.Context, name string) bool {
	path := "/etc/systemd/system/" + name
	if !exists(path) {
		return false
	}
	_ = systemctl(ctx, "disable", "--now", name)
	_ = os.Remove(path)
	_ = systemctl(ctx, "daemon-reload")
	_ = systemctl(ctx, "reset-failed", name)
	return true
}

var aptUpdated bool

func aptInstall(ctx context.Context, pkgs ...string) error {
	missing := []string{}
	for _, p := range pkgs {
		if out, err := exec.Command("dpkg-query", "-W", "-f=${Status}", p).Output(); err != nil || !strings.Contains(string(out), "install ok installed") {
			missing = append(missing, p)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	if !have("apt-get") {
		return errors.New("only Debian/Ubuntu (apt) is supported")
	}
	if !aptUpdated {
		if err := run(ctx, "apt-get", "update", "-qq"); err != nil {
			return err
		}
		aptUpdated = true
	}
	Logf("installing packages: %s", strings.Join(missing, " "))
	args := append([]string{"install", "-y", "-qq", "-o", "Dpkg::Options::=--force-confold"}, missing...)
	return run(ctx, "apt-get", args...)
}
