// Package backup writes and restores an encrypted copy of the panel state:
// the database (with the encrypted secrets), its master key, the panel's
// SSH key and certificate, and the WDTT server's keys and devices.
//
// File format: "WDTTRBK1" | salt (16) | nonce (12) | AES-256-GCM(tar.gz),
// the key derived from the passphrase with scrypt (N=2^15, r=8, p=1) and
// the header as additional data. Without the passphrase the file is useless.
package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/scrypt"
)

const (
	magic   = "WDTTRBK1"
	saltLen = 16
	// MinPassphrase is the shortest passphrase accepted.
	MinPassphrase = 12
	maxSize       = 256 << 20
)

// Entry is one file of the backup: its name in the archive and its data.
type Entry struct {
	Name string
	Mode int64
	Data []byte
}

func deriveKey(pass string, salt []byte) ([]byte, error) {
	return scrypt.Key([]byte(pass), salt, 1<<15, 8, 1, 32)
}

// Seal packs and encrypts the entries.
func Seal(entries []Entry, pass string) ([]byte, error) {
	if len(pass) < MinPassphrase {
		return nil, fmt.Errorf("passphrase must be at least %d characters", MinPassphrase)
	}
	var plain bytes.Buffer
	gz := gzip.NewWriter(&plain)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		if err := tw.WriteHeader(&tar.Header{Name: e.Name, Mode: e.Mode, Size: int64(len(e.Data)), ModTime: time.Now()}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(e.Data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	key, err := deriveKey(pass, salt)
	if err != nil {
		return nil, err
	}
	aead, err := gcm(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	header := append(append([]byte(magic), salt...), nonce...)
	return aead.Seal(header, nonce, plain.Bytes(), []byte(magic)), nil
}

// Open decrypts and unpacks a backup.
func Open(data []byte, pass string) ([]Entry, error) {
	if len(data) < len(magic)+saltLen+12+16 || string(data[:len(magic)]) != magic {
		return nil, errors.New("not a WDTT Router backup")
	}
	salt := data[len(magic) : len(magic)+saltLen]
	key, err := deriveKey(pass, salt)
	if err != nil {
		return nil, err
	}
	aead, err := gcm(key)
	if err != nil {
		return nil, err
	}
	off := len(magic) + saltLen
	nonce := data[off : off+aead.NonceSize()]
	plain, err := aead.Open(nil, nonce, data[off+aead.NonceSize():], []byte(magic))
	if err != nil {
		return nil, errors.New("wrong passphrase or damaged file")
	}
	gz, err := gzip.NewReader(bytes.NewReader(plain))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	var out []Entry
	total := 0
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if h.Typeflag != tar.TypeReg || !safeName(h.Name) {
			return nil, fmt.Errorf("unexpected entry %q in the backup", h.Name)
		}
		b, err := io.ReadAll(io.LimitReader(tr, maxSize))
		if err != nil {
			return nil, err
		}
		if total += len(b); total > maxSize {
			return nil, errors.New("backup too large")
		}
		out = append(out, Entry{Name: h.Name, Mode: h.Mode, Data: b})
	}
	return out, nil
}

// safeName admits only "panel/<file>" and "wdtt/<file>".
func safeName(n string) bool {
	dir, file := path.Split(n)
	return (dir == "panel/" || dir == "wdtt/") && file != "" && file != "." && file != ".." && !strings.ContainsAny(file, `/\`)
}

func gcm(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Collect reads the files of the panel and WDTT directories. db is a
// consistent snapshot of the database (VACUUM INTO), stored as state.db.
func Collect(panelDir, wdttDir string, db []byte) ([]Entry, error) {
	out := []Entry{{Name: "panel/state.db", Mode: 0600, Data: db}}
	for _, f := range []string{"master.key", "ssh_ed25519", "ssh_ed25519.pub", "panel.crt", "panel.key", "public_host"} {
		b, err := os.ReadFile(filepath.Join(panelDir, f))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, Entry{Name: "panel/" + f, Mode: 0600, Data: b})
	}
	if b, err := os.ReadFile(filepath.Join(wdttDir, "state.json")); err == nil {
		out = append(out, Entry{Name: "wdtt/state.json", Mode: 0600, Data: b})
	}
	return out, nil
}

// Restore writes the entries into place. Existing files are kept with a
// ".before-restore" suffix.
func Restore(entries []Entry, panelDir, wdttDir string) error {
	for _, e := range entries {
		dir := panelDir
		if strings.HasPrefix(e.Name, "wdtt/") {
			dir = wdttDir
		}
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
		dst := filepath.Join(dir, path.Base(e.Name))
		if _, err := os.Stat(dst); err == nil {
			_ = os.Rename(dst, dst+".before-restore")
		}
		if err := os.WriteFile(dst, e.Data, 0600); err != nil {
			return err
		}
	}
	// A database restored from a snapshot must not be mixed with the
	// write-ahead log of the database it replaced.
	for _, f := range []string{"state.db-wal", "state.db-shm"} {
		p := filepath.Join(panelDir, f)
		if _, err := os.Stat(p); err == nil {
			_ = os.Rename(p, p+".before-restore")
		}
	}
	return nil
}
