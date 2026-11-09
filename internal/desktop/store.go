// Package desktop is the core of the Windows app: it keeps the list of panel
// servers, connects to them over SSH with its own key and serves the panel
// through an SSH tunnel to a local window. The panel itself keeps running on
// the server (statistics, the Telegram bot, jobs); the app is a client.
package desktop

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

// Server is a panel server in the app's list.
type Server struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
	User      string `json:"user"`
	HostKey   string `json:"host_key"` // the server's SSH host key, remembered on first contact
	Added     string `json:"added"`
	LastUsed  string `json:"last_used,omitempty"`
	Version   string `json:"version,omitempty"`
	LastEvent int64  `json:"last_event,omitempty"` // newest panel event already shown as a notification
}

// Store is the app's state in its own folder: servers.json and the app's
// SSH key, encrypted for the Windows user (DPAPI).
type Store struct {
	dir     string
	mu      sync.Mutex
	servers []Server
	signer  ssh.Signer
	pub     string
}

func OpenStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	s := &Store{dir: dir}
	b, err := os.ReadFile(filepath.Join(dir, "servers.json"))
	if err == nil {
		if err := json.Unmarshal(b, &s.servers); err != nil {
			return nil, fmt.Errorf("servers.json: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := s.loadKey(); err != nil {
		return nil, fmt.Errorf("ключ приложения: %w", err)
	}
	return s, nil
}

func (s *Store) Dir() string { return s.dir }

// loadKey reads the app's SSH key, creating it on first start.
func (s *Store) loadKey() error {
	path := filepath.Join(s.dir, "app_key")
	sealed, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		der, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return err
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		if sealed, err = protect(pemBytes); err != nil {
			return err
		}
		if err := writeFile(path, sealed); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	pemBytes, err := unprotect(sealed)
	if err != nil {
		return fmt.Errorf("не удалось расшифровать (файл с другого компьютера или пользователя?): %w", err)
	}
	if s.signer, err = ssh.ParsePrivateKey(pemBytes); err != nil {
		return err
	}
	s.pub = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.signer.PublicKey())))
	return nil
}

func (s *Store) Signer() ssh.Signer { return s.signer }

// PublicKey is the app's key in authorized_keys format, with a comment that
// names this computer.
func (s *Store) PublicKey(device string) string {
	return s.pub + " wdtt-router-app@" + strings.Map(func(r rune) rune {
		if r <= ' ' || r == 127 {
			return '_'
		}
		return r
	}, device)
}

func (s *Store) List() []Server {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.servers)
}

func (s *Store) Get(id string) (Server, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range s.servers {
		if v.ID == id {
			return v, true
		}
	}
	return Server{}, false
}

// Update changes a server in place (or adds it) and saves the list.
func (s *Store) Update(id string, f func(*Server)) (Server, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := slices.IndexFunc(s.servers, func(v Server) bool { return v.ID == id })
	if i < 0 {
		s.servers = append(s.servers, Server{ID: id})
		i = len(s.servers) - 1
	}
	f(&s.servers[i])
	return s.servers[i], s.save()
}

func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.servers = slices.DeleteFunc(s.servers, func(v Server) bool { return v.ID == id })
	return s.save()
}

func (s *Store) save() error {
	b, err := json.MarshalIndent(s.servers, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(filepath.Join(s.dir, "servers.json"), b)
}

// writeFile replaces a file atomically.
func writeFile(path string, b []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
