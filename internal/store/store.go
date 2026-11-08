package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	DB  *sql.DB
	key []byte
}

func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, err
	}
	keyPath := filepath.Join(dir, "master.key")
	key, err := os.ReadFile(keyPath)
	if errors.Is(err, os.ErrNotExist) {
		key = make([]byte, 32)
		if _, err = rand.Read(key); err != nil {
			return nil, err
		}
		err = os.WriteFile(keyPath, key, 0600)
	}
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, errors.New("invalid master key length")
	}
	if err := os.Chmod(keyPath, 0600); err != nil {
		return nil, err
	}
	dbPath := filepath.Join(dir, "state.db")
	db, err := sql.Open("sqlite", "file:"+dbPath+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{DB: db, key: key}
	if err = s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	for _, path := range []string{dbPath, dbPath + "-wal", dbPath + "-shm"} {
		if err := os.Chmod(path, 0600); err != nil && !errors.Is(err, os.ErrNotExist) {
			db.Close()
			return nil, err
		}
	}
	return s, nil
}

func (s *Store) Close() error { return s.DB.Close() }

func (s *Store) migrate() error {
	_, err := s.DB.Exec(`
CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, csrf TEXT NOT NULL, expires_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS settings (name TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS secrets (name TEXT PRIMARY KEY, cipher_text TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS nodes (
	id INTEGER PRIMARY KEY,
	name TEXT NOT NULL UNIQUE,
	host TEXT NOT NULL,
	ssh_port INTEGER NOT NULL DEFAULT 22,
	fingerprint TEXT NOT NULL DEFAULT '',
	local INTEGER NOT NULL DEFAULT 0,
	mesh_ip TEXT NOT NULL DEFAULT '',
	cf_node_id TEXT NOT NULL DEFAULT '',
	cf_node_name TEXT NOT NULL DEFAULT '',
	hop_port INTEGER NOT NULL DEFAULT 0,
	ssh_public INTEGER NOT NULL DEFAULT 1,
	ssh_allow TEXT NOT NULL DEFAULT '',
	allow_ping INTEGER NOT NULL DEFAULT 0,
	firewall INTEGER NOT NULL DEFAULT 1,
	status_json TEXT NOT NULL DEFAULT '{}',
	last_seen TEXT NOT NULL DEFAULT '',
	last_error TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS jobs (
	id INTEGER PRIMARY KEY,
	kind TEXT NOT NULL,
	node_id INTEGER NOT NULL DEFAULT 0,
	title TEXT NOT NULL,
	status TEXT NOT NULL,
	log TEXT NOT NULL DEFAULT '',
	error TEXT NOT NULL DEFAULT '',
	input_cipher TEXT NOT NULL DEFAULT '',
	created_by TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	started_at TEXT NOT NULL DEFAULT '',
	finished_at TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, username TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '', remote TEXT NOT NULL DEFAULT '', at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS cf_resources (id TEXT PRIMARY KEY, kind TEXT NOT NULL, name TEXT NOT NULL, node_id INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS wdtt_keys (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	password_cipher TEXT NOT NULL,
	vk_hash TEXT NOT NULL DEFAULT '',
	expires_at INTEGER NOT NULL DEFAULT 0,
	disabled INTEGER NOT NULL DEFAULT 0,
	device_epoch INTEGER NOT NULL DEFAULT 0,
	created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_jobs_created ON jobs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_at ON audit(at DESC);
`)
	return err
}

// Setting returns a stored setting or def.
func (s *Store) Setting(name, def string) string {
	var v string
	if err := s.DB.QueryRow(`SELECT value FROM settings WHERE name=?`, name).Scan(&v); err != nil {
		return def
	}
	return v
}

// SetSetting stores a setting.
func (s *Store) SetSetting(name, value string) error {
	_, err := s.DB.Exec(`INSERT INTO settings(name,value) VALUES(?,?) ON CONFLICT(name) DO UPDATE SET value=excluded.value`, name, value)
	return err
}

// Audit records a user action.
func (s *Store) Audit(user, action, detail, remote string) {
	_, _ = s.DB.Exec(`INSERT INTO audit(username,action,detail,remote,at) VALUES(?,?,?,?,?)`, user, action, detail, remote, time.Now().UTC().Format(time.RFC3339))
}

func (s *Store) Seal(plain string) (string, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := aead.Seal(nonce, nonce, []byte(plain), nil)
	return base64.RawStdEncoding.EncodeToString(sealed), nil
}

func (s *Store) OpenSecret(encoded string) (string, error) {
	data, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(data) < aead.NonceSize() {
		return "", errors.New("short secret")
	}
	plain, err := aead.Open(nil, data[:aead.NonceSize()], data[aead.NonceSize():], nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func (s *Store) PutSecret(name, plain string) error {
	enc, err := s.Seal(plain)
	if err != nil {
		return err
	}
	_, err = s.DB.Exec(`INSERT INTO secrets(name,cipher_text,updated_at) VALUES(?,?,?) ON CONFLICT(name) DO UPDATE SET cipher_text=excluded.cipher_text,updated_at=excluded.updated_at`, name, enc, time.Now().UTC().Format(time.RFC3339))
	return err
}

func (s *Store) Secret(name string) (string, error) {
	var cipherText string
	if err := s.DB.QueryRow(`SELECT cipher_text FROM secrets WHERE name=?`, name).Scan(&cipherText); err != nil {
		return "", err
	}
	return s.OpenSecret(cipherText)
}

func (s *Store) DeleteSecret(name string) error {
	_, err := s.DB.Exec(`DELETE FROM secrets WHERE name=?`, name)
	return err
}

// Prune removes old history: audit entries and finished jobs older than 30 days.
func (s *Store) Prune() error {
	cutoff := time.Now().UTC().Add(-30 * 24 * time.Hour).Format(time.RFC3339)
	if _, err := s.DB.Exec(`DELETE FROM audit WHERE at < ?`, cutoff); err != nil {
		return fmt.Errorf("prune audit: %w", err)
	}
	if _, err := s.DB.Exec(`DELETE FROM jobs WHERE created_at < ? AND status IN ('success','failed','cancelled')`, cutoff); err != nil {
		return fmt.Errorf("prune jobs: %w", err)
	}
	_, err := s.DB.Exec(`DELETE FROM sessions WHERE expires_at < ?`, time.Now().UTC().Format(time.RFC3339))
	return err
}
