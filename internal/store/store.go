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

	_ "github.com/mattn/go-sqlite3"
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
	db, err := sql.Open("sqlite3", dbPath+"?_busy_timeout=5000&_journal_mode=WAL&_foreign_keys=on")
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
CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), csrf TEXT NOT NULL, expires_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS servers (id INTEGER PRIMARY KEY, name TEXT NOT NULL, host TEXT NOT NULL UNIQUE, port INTEGER NOT NULL DEFAULT 22, role TEXT NOT NULL, os TEXT NOT NULL DEFAULT '', fingerprint TEXT NOT NULL DEFAULT '', transport TEXT NOT NULL DEFAULT 'ssh', firewall_auto INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, last_seen TEXT NOT NULL DEFAULT '', observed_json TEXT NOT NULL DEFAULT '{}');
CREATE TABLE IF NOT EXISTS chains (id INTEGER PRIMARY KEY, name TEXT NOT NULL, desired_json TEXT NOT NULL, observed_json TEXT NOT NULL DEFAULT '{}', applied_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS jobs (id INTEGER PRIMARY KEY, server_id INTEGER REFERENCES servers(id), action TEXT NOT NULL, status TEXT NOT NULL, progress TEXT NOT NULL DEFAULT '', input_cipher TEXT NOT NULL DEFAULT '', result TEXT NOT NULL DEFAULT '', snapshot_id TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS snapshots (id TEXT PRIMARY KEY, server_id INTEGER REFERENCES servers(id), action TEXT NOT NULL, data_json TEXT NOT NULL, created_at TEXT NOT NULL, committed INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS audit_events (id INTEGER PRIMARY KEY, user_id INTEGER, server_id INTEGER, action TEXT NOT NULL, result TEXT NOT NULL, at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS secrets (name TEXT PRIMARY KEY, cipher_text TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS settings (name TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS cloudflare_resources (id TEXT PRIMARY KEY, account_id TEXT NOT NULL, vnet_id TEXT NOT NULL DEFAULT '', kind TEXT NOT NULL, name TEXT NOT NULL, owner TEXT NOT NULL CHECK(owner IN ('created','imported')), created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, server_id INTEGER, component TEXT NOT NULL, severity TEXT NOT NULL, message TEXT NOT NULL, at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_jobs_created ON jobs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_at ON events(at DESC);
`)
	return err
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

func (s *Store) Event(serverID int64, component, severity, message string) {
	_, _ = s.DB.Exec(`INSERT INTO events(server_id,component,severity,message,at) VALUES(?,?,?,?,?)`, serverID, component, severity, message, time.Now().UTC().Format(time.RFC3339))
}

func (s *Store) Prune() error {
	cutoff := time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)
	if _, err := s.DB.Exec(`DELETE FROM events WHERE at < ?`, cutoff); err != nil {
		return fmt.Errorf("prune events: %w", err)
	}
	if _, err := s.DB.Exec(`DELETE FROM audit_events WHERE at < ?`, cutoff); err != nil {
		return fmt.Errorf("prune audit: %w", err)
	}
	if _, err := s.DB.Exec(`DELETE FROM jobs WHERE updated_at < ? AND status IN ('success','failed')`, cutoff); err != nil {
		return fmt.Errorf("prune jobs: %w", err)
	}
	_, err := s.DB.Exec(`DELETE FROM sessions WHERE expires_at < ?`, time.Now().UTC().Format(time.RFC3339))
	return err
}
