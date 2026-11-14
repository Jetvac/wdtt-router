package store

import (
	"encoding/json"
	"errors"
	"time"
)

// WDTTKey is an access password of the WDTT server. The password is kept
// encrypted like the other secrets.
type WDTTKey struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Password    string `json:"-"`
	VKHash      string `json:"vk_hash"`
	ExpiresAt   int64  `json:"expires_at"`
	Disabled    bool   `json:"disabled"`
	DeviceEpoch int    `json:"-"`
	CreatedAt   string `json:"created_at"`
	// Kind is the WDTT server the key belongs to: "standard" or "turnvk".
	Kind string `json:"kind"`
	// MaxDevices is how many devices may use the key; 0 = no limit.
	MaxDevices int `json:"max_devices"`
	// Unbind lists devices the administrator removed from the key.
	Unbind []WDTTUnbind `json:"-"`
}

// WDTTUnbind frees one device of a key: the server forgets the device if
// it was bound no later than At.
type WDTTUnbind struct {
	Device string `json:"device"`
	At     int64  `json:"at"`
}

// ErrNotFound is returned for a missing record.
var ErrNotFound = errors.New("not found")

// WDTTKeys lists the access keys, oldest first.
func (s *Store) WDTTKeys() ([]WDTTKey, error) {
	rows, err := s.DB.Query(`SELECT id, name, password_cipher, vk_hash, expires_at, disabled, device_epoch, created_at, kind, max_devices, unbind FROM wdtt_keys ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []WDTTKey{}
	for rows.Next() {
		var k WDTTKey
		var enc, unbind string
		if err := rows.Scan(&k.ID, &k.Name, &enc, &k.VKHash, &k.ExpiresAt, &k.Disabled, &k.DeviceEpoch, &k.CreatedAt, &k.Kind, &k.MaxDevices, &unbind); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(unbind), &k.Unbind)
		if k.Password, err = s.OpenSecret(enc); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// WDTTKey returns one key.
func (s *Store) WDTTKey(id string) (WDTTKey, error) {
	keys, err := s.WDTTKeys()
	if err != nil {
		return WDTTKey{}, err
	}
	for _, k := range keys {
		if k.ID == id {
			return k, nil
		}
	}
	return WDTTKey{}, ErrNotFound
}

// PutWDTTKey inserts or replaces a key.
func (s *Store) PutWDTTKey(k WDTTKey) error {
	enc, err := s.Seal(k.Password)
	if err != nil {
		return err
	}
	if k.CreatedAt == "" {
		k.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if k.Kind == "" {
		k.Kind = "standard"
	}
	if k.Unbind == nil {
		k.Unbind = []WDTTUnbind{}
	}
	unbind, _ := json.Marshal(k.Unbind)
	_, err = s.DB.Exec(`INSERT INTO wdtt_keys (id, name, password_cipher, vk_hash, expires_at, disabled, device_epoch, created_at, kind, max_devices, unbind)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET name=excluded.name, password_cipher=excluded.password_cipher, vk_hash=excluded.vk_hash,
 expires_at=excluded.expires_at, disabled=excluded.disabled, device_epoch=excluded.device_epoch,
 max_devices=excluded.max_devices, unbind=excluded.unbind`,
		k.ID, k.Name, enc, k.VKHash, k.ExpiresAt, k.Disabled, k.DeviceEpoch, k.CreatedAt, k.Kind, k.MaxDevices, string(unbind))
	return err
}

// DeleteWDTTKey removes a key.
func (s *Store) DeleteWDTTKey(id string) error {
	r, err := s.DB.Exec(`DELETE FROM wdtt_keys WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
