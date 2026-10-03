package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

var ErrWeakPassword = errors.New("password is too short")

func Random(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func HashPassword(password string) (string, error) {
	if len(password) < 16 {
		return "", ErrWeakPassword
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
	return fmt.Sprintf("$argon2id$v=19$m=65536,t=3,p=4$%s$%s", base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(hash)), nil
}

func VerifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" || parts[3] != "m=65536,t=3,p=4" {
		return false
	}
	salt, e1 := base64.RawStdEncoding.DecodeString(parts[4])
	want, e2 := base64.RawStdEncoding.DecodeString(parts[5])
	if e1 != nil || e2 != nil || len(salt) != 16 || len(want) != 32 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
	return subtle.ConstantTimeCompare(got, want) == 1
}

func CreateInitialUser(db *sql.DB) (string, string, error) {
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		return "", "", err
	}
	if count > 0 {
		return "", "", nil
	}
	user := "admin"
	password, err := Random(30)
	if err != nil {
		return "", "", err
	}
	hash, err := HashPassword(password)
	if err != nil {
		return "", "", err
	}
	_, err = db.Exec(`INSERT INTO users(username,password_hash,created_at) VALUES(?,?,?)`, user, hash, time.Now().UTC().Format(time.RFC3339))
	return user, password, err
}

func TokenHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

type Session struct {
	UserID   int64
	Username string
	CSRF     string
	Expires  time.Time
}

func Authenticate(db *sql.DB, username, password string) (int64, bool) {
	var id int64
	var hash string
	err := db.QueryRow(`SELECT id,password_hash FROM users WHERE username=?`, username).Scan(&id, &hash)
	if err != nil { // equalize most of the work for unknown usernames
		_, _ = HashPassword("0123456789abcdef")
		return 0, false
	}
	return id, VerifyPassword(hash, password)
}

func NewSession(db *sql.DB, userID int64) (string, string, error) {
	token, err := Random(32)
	if err != nil {
		return "", "", err
	}
	csrf, err := Random(24)
	if err != nil {
		return "", "", err
	}
	expires := time.Now().UTC().Add(12 * time.Hour).Format(time.RFC3339)
	_, err = db.Exec(`INSERT INTO sessions(token_hash,user_id,csrf,expires_at) VALUES(?,?,?,?)`, TokenHash(token), userID, csrf, expires)
	return token, csrf, err
}

func ReadSession(db *sql.DB, token string) (Session, error) {
	var s Session
	var expires string
	err := db.QueryRow(`SELECT s.user_id,u.username,s.csrf,s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?`, TokenHash(token)).Scan(&s.UserID, &s.Username, &s.CSRF, &expires)
	if err != nil {
		return s, err
	}
	s.Expires, err = time.Parse(time.RFC3339, expires)
	if err != nil {
		return s, err
	}
	if time.Now().After(s.Expires) {
		return s, sql.ErrNoRows
	}
	return s, nil
}

func Revoke(db *sql.DB, token string) error {
	_, err := db.Exec(`DELETE FROM sessions WHERE token_hash=?`, TokenHash(token))
	return err
}

func ChangePassword(db *sql.DB, userID int64, oldPass, newPass string) error {
	var oldHash string
	if err := db.QueryRow(`SELECT password_hash FROM users WHERE id=?`, userID).Scan(&oldHash); err != nil {
		return err
	}
	if !VerifyPassword(oldHash, oldPass) {
		return errors.New("incorrect password")
	}
	hash, err := HashPassword(newPass)
	if err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`UPDATE users SET password_hash=? WHERE id=?`, hash, userID); err != nil {
		return err
	}
	if _, err = tx.Exec(`DELETE FROM sessions WHERE user_id=?`, userID); err != nil {
		return err
	}
	return tx.Commit()
}
