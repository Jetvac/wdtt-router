package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

type Target struct {
	Host        string
	Port        int
	User        string
	Fingerprint string
}

type Runner interface {
	Run(context.Context, Target, string, []byte) ([]byte, error)
	Upload(context.Context, Target, string, []byte) error
}

type SSH struct{ KeyPath string }

func EnsureKey(path string) (string, error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return "", err
		}
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return "", err
		}
		der, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return "", err
		}
		b := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		if err := os.WriteFile(path, b, 0600); err != nil {
			return "", err
		}
		_ = pub
	}
	if err := os.Chmod(path, 0600); err != nil {
		return "", err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	signer, err := ssh.ParsePrivateKey(b)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))), nil
}

func (s SSH) signer() (ssh.Signer, error) {
	b, err := os.ReadFile(s.KeyPath)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(b)
}

func (s SSH) connect(ctx context.Context, t Target, auth []ssh.AuthMethod) (*ssh.Client, string, error) {
	if t.Port == 0 {
		t.Port = 22
	}
	if t.User == "" {
		t.User = "root"
	}
	var found string
	conf := &ssh.ClientConfig{User: t.User, Auth: auth, Timeout: 10 * time.Second, HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		found = ssh.FingerprintSHA256(key)
		if t.Fingerprint != "" && t.Fingerprint != found {
			return fmt.Errorf("SSH host fingerprint changed: expected %s, received %s", t.Fingerprint, found)
		}
		return nil
	}}
	addr := net.JoinHostPort(t.Host, fmt.Sprint(t.Port))
	conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, "", err
	}
	c, channels, requests, err := ssh.NewClientConn(conn, addr, conf)
	if err != nil {
		conn.Close()
		return nil, "", err
	}
	return ssh.NewClient(c, channels, requests), found, nil
}

func (s SSH) Bootstrap(ctx context.Context, t Target, password string) (string, error) {
	if password == "" {
		return "", errors.New("SSH password required")
	}
	pub, err := EnsureKey(s.KeyPath)
	if err != nil {
		return "", err
	}
	client, fp, err := s.connect(ctx, t, []ssh.AuthMethod{ssh.Password(password)})
	if err != nil {
		return "", err
	}
	defer client.Close()
	if strings.ContainsAny(pub, "'\n\r") {
		return "", errors.New("invalid generated public key")
	}
	cmd := fmt.Sprintf("umask 077; mkdir -p /root/.ssh; touch /root/.ssh/authorized_keys; grep -qxF '%s' /root/.ssh/authorized_keys || printf '%%s\\n' '%s' >> /root/.ssh/authorized_keys; chmod 700 /root/.ssh; chmod 600 /root/.ssh/authorized_keys", pub, pub)
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()
	if out, err := session.CombinedOutput(cmd); err != nil {
		return "", fmt.Errorf("SSH bootstrap: %w: %s", err, string(out))
	}
	return fp, nil
}

func (s SSH) Run(ctx context.Context, t Target, command string, input []byte) ([]byte, error) {
	signer, err := s.signer()
	if err != nil {
		return nil, err
	}
	client, _, err := s.connect(ctx, t, []ssh.AuthMethod{ssh.PublicKeys(signer)})
	if err != nil {
		return nil, err
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()
	if input != nil {
		session.Stdin = bytes.NewReader(input)
	}
	var out bytes.Buffer
	session.Stdout = &limitedWriter{w: &out, n: 2 << 20}
	session.Stderr = &limitedWriter{w: &out, n: 2 << 20}
	done := make(chan error, 1)
	go func() { done <- session.Run(command) }()
	select {
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGKILL)
		return nil, ctx.Err()
	case err := <-done:
		if err != nil {
			return out.Bytes(), fmt.Errorf("remote operation failed: %w", err)
		}
		return out.Bytes(), nil
	}
}

func (s SSH) Upload(ctx context.Context, t Target, path string, data []byte) error {
	if path != "/usr/local/bin/wdtt-panel" {
		return errors.New("upload path denied")
	}
	_, err := s.Run(ctx, t, "umask 077; cat > /usr/local/bin/wdtt-panel.new && chmod 0755 /usr/local/bin/wdtt-panel.new && mv /usr/local/bin/wdtt-panel.new /usr/local/bin/wdtt-panel", data)
	return err
}

type limitedWriter struct {
	w io.Writer
	n int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if len(p) > l.n {
		return 0, errors.New("remote output limit")
	}
	n, err := l.w.Write(p)
	l.n -= n
	return n, err
}
