package desktop

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// Login is a one-time way in for a server that does not know the app's key
// yet. It is used once to add the key and is never stored.
type Login struct {
	Password   string
	Key        string // a private key in OpenSSH or PEM format
	Passphrase string
}

var (
	errAuth        = errors.New("сервер не принял ключ приложения")
	errHostChanged = errors.New("ключ SSH сервера изменился с прошлого подключения: если сервер не переустанавливали, кто-то может перехватывать соединение. Если переустанавливали — удалите сервер из списка и добавьте снова")
)

// dial connects to a server over SSH. A server seen for the first time is
// trusted and its host key returned for remembering; later the key must
// match.
func dial(ctx context.Context, srv Server, signer ssh.Signer, login *Login) (*ssh.Client, string, error) {
	var seen string
	methods := []ssh.AuthMethod{ssh.PublicKeys(signer)}
	if login != nil && login.Key != "" {
		var k ssh.Signer
		var err error
		if login.Passphrase != "" {
			k, err = ssh.ParsePrivateKeyWithPassphrase([]byte(login.Key), []byte(login.Passphrase))
		} else {
			k, err = ssh.ParsePrivateKey([]byte(login.Key))
		}
		var missing *ssh.PassphraseMissingError
		switch {
		case errors.As(err, &missing):
			return nil, "", errors.New("ключ защищён паролем — укажите его")
		case err != nil:
			return nil, "", fmt.Errorf("не удалось прочитать ключ: %w", err)
		}
		methods = append(methods, ssh.PublicKeys(k))
	}
	if login != nil && login.Password != "" {
		pw := login.Password
		methods = append(methods, ssh.Password(pw), ssh.KeyboardInteractive(func(_, _ string, qs []string, _ []bool) ([]string, error) {
			out := make([]string, len(qs))
			for i := range qs {
				out[i] = pw
			}
			return out, nil
		}))
	}
	cfg := &ssh.ClientConfig{
		User: srv.User,
		Auth: methods,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			seen = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
			if srv.HostKey != "" && srv.HostKey != seen {
				return errHostChanged
			}
			return nil
		},
		Timeout: 15 * time.Second,
	}
	addr := net.JoinHostPort(srv.Host, strconv.Itoa(srv.Port))
	d := net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	nc, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, "", fmt.Errorf("нет соединения с %s: %w", addr, err)
	}
	_ = nc.SetDeadline(time.Now().Add(30 * time.Second))
	c, chans, reqs, err := ssh.NewClientConn(nc, addr, cfg)
	if err != nil {
		nc.Close()
		switch {
		case errors.Is(err, errHostChanged):
			return nil, "", errHostChanged
		case strings.Contains(err.Error(), "unable to authenticate"):
			if login == nil {
				return nil, seen, errAuth
			}
			return nil, seen, errors.New("сервер не принял пароль или ключ")
		}
		return nil, "", fmt.Errorf("SSH: %w", err)
	}
	_ = nc.SetDeadline(time.Time{})
	return ssh.NewClient(c, chans, reqs), seen, nil
}

// run runs a command and returns its output; stderr goes into the error.
func run(ctx context.Context, c *ssh.Client, cmd string) (string, error) {
	var out, errb bytes.Buffer
	err := runWith(ctx, c, cmd, nil, &out, &errb)
	if err != nil {
		if msg := strings.TrimSpace(errb.String()); msg != "" {
			return out.String(), fmt.Errorf("%s", lastLines(msg, 3))
		}
		return out.String(), err
	}
	return out.String(), nil
}

func runWith(ctx context.Context, c *ssh.Client, cmd string, stdin []byte, stdout, stderr io.Writer) error {
	s, err := c.NewSession()
	if err != nil {
		return err
	}
	defer s.Close()
	s.Stdout, s.Stderr = stdout, stderr
	if stdin != nil {
		s.Stdin = bytes.NewReader(stdin)
	}
	done := make(chan error, 1)
	go func() { done <- s.Run(cmd) }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		_ = s.Signal(ssh.SIGTERM)
		s.Close()
		return ctx.Err()
	}
}

// stream runs a command with stdin and passes each output line (stdout and
// stderr) to line as it appears.
func stream(ctx context.Context, c *ssh.Client, cmd string, stdin []byte, line func(string)) error {
	pr, pw := io.Pipe()
	var mu sync.Mutex
	w := lockedWriter{w: pw, mu: &mu}
	go func() {
		sc := bufio.NewScanner(pr)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			line(cleanLine(sc.Text()))
		}
	}()
	err := runWith(ctx, c, cmd, stdin, w, w)
	pw.Close()
	return err
}

type lockedWriter struct {
	w  io.Writer
	mu *sync.Mutex
}

func (l lockedWriter) Write(b []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(b)
}

// cleanLine drops terminal colour codes from installer output.
func cleanLine(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && (s[j] < '@' || s[j] > '~') {
				j++
			}
			i = j
			continue
		}
		if s[i] == '\r' {
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " ")
}

// shellQuote quotes s for a POSIX shell.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
