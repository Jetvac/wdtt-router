package node

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

const recoveryDir = "/var/lib/wdtt-panel/recovery"

var recoveryIDPattern = regexp.MustCompile(`^[a-f0-9]{24}$`)

type recoverySnapshot struct {
	Kind      string          `json:"kind"`
	Previous  json.RawMessage `json:"previous"`
	CreatedAt string          `json:"created_at"`
}

func beginRecovery(ctx context.Context, kind string, previous []byte) (string, error) {
	if err := os.MkdirAll(recoveryDir, 0700); err != nil {
		return "", err
	}
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	id := hex.EncodeToString(b)
	s := recoverySnapshot{Kind: kind, Previous: previous, CreatedAt: time.Now().UTC().Format(time.RFC3339)}
	data, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(recoveryDir, id+".json"), data, 0600); err != nil {
		return "", err
	}
	unit := "wdtt-panel-recover-" + id
	if err := run(ctx, "systemd-run", "--quiet", "--unit="+unit, "--on-active=180s", "/usr/local/bin/wdtt-panel", "node", "recover", id); err != nil {
		_ = os.Remove(filepath.Join(recoveryDir, id+".json"))
		return "", fmt.Errorf("cannot schedule independent recovery: %w", err)
	}
	return id, nil
}

func CommitRecovery(ctx context.Context, id string) error {
	if !recoveryIDPattern.MatchString(id) {
		return errors.New("invalid recovery ID")
	}
	unit := "wdtt-panel-recover-" + id + ".timer"
	if err := run(ctx, "systemctl", "stop", unit); err != nil {
		return err
	}
	return os.Remove(filepath.Join(recoveryDir, id+".json"))
}

func Recover(ctx context.Context, id string) error {
	if !recoveryIDPattern.MatchString(id) {
		return errors.New("invalid recovery ID")
	}
	b, err := os.ReadFile(filepath.Join(recoveryDir, id+".json"))
	if err != nil {
		return err
	}
	var s recoverySnapshot
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	switch s.Kind {
	case "routing":
		var previous MeshConfig
		if len(s.Previous) > 0 {
			if err := json.Unmarshal(s.Previous, &previous); err != nil {
				return err
			}
		}
		if err := applyRoutingRaw(ctx, previous); err != nil {
			return err
		}
		if len(s.Previous) == 0 {
			_ = os.Remove("/etc/wdtt-panel/routing.json")
		} else {
			_ = os.WriteFile("/etc/wdtt-panel/routing.json", s.Previous, 0600)
		}
	case "firewall":
		var previous FirewallConfig
		if len(s.Previous) > 0 {
			if err := json.Unmarshal(s.Previous, &previous); err != nil {
				return err
			}
		}
		if err := applyFirewallRaw(ctx, previous); err != nil {
			return err
		}
		if len(s.Previous) == 0 {
			_ = os.Remove("/etc/wdtt-panel/firewall.json")
		} else {
			_ = os.WriteFile("/etc/wdtt-panel/firewall.json", s.Previous, 0600)
		}
	case "mesh":
		if len(s.Previous) == 0 {
			if err := removeOwnedMesh(ctx); err != nil {
				return err
			}
		}
	case "vless-client":
		if err := removeVLESSClient(ctx); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	default:
		return errors.New("unknown recovery kind")
	}
	return nil
}
