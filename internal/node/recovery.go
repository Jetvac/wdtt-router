package node

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

const recoveryDir = "/var/lib/wdtt-panel/recovery"
const snapshotDir = "/var/lib/wdtt-panel/snapshots"

var recoveryIDPattern = regexp.MustCompile(`^[a-f0-9]{24}$`)

type recoverySnapshot struct {
	Kind        string          `json:"kind"`
	Previous    json.RawMessage `json:"previous"`
	Current     json.RawMessage `json:"current,omitempty"`
	CreatedAt   string          `json:"created_at"`
	CommittedAt string          `json:"committed_at,omitempty"`
}

func (s recoverySnapshot) hasPrevious() bool {
	return len(s.Previous) > 0 && string(s.Previous) != "null"
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
	path := filepath.Join(recoveryDir, id+".json")
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var s recoverySnapshot
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	unit := "wdtt-panel-recover-" + id + ".timer"
	if err := run(ctx, "systemctl", "stop", unit); err != nil {
		return err
	}
	if s.Kind != "routing" && s.Kind != "firewall" {
		return os.Remove(path)
	}
	currentPath := "/etc/wdtt-panel/routing.json"
	if s.Kind == "firewall" {
		currentPath = "/etc/wdtt-panel/firewall.json"
	}
	s.Current, err = os.ReadFile(currentPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	s.CommittedAt = time.Now().UTC().Format(time.RFC3339)
	archive, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(snapshotDir, 0700); err != nil {
		return err
	}
	archivePath := filepath.Join(snapshotDir, id+".json")
	tmpPath := archivePath + ".tmp"
	if err := os.WriteFile(tmpPath, archive, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, archivePath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return os.Remove(path)
}

// RestoreSnapshot starts a fresh independent timer before changing panel-owned
// routes or firewall rules. The old committed snapshot remains available.
func RestoreSnapshot(ctx context.Context, snapshotID, managementIP string) (Result, error) {
	if !recoveryIDPattern.MatchString(snapshotID) {
		return Result{}, errors.New("invalid snapshot ID")
	}
	b, err := os.ReadFile(filepath.Join(snapshotDir, snapshotID+".json"))
	if err != nil {
		return Result{}, err
	}
	var s recoverySnapshot
	if err := json.Unmarshal(b, &s); err != nil {
		return Result{}, err
	}
	var path string
	var restore func() error
	switch s.Kind {
	case "routing":
		path = "/etc/wdtt-panel/routing.json"
		var desired MeshConfig
		if s.hasPrevious() {
			if err := json.Unmarshal(s.Previous, &desired); err != nil {
				return Result{}, err
			}
			if err := preflightRouting(ctx, desired); err != nil {
				return Result{}, err
			}
		}
		restore = func() error {
			if err := applyRoutingRaw(ctx, desired); err != nil {
				return err
			}
			if desired.Role != "" {
				return routingSelftest(ctx, desired)
			}
			return nil
		}
	case "firewall":
		path = "/etc/wdtt-panel/firewall.json"
		var desired FirewallConfig
		if s.hasPrevious() {
			if err := json.Unmarshal(s.Previous, &desired); err != nil {
				return Result{}, err
			}
		}
		desired.defaults()
		if err := desired.validate(); err != nil {
			return Result{}, err
		}
		if desired.RestrictSSH {
			_, allowed, _ := net.ParseCIDR(desired.ManagementCIDR)
			if !allowed.Contains(net.ParseIP(managementIP)) {
				return Result{}, errors.New("saved firewall would exclude your current address")
			}
		}
		restore = func() error { return applyFirewallRaw(ctx, desired) }
	default:
		return Result{}, errors.New("snapshot is not a routing or firewall change")
	}
	current, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return Result{}, err
	}
	id, err := beginRecovery(ctx, s.Kind, current)
	if err != nil {
		return Result{}, err
	}
	if err := restore(); err != nil {
		_ = Recover(ctx, id)
		return Result{}, err
	}
	if s.hasPrevious() {
		err = os.WriteFile(path, s.Previous, 0600)
	} else {
		err = os.Remove(path)
		if errors.Is(err, os.ErrNotExist) {
			err = nil
		}
	}
	if err != nil {
		_ = Recover(ctx, id)
		return Result{}, err
	}
	return Result{Message: "Panel-owned " + s.Kind + " snapshot restored; recovery timer awaits management check", RecoveryID: id}, nil
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
		if s.hasPrevious() {
			if err := json.Unmarshal(s.Previous, &previous); err != nil {
				return err
			}
		}
		if err := applyRoutingRaw(ctx, previous); err != nil {
			return err
		}
		if !s.hasPrevious() {
			_ = os.Remove("/etc/wdtt-panel/routing.json")
		} else {
			_ = os.WriteFile("/etc/wdtt-panel/routing.json", s.Previous, 0600)
		}
	case "firewall":
		var previous FirewallConfig
		if s.hasPrevious() {
			if err := json.Unmarshal(s.Previous, &previous); err != nil {
				return err
			}
		}
		if err := applyFirewallRaw(ctx, previous); err != nil {
			return err
		}
		if !s.hasPrevious() {
			_ = os.Remove("/etc/wdtt-panel/firewall.json")
		} else {
			_ = os.WriteFile("/etc/wdtt-panel/firewall.json", s.Previous, 0600)
		}
	case "mesh":
		if !s.hasPrevious() {
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
