package agent

import (
	"context"
	"encoding/json"
	"os"
	"strings"

	"github.com/Jetvac/wdtt-router/internal/spec"
)

const (
	botUnit     = "wdtt-router-bot.service"
	botConfig   = EtcDir + "/bot.json"
	botStateDir = "/var/lib/wdtt-router-bot"
)

// The bot only makes outbound HTTPS requests: no capabilities, read-only
// system, its own state directory.
const botUnitText = `[Unit]
Description=WDTT Router: Telegram bot
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/wdtt-router telegram-bot --config ` + botConfig + `
Restart=always
RestartSec=5
StateDirectory=wdtt-router-bot
CapabilityBoundingSet=
AmbientCapabilities=
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
`

func reconcileBot(ctx context.Context, b *spec.BotSpec, changed *[]string) error {
	if b == nil {
		if removeUnit(ctx, botUnit) {
			*changed = append(*changed, "bot: removed")
		}
		removeIfExists(botConfig, VarDir+"/bot.version")
		return nil
	}
	cfg, _ := json.MarshalIndent(struct {
		spec.BotSpec
		StateDir string `json:"state_dir"`
	}{*b, botStateDir}, "", " ")
	cfgChanged, err := writeIfChanged(botConfig, append(cfg, '\n'), 0600)
	if err != nil {
		return err
	}
	unitChanged, err := installUnit(ctx, botUnit, botUnitText)
	if err != nil {
		return err
	}
	// The binary changes on every panel update; restart to run the new one.
	marker := VarDir + "/bot.version"
	old, _ := os.ReadFile(marker)
	if cfgChanged || unitChanged || strings.TrimSpace(string(old)) != Version || unitState(botUnit) != "active" {
		if err := systemctl(ctx, "restart", botUnit); err != nil {
			return err
		}
		_ = os.WriteFile(marker, []byte(Version+"\n"), 0600)
		*changed = append(*changed, "bot: started")
	}
	return nil
}
