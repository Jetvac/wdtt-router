#!/usr/bin/env bash
set -Eeuo pipefail

APP=wdtt-panel
REPO=Jetvac/wdtt-router
BIN=/usr/local/bin/wdtt-panel
UNIT=/etc/systemd/system/wdtt-panel.service
DATA_DIR=/var/lib/wdtt-panel
PORT=8443
MODE=install
PURGE=0
PUBLIC_HOST=
UPDATE_STOPPED=0
BACKUP_DIR=
tmp=

cleanup() {
  local rc=$?
  if [[ -n $tmp ]]; then rm -rf -- "$tmp"; fi
  if [[ $rc -ne 0 && $UPDATE_STOPPED -eq 1 ]]; then
    if [[ -f ${BIN}.previous ]]; then
      cp -p -- "${BIN}.previous" "${BIN}.rollback"
      mv -f -- "${BIN}.rollback" "$BIN"
    fi
    if [[ -n $BACKUP_DIR && -d $BACKUP_DIR ]]; then
      rm -f -- "$DATA_DIR/state.db" "$DATA_DIR/state.db-wal" "$DATA_DIR/state.db-shm"
      for name in state.db state.db-wal state.db-shm master.key; do
        if [[ -f $BACKUP_DIR/$name ]]; then cp -p -- "$BACKUP_DIR/$name" "$DATA_DIR/$name"; fi
      done
      if [[ -f $BACKUP_DIR/wdtt-panel.service ]]; then
        cp -p -- "$BACKUP_DIR/wdtt-panel.service" "$UNIT"
        systemctl daemon-reload >/dev/null 2>&1 || true
      fi
    fi
    systemctl start wdtt-panel.service >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

usage() {
  cat <<'USAGE'
Usage: install.sh [install|update|rollback|repair|uninstall] [--port PORT] [--public-host IP_OR_DNS] [--purge]

The first install prints one-time login credentials. Updates back up the old
binary and keep data in /var/lib/wdtt-panel. Uninstall keeps data unless --purge.
USAGE
}

if [[ $# -gt 0 && $1 != --* ]]; then MODE=$1; shift; fi
while [[ $# -gt 0 ]]; do
  case "$1" in
    --port) PORT=${2:?missing port}; shift 2 ;;
    --public-host) PUBLIC_HOST=${2:?missing host}; shift 2 ;;
    --purge) PURGE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ $EUID -eq 0 ]] || { echo 'Run as root.' >&2; exit 1; }
[[ $PORT =~ ^[0-9]+$ && $PORT -ge 1 && $PORT -le 65535 ]] || { echo 'Invalid port.' >&2; exit 2; }
case "$MODE" in install|update|rollback|repair|uninstall) ;; *) usage >&2; exit 2 ;; esac

if [[ $MODE == install && -f $DATA_DIR/state.db ]]; then MODE=update; fi
if [[ $MODE == update && ! -f $DATA_DIR/state.db ]]; then
  echo 'Panel state missing. Run install for a first installation.' >&2
  exit 1
fi

if [[ $MODE == uninstall ]]; then
  systemctl disable --now wdtt-panel.service 2>/dev/null || true
  rm -f -- "$UNIT" "$BIN"
  systemctl daemon-reload
  if [[ $PURGE -eq 1 ]]; then
    read -r -p 'Delete all panel state and saved secrets? Type DELETE: ' answer
    [[ $answer == DELETE ]] || { echo 'State preserved.'; exit 1; }
    rm -rf -- "$DATA_DIR"
  fi
  echo 'WDTT panel uninstalled. WDTT, Mesh, 3x-ui, and node state were not changed.'
  exit 0
fi

restore_panel_state() {
  local source=$1 name
  rm -f -- "$DATA_DIR/state.db" "$DATA_DIR/state.db-wal" "$DATA_DIR/state.db-shm" || return
  for name in state.db state.db-wal state.db-shm master.key; do
    if [[ -f $source/$name ]]; then cp -p -- "$source/$name" "$DATA_DIR/$name" || return; fi
  done
  if [[ -f $source/wdtt-panel.service ]]; then
    cp -p -- "$source/wdtt-panel.service" "$UNIT" || return
  fi
}

if [[ $MODE == rollback ]]; then
  [[ -x ${BIN}.previous && -f $DATA_DIR/last-update-backup ]] || { echo 'No previous panel version is available.' >&2; exit 1; }
  IFS= read -r BACKUP_DIR < "$DATA_DIR/last-update-backup"
  case "$BACKUP_DIR" in "$DATA_DIR"/backups/*) ;; *) echo 'Invalid backup path.' >&2; exit 1 ;; esac
  [[ -f $BACKUP_DIR/state.db && -f $BACKUP_DIR/master.key && -f $BACKUP_DIR/wdtt-panel.service ]] || { echo 'Application backup is incomplete.' >&2; exit 1; }
  tmp=$(mktemp -d)
  install -m 0755 "$BIN" "$tmp/current-bin"
  for name in state.db state.db-wal state.db-shm master.key; do
    if [[ -f $DATA_DIR/$name ]]; then cp -p -- "$DATA_DIR/$name" "$tmp/$name"; fi
  done
  if [[ -f $UNIT ]]; then cp -p -- "$UNIT" "$tmp/wdtt-panel.service"; fi
  systemctl stop wdtt-panel.service
  if install -m 0755 "${BIN}.previous" "${BIN}.next" &&
     mv -f -- "${BIN}.next" "$BIN" &&
     restore_panel_state "$BACKUP_DIR" &&
     systemctl daemon-reload &&
     systemctl start wdtt-panel.service &&
     systemctl is-active --quiet wdtt-panel.service; then
    rm -f -- "$DATA_DIR/last-update-backup"
    echo "Panel rollback complete. Service: systemctl status wdtt-panel"
    exit 0
  fi
  install -m 0755 "$tmp/current-bin" "${BIN}.next"
  mv -f -- "${BIN}.next" "$BIN"
  restore_panel_state "$tmp"
  systemctl daemon-reload
  systemctl start wdtt-panel.service
  echo 'Rollback failed; current panel version restored.' >&2
  exit 1
fi

if [[ $MODE == repair ]]; then
  [[ -x $BIN ]] || { echo 'Panel binary missing. Run install or update.' >&2; exit 1; }
else
  [[ $(uname -s) == Linux ]] || { echo 'Linux is required.' >&2; exit 1; }
  source /etc/os-release
  case "${ID:-}" in ubuntu|debian) ;; *) echo 'Only Debian and Ubuntu are supported.' >&2; exit 1 ;; esac
  case "$(uname -m)" in x86_64) ARCH=amd64 ;; aarch64) ARCH=arm64 ;; *) echo 'Unsupported architecture.' >&2; exit 1 ;; esac
  command -v curl >/dev/null || { echo 'curl is required.' >&2; exit 1; }
  command -v sha256sum >/dev/null || { echo 'sha256sum is required.' >&2; exit 1; }
  command -v tar >/dev/null || { echo 'tar is required.' >&2; exit 1; }

  tmp=$(mktemp -d)
  asset="wdtt-panel-linux-${ARCH}.tar.gz"
  if [[ -n ${WDTT_PANEL_ARTIFACT_DIR:-} ]]; then
    cp -- "${WDTT_PANEL_ARTIFACT_DIR}/${asset}" "$tmp/$asset"
    cp -- "${WDTT_PANEL_ARTIFACT_DIR}/SHA256SUMS" "$tmp/SHA256SUMS"
  else
    base="https://github.com/${REPO}/releases/latest/download"
    curl --fail --location --silent --show-error --retry 3 "$base/$asset" -o "$tmp/$asset"
    curl --fail --location --silent --show-error --retry 3 "$base/SHA256SUMS" -o "$tmp/SHA256SUMS"
  fi
  (cd "$tmp" && grep -F "  $asset" SHA256SUMS | sha256sum -c -) || { echo 'Release checksum verification failed.' >&2; exit 1; }
  tar -xzf "$tmp/$asset" -C "$tmp" wdtt-panel
  [[ -x "$tmp/wdtt-panel" ]] || chmod 0755 "$tmp/wdtt-panel"
  "$tmp/wdtt-panel" version >/dev/null
  if [[ $MODE == update && -f $DATA_DIR/state.db ]]; then
    systemctl stop wdtt-panel.service 2>/dev/null || true
    UPDATE_STOPPED=1
    BACKUP_DIR="$DATA_DIR/backups/$(date -u +%Y%m%dT%H%M%SZ)"
    install -d -m 0700 "$BACKUP_DIR"
    for name in state.db state.db-wal state.db-shm master.key; do
      if [[ -f $DATA_DIR/$name ]]; then cp -p -- "$DATA_DIR/$name" "$BACKUP_DIR/$name"; fi
    done
    if [[ -f $UNIT ]]; then cp -p -- "$UNIT" "$BACKUP_DIR/wdtt-panel.service"; fi
  fi
  if [[ -f $BIN ]]; then cp -p -- "$BIN" "${BIN}.previous"; fi
  install -m 0755 "$tmp/wdtt-panel" "${BIN}.next"
  mv -f -- "${BIN}.next" "$BIN"
fi

install -d -m 0700 "$DATA_DIR"
chmod 0700 "$DATA_DIR"
if [[ -z $PUBLIC_HOST ]]; then
  PUBLIC_HOST=$(ip -4 route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}')
fi
[[ -n $PUBLIC_HOST ]] || { echo 'Could not detect a public host; use --public-host.' >&2; exit 1; }

if [[ $MODE == install && ! -e "$DATA_DIR/state.db" ]]; then
  "$BIN" init --data-dir "$DATA_DIR" --public-host "$PUBLIC_HOST"
fi

cat >"$UNIT" <<EOF
[Unit]
Description=WDTT Mesh Control Panel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart=$BIN serve --data-dir $DATA_DIR --listen :$PORT
Restart=on-failure
RestartSec=3
UMask=0077
NoNewPrivileges=true
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "$UNIT"
systemctl daemon-reload
systemctl enable --now wdtt-panel.service
systemctl restart wdtt-panel.service
if ! systemctl is-active --quiet wdtt-panel.service; then
  echo 'Panel failed to start; see systemctl status wdtt-panel.' >&2
  exit 1
fi
if [[ $MODE == update && -n $BACKUP_DIR ]]; then
  printf '%s\n' "$BACKUP_DIR" > "$DATA_DIR/last-update-backup"
  chmod 0600 "$DATA_DIR/last-update-backup"
fi
UPDATE_STOPPED=0
echo "Panel URL: https://${PUBLIC_HOST}:${PORT}/"
echo "Port: ${PORT}"
echo 'Certificate: self-signed; verify its fingerprint before accepting it in a browser.'
echo "Service: systemctl status wdtt-panel"
if [[ $MODE == update ]]; then echo "Previous binary: ${BIN}.previous"; echo "State backup: ${BACKUP_DIR:-none}"; fi
