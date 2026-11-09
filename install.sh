#!/usr/bin/env bash
# WDTT Router installer: install | update | rollback | uninstall [--purge]
# Run on the entry server (the one that hosts the panel).
set -Eeuo pipefail

REPO=Jetvac/wdtt-router
BIN=/usr/local/bin/wdtt-router
UNIT=/etc/systemd/system/wdtt-router.service
DATA=/var/lib/wdtt-router/panel
BACKUPS=/var/lib/wdtt-router/backups
PORT=8443
MODE=install
VERSION=latest
PUBLIC_HOST=
PURGE=0
tmp=
stopped=0
backup=

# Releases are signed: SHA256SUMS.sig is an Ed25519 signature of SHA256SUMS
# made with the project's release key. A download whose signature does not
# match this key is refused, even if it comes from the expected URL.
RELEASE_PUBKEY='-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAfjR2SyY3AWyr2woh/LnVklQ73lKJ/9F4QGjYvV4THHI=
-----END PUBLIC KEY-----'

log() { printf '\033[1;34m•\033[0m %s\n' "$*"; }
die() { printf '\033[1;31mОшибка:\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'USAGE'
Использование:
  install.sh install  --public-host IP [--port 8443] [--version vX.Y.Z]
  install.sh update   [--version vX.Y.Z]
  install.sh rollback
  install.sh uninstall [--purge]

install    ставит панель на этот сервер и один раз выводит логин и пароль.
update     обновляет бинарный файл; при ошибке запуска возвращает прежнюю версию.
rollback   возвращает версию, сохранённую перед последним обновлением.
uninstall  удаляет панель; настройки серверов и состояние сохраняются.
           С --purge удаляет также базу панели и все компоненты с этого сервера
           (Mesh, звено цепочки, firewall, WDTT, 3x-ui, установленные панелью).

Переменная WDTT_ROUTER_ARTIFACT_DIR позволяет установить из локального каталога
с архивом wdtt-router-linux-<arch>.tar.gz, SHA256SUMS и SHA256SUMS.sig.
Подпись релиза проверяется всегда; WDTT_ROUTER_ALLOW_UNSIGNED=1 разрешает
неподписанную сборку (только для собственных тестовых сборок).
USAGE
}

cleanup() {
  local rc=$?
  [[ -n $tmp ]] && rm -rf -- "$tmp"
  if [[ $rc -ne 0 && $stopped -eq 1 && -n $backup && -f $backup/wdtt-router ]]; then
    log "Возвращаю предыдущую версию"
    install -m 0755 "$backup/wdtt-router" "$BIN"
    [[ -f $backup/state.db ]] && cp -p "$backup"/state.db* "$DATA"/ 2>/dev/null || true
    systemctl start wdtt-router.service || true
  fi
}
trap cleanup EXIT

if [[ $# -gt 0 && $1 != --* ]]; then MODE=$1; shift; fi
while [[ $# -gt 0 ]]; do
  case "$1" in
    --port) PORT=${2:?}; shift 2 ;;
    --public-host) PUBLIC_HOST=${2:?}; shift 2 ;;
    --version) VERSION=${2:?}; shift 2 ;;
    --purge) PURGE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "неизвестный параметр $1" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "запустите от root"
command -v systemctl >/dev/null || die "нужен systemd"
[[ $PORT =~ ^[0-9]+$ && $PORT -ge 1 && $PORT -le 65535 ]] || die "некорректный порт"

arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo amd64 ;;
    aarch64|arm64) echo arm64 ;;
    *) die "архитектура $(uname -m) не поддерживается" ;;
  esac
}

# fetch downloads and verifies the release archive, leaving the binary in $tmp.
fetch() {
  local a name base
  a=$(arch)
  name="wdtt-router-linux-$a.tar.gz"
  tmp=$(mktemp -d)
  if [[ -n ${WDTT_ROUTER_ARTIFACT_DIR:-} ]]; then
    cp "$WDTT_ROUTER_ARTIFACT_DIR/$name" "$WDTT_ROUTER_ARTIFACT_DIR/SHA256SUMS" "$tmp/"
    cp "$WDTT_ROUTER_ARTIFACT_DIR/SHA256SUMS.sig" "$tmp/" 2>/dev/null || true
  else
    command -v curl >/dev/null || { apt-get update -qq && apt-get install -y -qq curl ca-certificates; }
    if [[ $VERSION == latest ]]; then
      base="https://github.com/$REPO/releases/latest/download"
    else
      base="https://github.com/$REPO/releases/download/$VERSION"
    fi
    log "Загружаю $name ($VERSION)"
    curl -fsSL --retry 3 -o "$tmp/$name" "$base/$name"
    curl -fsSL --retry 3 -o "$tmp/SHA256SUMS" "$base/SHA256SUMS"
    curl -fsSL --retry 3 -o "$tmp/SHA256SUMS.sig" "$base/SHA256SUMS.sig" || true
  fi
  verify_signature
  (cd "$tmp" && grep -E "^[0-9a-f]{64} [ *]$name\$" SHA256SUMS | sha256sum -c --quiet -) || die "контрольная сумма архива не совпала"
  tar -xzf "$tmp/$name" -C "$tmp" wdtt-router
  chmod 0755 "$tmp/wdtt-router"
  "$tmp/wdtt-router" version >/dev/null || die "загруженный файл не запускается"
}

verify_signature() {
  if [[ ! -s $tmp/SHA256SUMS.sig ]]; then
    [[ ${WDTT_ROUTER_ALLOW_UNSIGNED:-} == 1 ]] && { log "ВНИМАНИЕ: сборка без подписи (WDTT_ROUTER_ALLOW_UNSIGNED=1)"; return; }
    die "у релиза нет подписи SHA256SUMS.sig — установка отменена"
  fi
  command -v openssl >/dev/null || { apt-get update -qq && apt-get install -y -qq openssl; }
  printf '%s\n' "$RELEASE_PUBKEY" >"$tmp/release.pub"
  openssl pkeyutl -verify -pubin -inkey "$tmp/release.pub" -rawin -in "$tmp/SHA256SUMS" -sigfile "$tmp/SHA256SUMS.sig" >/dev/null 2>&1 \
    || die "подпись релиза не совпала с ключом проекта — установка отменена"
  log "Подпись релиза проверена"
}

write_unit() {
  cat >"$UNIT" <<EOF
[Unit]
Description=WDTT Router panel
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$BIN serve --listen :$PORT
Restart=always
RestartSec=3
LimitNOFILE=65535
# The panel manages firewall, routing and services, so it runs as root;
# its state is still kept private.
UMask=0077

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
}

wait_up() {
  for _ in $(seq 1 20); do
    systemctl is-active --quiet wdtt-router.service && curl -sk -o /dev/null "https://127.0.0.1:$PORT/" && return 0
    sleep 1
  done
  journalctl -u wdtt-router -n 20 --no-pager >&2 || true
  return 1
}

guess_ip() {
  ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}'
}

# Keep a copy of the installer for rollbacks from the panel (not when the
# script is piped into bash).
if [[ $MODE == install || $MODE == update ]] && [[ -f ${BASH_SOURCE[0]:-} ]]; then
  mkdir -p /var/lib/wdtt-router && install -m 0700 "${BASH_SOURCE[0]}" /var/lib/wdtt-router/install.sh 2>/dev/null || true
fi

case "$MODE" in
  install)
    if [[ -x $BIN && -f $DATA/state.db ]]; then
      die "панель уже установлена; используйте update"
    fi
    [[ -n $PUBLIC_HOST ]] || PUBLIC_HOST=$(guess_ip)
    [[ -n $PUBLIC_HOST ]] || die "укажите --public-host"
    # Read in a subshell: os-release defines VERSION, NAME and others that
    # would overwrite the installer's own variables.
    os_ids=" $( . /etc/os-release && echo "${ID:-} ${ID_LIKE:-}" ) "
    [[ $os_ids == *" debian "* || $os_ids == *" ubuntu "* ]] || die "поддерживаются Debian и Ubuntu"
    fetch
    install -m 0755 "$tmp/wdtt-router" "$BIN"
    out=$("$BIN" init --public-host "$PUBLIC_HOST" --port "$PORT")
    write_unit
    systemctl enable --now wdtt-router.service >/dev/null
    wait_up || die "панель не запустилась"
    echo
    echo "$out"
    echo
    echo "Сверьте отпечаток сертификата при первом входе в браузере."
    ;;
  update)
    [[ -x $BIN ]] || die "панель не установлена"
    fetch
    old=$("$BIN" version) new=$("$tmp/wdtt-router" version)
    log "Текущая версия $old, новая $new"
    backup="$BACKUPS/$(date +%Y%m%d-%H%M%S)-$old"
    mkdir -p "$backup" && chmod 700 "$BACKUPS" "$backup"
    cp -p "$BIN" "$backup/wdtt-router"
    systemctl stop wdtt-router.service
    stopped=1
    cp -p "$DATA"/state.db* "$backup/" 2>/dev/null || true
    cp -p "$DATA/master.key" "$backup/" 2>/dev/null || true
    install -m 0755 "$tmp/wdtt-router" "$BIN.new" && mv -f "$BIN.new" "$BIN"
    systemctl start wdtt-router.service
    wait_up || die "новая версия не запустилась"
    stopped=0
    ln -sfn "$backup" "$BACKUPS/last"
    log "Обновлено до $new. Агенты на серверах обновятся при следующем применении настроек."
    ;;
  rollback)
    [[ -L $BACKUPS/last && -f $BACKUPS/last/wdtt-router ]] || die "нет сохранённой версии"
    systemctl stop wdtt-router.service
    install -m 0755 "$BACKUPS/last/wdtt-router" "$BIN"
    [[ -f $BACKUPS/last/state.db ]] && cp -p "$BACKUPS"/last/state.db* "$DATA"/
    systemctl start wdtt-router.service
    wait_up || die "панель не запустилась после отката"
    log "Возвращена версия $("$BIN" version)"
    ;;
  uninstall)
    systemctl disable --now wdtt-router.service 2>/dev/null || true
    rm -f "$UNIT"
    systemctl daemon-reload
    if [[ $PURGE -eq 1 ]]; then
      read -r -p "Удалить базу панели и все компоненты с этого сервера? Введите DELETE: " ans
      [[ $ans == DELETE ]] || die "отменено"
      [[ -x $BIN ]] && "$BIN" agent uninstall --purge || true
      rm -rf "$DATA" "$BACKUPS"
      rm -f "$BIN"
      log "Панель и компоненты удалены. Mesh-узлы в Cloudflare и другие серверы не затронуты — удалите их в панели до uninstall."
    else
      log "Панель остановлена и удалена; данные сохранены в $DATA"
    fi
    ;;
  *) usage >&2; exit 2 ;;
esac
