#!/usr/bin/env bash
set -Eeuo pipefail

VERSION="0.3.0"
CONFIG_FILE="/etc/wdtt-mesh-egress.conf"
NODE_ENV_FILE="/etc/wdtt-mesh-node.env"
SYSTEMD_UNIT="/etc/systemd/system/wdtt-mesh-egress.service"
DE_WARP_WATCH_UNIT="/etc/systemd/system/wdtt-mesh-de-warp-routes.service"
XUI_RELAY_UNIT="/etc/systemd/system/wdtt-mesh-xui-relay.service"
STATE_DIR="/var/lib/wdtt-mesh-egress"
BACKUP_ROOT="${STATE_DIR}/backups"
LAST_BACKUP_FILE="${STATE_DIR}/last-backup"
XUI_ENV_FILE="/etc/wdtt-mesh-xui.env"


VLESS_CONTAINER="wdtt-mesh-vless"
VLESS_IMAGE="ghcr.io/xtls/xray-core:26.9.9"
VLESS_CONFIG_DIR="/etc/wdtt-mesh-vless"
VLESS_CONFIG_FILE="${VLESS_CONFIG_DIR}/config.json"
VLESS_UUID_FILE="${VLESS_CONFIG_DIR}/uuid"
VLESS_PORT="24443"
VLESS_UUID=""
VLESS_TAG="mesh-de"
VLESS_SEND_THROUGH="10.66.66.1"
VLESS_MESH_IP=""
VLESS_BACKEND="legacy"
XUI_VERSION="v3.8.5"
XUI_BIN="/usr/local/x-ui/x-ui"
XUI_SERVICE="x-ui.service"
XUI_INBOUND_REMARK="WDTT Mesh Internal"
XUI_INBOUND_ID=""
XUI_INBOUND_TAG=""
XUI_INBOUND_CREATED="0"
XUI_PANEL_INSTALLED_BY_SCRIPT="0"
XUI_ENABLE_ON_INSTALL="0"
XUI_API_BASE=""
XUI_API_TOKEN=""
XUI_PANEL_PORT=""
XUI_WEB_BASE_PATH=""
XUI_PANEL_SCHEME="http"
XUI_INPUT_COMMENT="WDTT_MESH_XUI_IN"
WDTT_DROPIN_DIR="/etc/systemd/system/wdtt.service.d"
WDTT_DROPIN_FILE="$WDTT_DROPIN_DIR/95-mesh-egress.conf"

CF_API_BASE="https://api.cloudflare.com/client/v4"
PROFILE_NAME="WDTT Mesh full-tunnel egress nodes"
LEGACY_PROFILE_NAME="WDTT Mesh egress nodes"
PROFILE_PRECEDENCE="90"
MESH_IMAGE="cloudflare/mesh:latest"
MESH_CONTAINER="cloudflare-mesh"
MESH_DOCKER_NETWORK="wdtt-mesh-net"
MESH_BRIDGE="wdttmesh0"
MESH_DOCKER_NET="172.31.255.0/29"
MESH_DOCKER_GW="172.31.255.1"
MESH_CONTAINER_IP="172.31.255.2"

ROLE=""
ACCOUNT_ID=""
TEAM_NAME=""
NODE_NAME=""
NODE_ID=""
ROUTE_ID=""
EXIT_ROUTE_ID=""
EXIT_ROUTE_ID_A=""
EXIT_ROUTE_ID_B=""
WDTT_ROUTE_ID=""
WDTT_IF="wdtt0"
WDTT_NET="10.66.66.0/24"
PROBE_IP="10.66.66.2"
ROUTE_TABLE="51889"
RULE_PREF="10667"
EXT_IF=""
DELETE_CLOUDFLARE="0"

CHAIN_MSK="WDTT_MESH_EGRESS"
CHAIN_DE="WDTT_MESH_DE"
COMMENT_MSK_OUT="WDTT_MESH_OUT"
COMMENT_MSK_IN="WDTT_MESH_IN"
COMMENT_DE="WDTT_MESH_DE_FWD"
COMMENT_DE_NAT="WDTT_MESH_DE_NAT"

log()  { printf '[wdtt-mesh] %s\n' "$*"; }
warn() { printf '[wdtt-mesh] WARNING: %s\n' "$*" >&2; }
die()  { printf '[wdtt-mesh] ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'USAGE'
WDTT selective Cloudflare Mesh egress router

Cloudflare Mesh replaces the MSK -> AmneziaWG/WireGuard -> DE transport.
DE advertises two public /1 routes; MSK keeps SRCNAT disabled to prevent local breakout.
DE also maintains explicit return routes for Mesh/WDTT sources inside the CloudflareWARP policy table.
Run install-de on the German VPS first, then install-msk on the Moscow VPS.

Required environment variable for install/uninstall --delete-cloudflare:
  CLOUDFLARE_API_TOKEN

Usage:
  wdtt-mesh-egress-router.sh install-de  --account-id ID --team-name TEAM [options]
  wdtt-mesh-egress-router.sh install-msk --account-id ID --team-name TEAM [options]
  wdtt-mesh-egress-router.sh apply
  wdtt-mesh-egress-router.sh status
  wdtt-mesh-egress-router.sh selftest
  wdtt-mesh-egress-router.sh profile
  wdtt-mesh-egress-router.sh enable-xui-egress
  wdtt-mesh-egress-router.sh rollback
  wdtt-mesh-egress-router.sh disable
  wdtt-mesh-egress-router.sh enable
  wdtt-mesh-egress-router.sh uninstall [--delete-cloudflare]

Common install options:
  --account-id ID          Cloudflare account ID (required)
  --team-name TEAM         Zero Trust team name; bare name or *.cloudflareaccess.com accepted (required)
  --node-name NAME         Mesh node name. Defaults: wdtt-de / wdtt-msk
  --wdtt-net CIDR          WDTT client network. Default: 10.66.66.0/24
  --mesh-image IMAGE       Cloudflare Mesh image. Default: cloudflare/mesh:latest

MSK options:
  --wdtt-if IFACE          WDTT interface. Default: wdtt0
  --probe-ip IPv4          Client address used for route checks. Default: 10.66.66.2
  --table NUMBER           Policy routing table. Default: 51889
  --rule-pref NUMBER       Policy rule priority. Default: 10667

DE options:
  --ext-if IFACE           Public egress interface. Auto-detected from main default route.
  --vless-port PORT        Internal VLESS port on the DE Mesh node. Default: 24443
  --vless-uuid UUID        Reuse a specific VLESS UUID. Otherwise generated once and persisted.
  --vless-image IMAGE      Xray image. Default: ghcr.io/xtls/xray-core:26.9.9
  --vless-tag TAG          3x-ui outbound tag. Default: mesh-de
  --vless-send-through IP  Source IP used by 3x-ui/Xray on MSK. Default: 10.66.66.1
  --xui-egress             After DE install, migrate private VLESS endpoint into local 3x-ui.
  --xui-version VERSION    3x-ui version for an automatic fresh install. Default: v3.8.5

Cloudflare requirements:
  API token permissions:
    - Cloudflare One Connectors Write
    - Cloudflare One Networks Write
    - Zero Trust Write

  One Cloudflare setting is currently human-only and cannot be changed via API:
    "Allow all Cloudflare One traffic to reach enrolled devices" must be enabled once
    in the Cloudflare dashboard (Networking -> Mesh setup / device client settings).

Important:
  The script creates/updates an account-wide Mesh-node device profile in Traffic-only
  + Exclude mode (full tunnel) with MASQUE. Only the local Docker bridge is excluded. Use a dedicated
  Zero Trust account for this WDTT egress
  if other Mesh nodes in the same account must NOT use the German exit route.

VLESS/3x-ui:
  DE always keeps a rollback-capable legacy private VLESS implementation.
  With --xui-egress (or enable-xui-egress later), the same Mesh endpoint is
  transparently relayed to a VLESS RAW/TCP inbound in local 3x-ui. 3x-ui then
  becomes the egress/routing engine. The relay adds no TLS/REALITY/encryption.
  Neither the VLESS port nor the 3x-ui panel is published on the DE public interface.
  At the end of install-de the script prints:
    1) a ready 3x-ui/Xray outbound JSON (recommended; includes sendThrough)
    2) a vless:// share link (credentials/transport only)
  Run "profile" on DE at any time to print them again.
USAGE
}

need_root() {
  [ "$(id -u)" -eq 0 ] || die "Run as root."
}

validate_integer() {
  local name="$1" value="$2"
  case "$value" in ''|*[!0-9]*) die "$name must be an integer: $value" ;; esac
  [ "$value" -ge 1 ] || die "$name must be greater than zero."
}

parse_install_options() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --account-id) [ "$#" -ge 2 ] || die "$1 requires a value"; ACCOUNT_ID="$2"; shift 2 ;;
      --team-name) [ "$#" -ge 2 ] || die "$1 requires a value"; TEAM_NAME="$2"; shift 2 ;;
      --node-name) [ "$#" -ge 2 ] || die "$1 requires a value"; NODE_NAME="$2"; shift 2 ;;
      --wdtt-if) [ "$#" -ge 2 ] || die "$1 requires a value"; WDTT_IF="$2"; shift 2 ;;
      --wdtt-net) [ "$#" -ge 2 ] || die "$1 requires a value"; WDTT_NET="$2"; shift 2 ;;
      --probe-ip) [ "$#" -ge 2 ] || die "$1 requires a value"; PROBE_IP="$2"; shift 2 ;;
      --table) [ "$#" -ge 2 ] || die "$1 requires a value"; ROUTE_TABLE="$2"; shift 2 ;;
      --rule-pref) [ "$#" -ge 2 ] || die "$1 requires a value"; RULE_PREF="$2"; shift 2 ;;
      --ext-if) [ "$#" -ge 2 ] || die "$1 requires a value"; EXT_IF="$2"; shift 2 ;;
      --mesh-image) [ "$#" -ge 2 ] || die "$1 requires a value"; MESH_IMAGE="$2"; shift 2 ;;
      --vless-port) [ "$#" -ge 2 ] || die "$1 requires a value"; VLESS_PORT="$2"; shift 2 ;;
      --vless-uuid) [ "$#" -ge 2 ] || die "$1 requires a value"; VLESS_UUID="$2"; shift 2 ;;
      --vless-image) [ "$#" -ge 2 ] || die "$1 requires a value"; VLESS_IMAGE="$2"; shift 2 ;;
      --vless-tag) [ "$#" -ge 2 ] || die "$1 requires a value"; VLESS_TAG="$2"; shift 2 ;;
      --vless-send-through) [ "$#" -ge 2 ] || die "$1 requires a value"; VLESS_SEND_THROUGH="$2"; shift 2 ;;
      --xui-egress) XUI_ENABLE_ON_INSTALL="1"; shift ;;
      --xui-version) [ "$#" -ge 2 ] || die "$1 requires a value"; XUI_VERSION="$2"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) die "Unknown option: $1" ;;
    esac
  done
}

normalize_team_name() {
  local original="$TEAM_NAME"
  TEAM_NAME="${TEAM_NAME#https://}"
  TEAM_NAME="${TEAM_NAME#http://}"
  TEAM_NAME="${TEAM_NAME%%/*}"
  TEAM_NAME="${TEAM_NAME%.cloudflareaccess.com}"
  TEAM_NAME="${TEAM_NAME%.cloudflareaccess.com.}"
  TEAM_NAME="${TEAM_NAME%.}"
  if [ "$TEAM_NAME" != "$original" ]; then
    log "Normalized Zero Trust team name: $original -> $TEAM_NAME"
  fi
}

validate_install_config() {
  [ -n "$ACCOUNT_ID" ] || die "--account-id is required."
  [ -n "$TEAM_NAME" ] || die "--team-name is required."
  normalize_team_name
  [ -n "$TEAM_NAME" ] || die "--team-name resolved to an empty value."
  [ -n "$NODE_NAME" ] || die "NODE_NAME is empty."
  [ -n "${CLOUDFLARE_API_TOKEN:-}" ] || die "CLOUDFLARE_API_TOKEN environment variable is required."
  validate_integer ROUTE_TABLE "$ROUTE_TABLE"
  validate_integer RULE_PREF "$RULE_PREF"
  validate_integer VLESS_PORT "$VLESS_PORT"
  [ "$VLESS_PORT" -le 65535 ] || die "--vless-port must be <= 65535."
  [[ "$VLESS_TAG" =~ ^[A-Za-z0-9._-]+$ ]] || die "--vless-tag may contain only letters, digits, dot, underscore and dash."
  [[ "$VLESS_SEND_THROUGH" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "--vless-send-through must be an IPv4 address."
  if [ -n "$VLESS_UUID" ]; then
    [[ "$VLESS_UUID" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]       || die "--vless-uuid must be a standard UUID."
  fi
  [ "$ROUTE_TABLE" -ne 253 ] && [ "$ROUTE_TABLE" -ne 254 ] && [ "$ROUTE_TABLE" -ne 255 ] || die "Do not use local/main/default routing tables."
  command -v curl >/dev/null 2>&1 || die "curl is required."
}

load_config() {
  [ -f "$CONFIG_FILE" ] || return 0
  # shellcheck disable=SC1090
  . "$CONFIG_FILE"
}

install_prereqs() {
  local missing="0" cmd
  for cmd in curl jq ip iptables sysctl systemctl nsenter; do
    command -v "$cmd" >/dev/null 2>&1 || missing="1"
  done
  if ! command -v docker >/dev/null 2>&1; then
    missing="1"
  fi
  [ "$missing" = "0" ] && return 0

  command -v apt-get >/dev/null 2>&1 || die "Automatic dependency install currently supports Debian/Ubuntu (apt). Install curl jq iproute2 iptables and Docker manually."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y ca-certificates curl jq iproute2 iptables util-linux docker.io
  systemctl enable --now docker
}

cf_api() {
  local method="$1" path="$2" body="${3:-}" response
  local -a args
  args=(--fail-with-body --silent --show-error
        --request "$method"
        --header "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}"
        --header "Content-Type: application/json")
  if [ -n "$body" ]; then
    args+=(--data "$body")
  fi
  if ! response="$(curl "${args[@]}" "${CF_API_BASE}/accounts/${ACCOUNT_ID}/${path}")"; then
    [ -n "$response" ] && printf '%s\n' "$response" >&2
    return 1
  fi
  jq -e '.success == true' >/dev/null <<<"$response" || {
    printf '%s\n' "$response" >&2
    return 1
  }
  printf '%s' "$response"
}

ensure_cf_account_settings() {
  local body
  body='{"use_zt_virtual_ip":true,"gateway_proxy_enabled":true,"gateway_udp_proxy_enabled":true}'
  cf_api PATCH "devices/settings" "$body" >/dev/null || die "Could not enable required Cloudflare device settings. Check Zero Trust Write permission."
  log "Cloudflare unique device IPs and TCP/UDP Gateway proxy are enabled."
}

ensure_cf_mesh_profile() {
  local profiles profile_id legacy_id match body excludes verify precedence candidate used

  profiles="$(cf_api GET "devices/policies")" || die "Could not list Cloudflare device profiles."
  match="identity.email == \"warp_connector@${TEAM_NAME}.cloudflareaccess.com\""
  excludes="$(jq -cn --arg net "$MESH_DOCKER_NET" \
    '[{address:$net,description:"Local Docker bridge for Mesh node"}]')"

  profile_id="$(jq -r --arg name "$PROFILE_NAME" \
    '.result[]? | select(.name == $name) | (.policy_id // .id // empty)' \
    <<<"$profiles" | head -n1)"

  legacy_id="$(jq -r --arg name "$LEGACY_PROFILE_NAME" \
    '.result[]? | select(.name == $name) | (.policy_id // .id // empty)' \
    <<<"$profiles" | head -n1)"

  # Prefer converting the profile created by v0.1.0-v0.1.4 in place. A disabled
  # custom profile still reserves its precedence in Cloudflare, so creating a
  # second profile with the same precedence returns API error 2070.
  if { [ -z "$profile_id" ] || [ "$profile_id" = "null" ]; } \
     && [ -n "$legacy_id" ] && [ "$legacy_id" != "null" ]; then
    profile_id="$legacy_id"
    precedence="$(jq -r --arg id "$profile_id" \
      '.result[]? | select((.policy_id // .id) == $id) | (.precedence // empty)' \
      <<<"$profiles" | head -n1)"
    [ -n "$precedence" ] && [ "$precedence" != "null" ] || precedence="$PROFILE_PRECEDENCE"

    # Clear the old Include-mode list before applying an Exclude-mode list.
    cf_api PUT "devices/policy/${profile_id}/include" '[]' >/dev/null \
      || die "Could not clear the legacy Split Tunnel include list."

    body="$(jq -cn \
      --arg name "$PROFILE_NAME" \
      --arg desc "Traffic-only full-tunnel MASQUE profile for WDTT Mesh German egress" \
      --arg match "$match" \
      --argjson precedence "$precedence" \
      '{name:$name,description:$desc,enabled:true,precedence:$precedence,match:$match,service_mode_v2:{mode:"warp_tunnel_only"},tunnel_protocol:"masque"}')"

    cf_api PATCH "devices/policy/${profile_id}" "$body" >/dev/null \
      || die "Could not convert the legacy Mesh profile to full-tunnel mode."

    cf_api PUT "devices/policy/${profile_id}/exclude" "$excludes" >/dev/null \
      || die "Could not set the Mesh node Split Tunnel exclude list."

    log "Converted legacy profile in place: $LEGACY_PROFILE_NAME -> $PROFILE_NAME ($profile_id, precedence $precedence)."
    log "Mesh-node profile uses MASQUE + Traffic-only + Exclude mode (full tunnel)."
    log "Only the local Docker bridge $MESH_DOCKER_NET bypasses Cloudflare."
    return 0
  fi

  if [ -n "$profile_id" ] && [ "$profile_id" != "null" ]; then
    precedence="$(jq -r --arg id "$profile_id" \
      '.result[]? | select((.policy_id // .id) == $id) | (.precedence // empty)' \
      <<<"$profiles" | head -n1)"
    [ -n "$precedence" ] && [ "$precedence" != "null" ] || precedence="$PROFILE_PRECEDENCE"

    # Ensure this profile is really Exclude mode even after upgrades/re-runs.
    cf_api PUT "devices/policy/${profile_id}/include" '[]' >/dev/null \
      || die "Could not clear the Split Tunnel include list."

    body="$(jq -cn \
      --arg desc "Traffic-only full-tunnel MASQUE profile for WDTT Mesh German egress" \
      --arg match "$match" \
      --argjson precedence "$precedence" \
      '{description:$desc,enabled:true,precedence:$precedence,match:$match,service_mode_v2:{mode:"warp_tunnel_only"},tunnel_protocol:"masque"}')"

    cf_api PATCH "devices/policy/${profile_id}" "$body" >/dev/null \
      || die "Could not update full-tunnel Mesh device profile."
    cf_api PUT "devices/policy/${profile_id}/exclude" "$excludes" >/dev/null \
      || die "Could not set the Mesh node Split Tunnel exclude list."

    log "Updated full-tunnel Cloudflare device profile: $PROFILE_NAME ($profile_id, precedence $precedence)."
  else
    # Pick a free positive precedence. Cloudflare requires custom-profile
    # precedence values to be unique even when another profile is disabled.
    used="$(jq -r '.result[]? | .precedence // empty' <<<"$profiles" | sort -n -u)"
    candidate="$PROFILE_PRECEDENCE"
    while grep -qx "$candidate" <<<"$used"; do
      candidate=$((candidate + 1))
    done
    precedence="$candidate"

    body="$(jq -cn \
      --arg name "$PROFILE_NAME" \
      --arg desc "Traffic-only full-tunnel MASQUE profile for WDTT Mesh German egress" \
      --arg match "$match" \
      --argjson precedence "$precedence" \
      --argjson exclude "$excludes" \
      '{name:$name,description:$desc,enabled:true,precedence:$precedence,match:$match,service_mode_v2:{mode:"warp_tunnel_only"},tunnel_protocol:"masque",exclude:$exclude}')"

    verify="$(cf_api POST "devices/policy" "$body")" \
      || die "Could not create the full-tunnel Mesh device profile."
    profile_id="$(jq -r '.result.policy_id // .result.id // empty' <<<"$verify")"
    [ -n "$profile_id" ] && [ "$profile_id" != "null" ] \
      || die "Cloudflare created the profile but did not return policy_id/id."

    cf_api PUT "devices/policy/${profile_id}/exclude" "$excludes" >/dev/null \
      || die "Could not set the Mesh node Split Tunnel exclude list."

    log "Created full-tunnel Cloudflare device profile: $PROFILE_NAME ($profile_id, precedence $precedence)."
  fi

  log "Mesh-node profile uses MASQUE + Traffic-only + Exclude mode (full tunnel)."
  log "Only the local Docker bridge $MESH_DOCKER_NET bypasses Cloudflare."
}
ensure_cf_node() {
  local list body created token_response
  list="$(cf_api GET "warp_connector")" || die "Could not list Cloudflare Mesh nodes."
  NODE_ID="$(jq -r --arg name "$NODE_NAME" '.result[]? | select(.name == $name and (.deleted_at == null or .deleted_at == "")) | .id' <<<"$list" | head -n1)"
  if [ -z "$NODE_ID" ]; then
    body="$(jq -cn --arg name "$NODE_NAME" '{name:$name,ha:false}')"
    created="$(cf_api POST "warp_connector" "$body")" || die "Could not create Cloudflare Mesh node $NODE_NAME."
    NODE_ID="$(jq -r '.result.id' <<<"$created")"
    [ -n "$NODE_ID" ] && [ "$NODE_ID" != "null" ] || die "Cloudflare did not return a node ID."
    log "Created Mesh node $NODE_NAME ($NODE_ID)."
  else
    log "Reusing Mesh node $NODE_NAME ($NODE_ID)."
  fi

  token_response="$(cf_api GET "warp_connector/${NODE_ID}/token")" || die "Could not obtain token for Mesh node $NODE_NAME."
  MESH_NODE_TOKEN="$(jq -er '.result | select(type == "string" and length > 0)' <<<"$token_response")" || die "Cloudflare returned an empty Mesh node token."
}

remove_cf_route_by_network_if_owned() {
  local network="$1" list entry rid owner
  list="$(cf_api GET "teamnet/routes")" || die "Could not list Cloudflare network routes."
  entry="$(jq -c --arg network "$network" '.result[]? | select(.network == $network and (.deleted_at == null or .deleted_at == ""))' <<<"$list" | head -n1)"
  [ -n "$entry" ] || return 0

  rid="$(jq -r '.id // empty' <<<"$entry")"
  owner="$(jq -r '.tunnel_id // empty' <<<"$entry")"
  [ -n "$rid" ] || return 0

  if [ "$owner" = "$NODE_ID" ]; then
    cf_api DELETE "teamnet/routes/${rid}" >/dev/null || die "Could not remove legacy Cloudflare route $network."
    log "Removed legacy Cloudflare route $network from $NODE_NAME ($rid)."
  else
    warn "Route $network belongs to another connector ($owner); leaving it untouched."
  fi
}

ensure_cf_route() {
  local network="$1" comment="$2" list existing existing_tunnel body created
  list="$(cf_api GET "teamnet/routes")" || die "Could not list Cloudflare network routes."
  existing="$(jq -c --arg network "$network" '.result[]? | select(.network == $network and (.deleted_at == null or .deleted_at == ""))' <<<"$list" | head -n1)"
  if [ -n "$existing" ]; then
    existing_tunnel="$(jq -r '.tunnel_id' <<<"$existing")"
    if [ "$existing_tunnel" != "$NODE_ID" ]; then
      die "Cloudflare route $network already belongs to another connector ($existing_tunnel). Remove it or use a dedicated Zero Trust account."
    fi
    ROUTE_ID="$(jq -r '.id' <<<"$existing")"
    log "Reusing Cloudflare route $network -> $NODE_NAME ($ROUTE_ID)."
    return 0
  fi

  body="$(jq -cn --arg network "$network" --arg tunnel "$NODE_ID" --arg comment "$comment" '{network:$network,tunnel_id:$tunnel,comment:$comment}')"
  created="$(cf_api POST "teamnet/routes" "$body")" || die "Could not create Cloudflare route $network -> $NODE_NAME."
  ROUTE_ID="$(jq -r '.result.id' <<<"$created")"
  [ -n "$ROUTE_ID" ] && [ "$ROUTE_ID" != "null" ] || die "Cloudflare did not return a route ID for $network."
  log "Created Cloudflare route $network -> $NODE_NAME ($ROUTE_ID)."
}

write_node_env() {
  local srcnat="$1"
  umask 077
  cat >"$NODE_ENV_FILE" <<EOF_ENV
MESH_NODE_TOKEN=${MESH_NODE_TOKEN}
SRCNAT_ENABLED=${srcnat}
EOF_ENV
  chmod 600 "$NODE_ENV_FILE"
}


ensure_vless_credentials() {
  mkdir -p "$VLESS_CONFIG_DIR"
  chmod 755 "$VLESS_CONFIG_DIR"

  if [ -n "$VLESS_UUID" ]; then
    printf '%s\n' "$VLESS_UUID" >"$VLESS_UUID_FILE"
  elif [ -s "$VLESS_UUID_FILE" ]; then
    VLESS_UUID="$(tr -d '\r\n' <"$VLESS_UUID_FILE")"
  else
    [ -r /proc/sys/kernel/random/uuid ] || die "Cannot generate VLESS UUID."
    VLESS_UUID="$(cat /proc/sys/kernel/random/uuid)"
    printf '%s\n' "$VLESS_UUID" >"$VLESS_UUID_FILE"
  fi

  chmod 600 "$VLESS_UUID_FILE"
  [[ "$VLESS_UUID" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] \
    || die "Saved VLESS UUID is invalid: $VLESS_UUID_FILE"
}

write_vless_server_config() {
  [ "$ROLE" = "de" ] || return 0
  ensure_vless_credentials

  jq -n \
    --arg uuid "$VLESS_UUID" \
    --argjson port "$VLESS_PORT" \
    '{
      log: {loglevel: "warning"},
      inbounds: [
        {
          listen: "0.0.0.0",
          port: $port,
          protocol: "vless",
          settings: {
            clients: [
              {
                id: $uuid,
                level: 0,
                email: "wdtt-mesh-de"
              }
            ],
            decryption: "none"
          },
          streamSettings: {
            network: "tcp",
            security: "none",
            tcpSettings: {
              header: {type: "none"}
            }
          },
          tag: "wdtt-mesh-vless-in"
        }
      ],
      outbounds: [
        {protocol: "freedom", settings: {}, tag: "direct"},
        {protocol: "blackhole", settings: {}, tag: "block"}
      ]
    }' >"$VLESS_CONFIG_FILE"

  # Keep the config readable inside the container. The UUID itself remains
  # separately stored as root-only in $VLESS_UUID_FILE.
  chmod 644 "$VLESS_CONFIG_FILE"
}

wait_vless_listener() {
  local pid i
  pid="$(get_mesh_container_pid 2>/dev/null || true)"
  [ -n "$pid" ] && [ "$pid" != "0" ] || return 1

  for i in $(seq 1 20); do
    if nsenter -t "$pid" -n ss -lnt 2>/dev/null | grep -Eq "[:.]${VLESS_PORT}[[:space:]]"; then
      return 0
    fi
    sleep 1
  done
  return 1
}

deploy_vless_container() {
  [ "$ROLE" = "de" ] || return 0
  docker inspect "$MESH_CONTAINER" >/dev/null 2>&1 || die "Mesh container must exist before VLESS is deployed."

  write_vless_server_config
  docker pull "$VLESS_IMAGE" >/dev/null

  docker rm -f "$VLESS_CONTAINER" >/dev/null 2>&1 || true

  # Validate the config before starting the persistent service.
  if ! docker run --rm \
      --user 0:0 \
      -v "${VLESS_CONFIG_FILE}:/usr/local/etc/xray/config.json:ro" \
      "$VLESS_IMAGE" run -test -config /usr/local/etc/xray/config.json >/dev/null 2>&1; then
    die "Generated VLESS/Xray config failed validation."
  fi

  docker run -d \
    --name "$VLESS_CONTAINER" \
    --restart unless-stopped \
    --user 0:0 \
    --network "container:${MESH_CONTAINER}" \
    -v "${VLESS_CONFIG_FILE}:/usr/local/etc/xray/config.json:ro" \
    "$VLESS_IMAGE" run -config /usr/local/etc/xray/config.json >/dev/null

  if wait_vless_listener; then
    log "Private VLESS endpoint is listening inside the DE Mesh namespace on port $VLESS_PORT."
  else
    docker logs --tail 80 "$VLESS_CONTAINER" >&2 2>/dev/null || true
    die "VLESS container started but port $VLESS_PORT did not become ready."
  fi
}

ensure_vless_container() {
  [ "$ROLE" = "de" ] || return 0

  local mesh_id mode running
  mesh_id="$(docker inspect -f '{{.Id}}' "$MESH_CONTAINER" 2>/dev/null || true)"
  [ -n "$mesh_id" ] || return 1

  if docker inspect "$VLESS_CONTAINER" >/dev/null 2>&1; then
    mode="$(docker inspect -f '{{.HostConfig.NetworkMode}}' "$VLESS_CONTAINER" 2>/dev/null || true)"
    running="$(docker inspect -f '{{.State.Running}}' "$VLESS_CONTAINER" 2>/dev/null || true)"

    if { [ "$mode" = "container:${mesh_id}" ] || [ "$mode" = "container:${MESH_CONTAINER}" ]; } \
       && [ "$running" = "true" ]; then
      wait_vless_listener && return 0
    fi
  fi

  deploy_vless_container
}

get_mesh_virtual_ipv4() {
  local pid
  pid="$(get_mesh_container_pid 2>/dev/null || true)"
  [ -n "$pid" ] && [ "$pid" != "0" ] || return 1

  nsenter -t "$pid" -n ip -4 -o addr show dev CloudflareWARP 2>/dev/null \
    | awk 'NR==1{split($4,a,"/"); print a[1]}'
}

wait_mesh_virtual_ipv4() {
  local i ip
  for i in $(seq 1 30); do
    ip="$(get_mesh_virtual_ipv4 2>/dev/null || true)"
    if [ -n "$ip" ]; then
      printf '%s\n' "$ip"
      return 0
    fi
    sleep 2
  done
  return 1
}

print_vless_profile() {
  [ "$ROLE" = "de" ] || die "The VLESS/3x-ui profile is generated on the DE role."

  if [ -z "$VLESS_UUID" ] && [ -s "$VLESS_UUID_FILE" ]; then
    VLESS_UUID="$(tr -d '\r\n' <"$VLESS_UUID_FILE")"
  fi
  [ -n "$VLESS_UUID" ] || die "VLESS UUID is missing."

  local mesh_ip uri
  mesh_ip="$(get_mesh_virtual_ipv4 2>/dev/null || true)"
  [ -n "$mesh_ip" ] || mesh_ip="${VLESS_MESH_IP:-}"
  [ -n "$mesh_ip" ] || die "Could not determine the DE Cloudflare Mesh IPv4 address."

  uri="vless://${VLESS_UUID}@${mesh_ip}:${VLESS_PORT}?encryption=none&security=none&type=tcp#${VLESS_TAG}"

  printf '\n'
  printf '==================== 3X-UI MESH-DE OUTBOUND ====================\n'
  printf 'Paste this OBJECT into: 3x-ui -> Xray Settings -> Outbounds\n'
  printf 'It includes sendThrough=%s so the connection itself enters Mesh on MSK.\n\n' "$VLESS_SEND_THROUGH"

  jq -n \
    --arg tag "$VLESS_TAG" \
    --arg address "$mesh_ip" \
    --argjson port "$VLESS_PORT" \
    --arg uuid "$VLESS_UUID" \
    --arg sendThrough "$VLESS_SEND_THROUGH" \
    '{
      tag: $tag,
      protocol: "vless",
      settings: {
        address: $address,
        port: $port,
        id: $uuid,
        flow: "",
        encryption: "none"
      },
      streamSettings: {
        network: "tcp",
        security: "none",
        tcpSettings: {
          header: {type: "none"}
        }
      },
      sendThrough: $sendThrough
    }'

  printf '\nVLESS share link (does NOT carry the 3x-ui sendThrough field):\n'
  printf '%s\n' "$uri"
  printf '================================================================\n'
}

xui_cli() {
  [ -x "$XUI_BIN" ] || return 1
  "$XUI_BIN" "$@"
}

xui_normalize_web_path() {
  local p="${1:-}"
  p="${p#/}"
  p="${p%/}"
  if [ -n "$p" ]; then printf '/%s' "$p"; else printf ''; fi
}

xui_api() {
  local method="$1" path="$2" body="${3:-}" response
  [ -n "$XUI_API_BASE" ] || return 1
  [ -n "$XUI_API_TOKEN" ] || return 1
  local -a args
  args=(-k --fail-with-body --silent --show-error --request "$method"
        --header "Authorization: Bearer ${XUI_API_TOKEN}")
  if [ -n "$body" ]; then
    args+=(--header 'Content-Type: application/json' --data "$body")
  fi
  response="$(curl "${args[@]}" "${XUI_API_BASE}${path}")" || return 1
  printf '%s' "$response"
}

save_xui_runtime_secret() {
  umask 077
  cat >"$XUI_ENV_FILE" <<EOF_XUI_ENV
XUI_API_BASE=$(printf '%q' "$XUI_API_BASE")
XUI_API_TOKEN=$(printf '%q' "$XUI_API_TOKEN")
XUI_PANEL_PORT=$(printf '%q' "$XUI_PANEL_PORT")
XUI_WEB_BASE_PATH=$(printf '%q' "$XUI_WEB_BASE_PATH")
XUI_PANEL_SCHEME=$(printf '%q' "$XUI_PANEL_SCHEME")
EOF_XUI_ENV
  chmod 600 "$XUI_ENV_FILE"
}

load_xui_runtime_secret() {
  [ -f "$XUI_ENV_FILE" ] || return 1
  # shellcheck disable=SC1090
  . "$XUI_ENV_FILE"
  [ -n "${XUI_API_BASE:-}" ] && [ -n "${XUI_API_TOKEN:-}" ]
}

refresh_xui_connection_info() {
  [ -x "$XUI_BIN" ] || return 1
  local settings cert token path api_test detected_base detected_port detected_path detected_scheme cached_token
  settings="$(xui_cli setting -show true 2>/dev/null || true)"
  detected_port="$(grep -Eo 'port: [0-9]+' <<<"$settings" | awk '{print $2}' | tail -n1)"
  path="$(grep -Eo 'webBasePath: .+' <<<"$settings" | sed 's/^webBasePath:[[:space:]]*//' | tail -n1)"
  detected_path="$(xui_normalize_web_path "$path")"
  [ -n "$detected_port" ] || return 1

  cert="$(xui_cli setting -getCert true 2>/dev/null | awk -F': ' '/^cert:/{print $2}' | tr -d '[:space:]' | tail -n1)"
  if [ -n "$cert" ]; then detected_scheme="https"; else detected_scheme="http"; fi
  detected_base="${detected_scheme}://127.0.0.1:${detected_port}${detected_path}"

  cached_token=""
  if [ -f "$XUI_ENV_FILE" ]; then
    cached_token="$(bash -c '. "$1" 2>/dev/null; printf "%s" "${XUI_API_TOKEN:-}"' _ "$XUI_ENV_FILE" 2>/dev/null || true)"
  fi
  if [ -n "$cached_token" ]; then
    XUI_API_BASE="$detected_base"
    XUI_API_TOKEN="$cached_token"
    XUI_PANEL_PORT="$detected_port"
    XUI_WEB_BASE_PATH="$detected_path"
    XUI_PANEL_SCHEME="$detected_scheme"
    api_test="$(xui_api GET '/panel/api/inbounds/list' 2>/dev/null || true)"
    if jq -e '.success == true' >/dev/null 2>&1 <<<"$api_test"; then
      save_xui_runtime_secret
      return 0
    fi
  fi

  # Use a dedicated CLI token name. Re-running rotates only this token, not the
  # user's other API tokens.
  token="$(xui_cli setting -tokenName wdtt-mesh -getApiToken 2>/dev/null | sed -n 's/^apiToken:[[:space:]]*//p' | tail -n1)"
  [ -n "$token" ] || return 1
  XUI_API_BASE="$detected_base"
  XUI_API_TOKEN="$token"
  XUI_PANEL_PORT="$detected_port"
  XUI_WEB_BASE_PATH="$detected_path"
  XUI_PANEL_SCHEME="$detected_scheme"
  save_xui_runtime_secret

  api_test="$(xui_api GET '/panel/api/inbounds/list' 2>/dev/null || true)"
  jq -e '.success == true' >/dev/null 2>&1 <<<"$api_test"
}
ensure_xui_installed() {
  if [ -x "$XUI_BIN" ]; then
    systemctl enable --now "$XUI_SERVICE" >/dev/null 2>&1 || true
    return 0
  fi

  [[ "$XUI_VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "Unsafe/invalid --xui-version: $XUI_VERSION"
  command -v apt-get >/dev/null 2>&1 || die "Automatic 3x-ui install is currently supported only on Debian/Ubuntu."

  log "Installing 3x-ui $XUI_VERSION non-interactively (SQLite, local HTTP panel)."
  local installer
  installer="$(mktemp)"
  curl -fsSL "https://raw.githubusercontent.com/MHSanaei/3x-ui/${XUI_VERSION}/install.sh" -o "$installer" \
    || { rm -f "$installer"; die "Could not download the pinned 3x-ui installer."; }

  XUI_NONINTERACTIVE=1 XUI_SSL_MODE=none XUI_DB_TYPE=sqlite bash "$installer" "$XUI_VERSION"
  rm -f "$installer"
  [ -x "$XUI_BIN" ] || die "3x-ui installer completed but $XUI_BIN is missing."

  # The panel is management-only on this DE node. Keep it off the public interface.
  xui_cli setting -listenIP 127.0.0.1 >/dev/null 2>&1 || die "Could not bind the 3x-ui panel to 127.0.0.1."
  systemctl restart "$XUI_SERVICE"
  systemctl is-active --quiet "$XUI_SERVICE" || die "3x-ui service did not start."
  XUI_PANEL_INSTALLED_BY_SCRIPT="1"
  log "3x-ui $XUI_VERSION installed. Panel is bound to 127.0.0.1 only."
}

xui_inbound_list() {
  xui_api GET '/panel/api/inbounds/list'
}

xui_inbound_by_remark() {
  local list
  list="$(xui_inbound_list)" || return 1
  jq -c --arg remark "$XUI_INBOUND_REMARK" '.obj[]? | select(.remark == $remark)' <<<"$list" | head -n1
}

validate_xui_inbound_json() {
  local inbound="$1"
  [ -n "$inbound" ] || return 1
  jq -e \
    --arg listen "$MESH_DOCKER_GW" \
    --argjson port "$VLESS_PORT" \
    --arg uuid "$VLESS_UUID" '
      .protocol == "vless" and
      .listen == $listen and
      .port == $port and
      .enable == true and
      ((.settings.clients // []) | any(.id == $uuid)) and
      (.streamSettings.network == "tcp") and
      (.streamSettings.security == "none")
    ' >/dev/null <<<"$inbound"
}

ensure_xui_inbound() {
  ensure_vless_credentials
  refresh_xui_connection_info || die "Could not authenticate to the local 3x-ui API."

  local existing payload response
  existing="$(xui_inbound_by_remark || true)"
  if [ -n "$existing" ]; then
    if ! validate_xui_inbound_json "$existing"; then
      die "3x-ui already has an inbound named '$XUI_INBOUND_REMARK', but its listen/port/protocol/UUID does not match this Mesh deployment. It was left untouched."
    fi
    XUI_INBOUND_ID="$(jq -r '.id' <<<"$existing")"
    XUI_INBOUND_TAG="$(jq -r '.tag // empty' <<<"$existing")"
    [ -n "$XUI_INBOUND_TAG" ] || XUI_INBOUND_TAG="inbound-${XUI_INBOUND_ID}"
    log "Reusing 3x-ui inbound '$XUI_INBOUND_REMARK' (id=$XUI_INBOUND_ID, tag=$XUI_INBOUND_TAG)."
    return 0
  fi

  payload="$(jq -cn \
    --arg remark "$XUI_INBOUND_REMARK" \
    --arg listen "$MESH_DOCKER_GW" \
    --argjson port "$VLESS_PORT" \
    --arg uuid "$VLESS_UUID" '
      {
        enable:true,
        remark:$remark,
        listen:$listen,
        port:$port,
        protocol:"vless",
        expiryTime:0,
        total:0,
        settings:{
          clients:[{id:$uuid,email:"wdtt-mesh-de",flow:"",level:0}],
          decryption:"none",
          fallbacks:[]
        },
        streamSettings:{
          network:"tcp",
          security:"none",
          tcpSettings:{header:{type:"none"}}
        },
        sniffing:{enabled:true,destOverride:["http","tls","quic"],routeOnly:false}
      }')"

  response="$(xui_api POST '/panel/api/inbounds/add' "$payload")" || die "3x-ui API rejected creation of the Mesh inbound."
  jq -e '.success == true' >/dev/null <<<"$response" || {
    printf '%s\n' "$response" >&2
    die "3x-ui returned an error while creating the Mesh inbound."
  }

  existing="$(xui_inbound_by_remark || true)"
  validate_xui_inbound_json "$existing" || die "3x-ui reported success, but the created Mesh inbound could not be verified."
  XUI_INBOUND_ID="$(jq -r '.id' <<<"$existing")"
  XUI_INBOUND_TAG="$(jq -r '.tag // empty' <<<"$existing")"
  [ -n "$XUI_INBOUND_TAG" ] || XUI_INBOUND_TAG="inbound-${XUI_INBOUND_ID}"
  XUI_INBOUND_CREATED="1"
  log "Created private 3x-ui inbound '$XUI_INBOUND_REMARK' (id=$XUI_INBOUND_ID, tag=$XUI_INBOUND_TAG)."
}

wait_xui_host_listener() {
  local i
  for i in $(seq 1 20); do
    if ss -H -lnt 2>/dev/null | grep -Fq "${MESH_DOCKER_GW}:${VLESS_PORT}"; then
      return 0
    fi
    sleep 1
  done
  return 1
}

ensure_xui_input_rule() {
  if ! iptables -w 5 -C INPUT -i "$MESH_BRIDGE" -s "${MESH_CONTAINER_IP}/32" -d "${MESH_DOCKER_GW}/32" \
      -p tcp --dport "$VLESS_PORT" -m comment --comment "$XUI_INPUT_COMMENT" -j ACCEPT 2>/dev/null; then
    # Put this before user/public DROP chains. It is scoped to the private Docker
    # bridge, one source address and one destination port.
    iptables -w 5 -I INPUT 1 -i "$MESH_BRIDGE" -s "${MESH_CONTAINER_IP}/32" -d "${MESH_DOCKER_GW}/32" \
      -p tcp --dport "$VLESS_PORT" -m comment --comment "$XUI_INPUT_COMMENT" -j ACCEPT
  fi
}

remove_xui_input_rule() {
  while iptables -w 5 -C INPUT -i "$MESH_BRIDGE" -s "${MESH_CONTAINER_IP}/32" -d "${MESH_DOCKER_GW}/32" \
      -p tcp --dport "$VLESS_PORT" -m comment --comment "$XUI_INPUT_COMMENT" -j ACCEPT 2>/dev/null; do
    iptables -w 5 -D INPUT -i "$MESH_BRIDGE" -s "${MESH_CONTAINER_IP}/32" -d "${MESH_DOCKER_GW}/32" \
      -p tcp --dport "$VLESS_PORT" -m comment --comment "$XUI_INPUT_COMMENT" -j ACCEPT
  done
}

relay_xui_forever() {
  need_root
  [ -f "$CONFIG_FILE" ] || die "Configuration not found: $CONFIG_FILE"
  load_config
  [ "$ROLE" = "de" ] || die "relay-xui is valid only on the DE role."
  [ "${VLESS_BACKEND:-legacy}" = "xui" ] || die "3x-ui backend is not enabled."
  command -v socat >/dev/null 2>&1 || die "socat is required for the Mesh->3x-ui namespace relay."

  local mesh_pid child_pid new_pid
  while :; do
    mesh_pid="$(get_mesh_container_pid 2>/dev/null || true)"
    if [ -z "$mesh_pid" ] || [ "$mesh_pid" = "0" ]; then
      sleep 2
      continue
    fi
    if ! systemctl is-active --quiet "$XUI_SERVICE"; then
      sleep 2
      continue
    fi

    log "Starting RAW/TCP namespace relay: Mesh :${VLESS_PORT} -> ${MESH_DOCKER_GW}:${VLESS_PORT} (netns pid $mesh_pid)."
    nsenter -t "$mesh_pid" -n socat \
      "TCP4-LISTEN:${VLESS_PORT},bind=0.0.0.0,reuseaddr,fork" \
      "TCP4:${MESH_DOCKER_GW}:${VLESS_PORT}" &
    child_pid=$!

    while kill -0 "$child_pid" 2>/dev/null; do
      sleep 2
      new_pid="$(get_mesh_container_pid 2>/dev/null || true)"
      if [ "$new_pid" != "$mesh_pid" ]; then
        kill "$child_pid" 2>/dev/null || true
        break
      fi
    done
    wait "$child_pid" 2>/dev/null || true
    sleep 1
  done
}

install_xui_relay_persistence() {
  local self
  self="$(readlink -f "$0")"
  cat >"$XUI_RELAY_UNIT" <<EOF_XUI_RELAY
[Unit]
Description=WDTT Mesh private relay into local 3x-ui
After=docker.service x-ui.service
Wants=docker.service x-ui.service
PartOf=wdtt-mesh-egress.service

[Service]
Type=simple
ExecStart=${self} relay-xui
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF_XUI_RELAY
  systemctl daemon-reload
  systemctl enable wdtt-mesh-xui-relay.service >/dev/null
}

stop_xui_relay() {
  systemctl disable --now wdtt-mesh-xui-relay.service >/dev/null 2>&1 || true
  rm -f "$XUI_RELAY_UNIT"
  systemctl daemon-reload >/dev/null 2>&1 || true
}

wait_xui_relay_listener() {
  local pid i
  pid="$(get_mesh_container_pid 2>/dev/null || true)"
  [ -n "$pid" ] && [ "$pid" != "0" ] || return 1
  for i in $(seq 1 20); do
    if systemctl is-active --quiet wdtt-mesh-xui-relay.service \
       && nsenter -t "$pid" -n ss -H -lnt 2>/dev/null | grep -Eq "[:.]${VLESS_PORT}[[:space:]]"; then
      return 0
    fi
    sleep 1
  done
  return 1
}

mesh_can_reach_xui_listener() {
  local pid
  pid="$(get_mesh_container_pid 2>/dev/null || true)"
  [ -n "$pid" ] && [ "$pid" != "0" ] || return 1
  nsenter -t "$pid" -n timeout 3 bash -c "exec 3<>/dev/tcp/${MESH_DOCKER_GW}/${VLESS_PORT}" >/dev/null 2>&1
}

find_xui_xray_binary() {
  find /usr/local/x-ui/bin -maxdepth 1 -type f -name 'xray-linux-*' -perm -u+x 2>/dev/null | head -n1
}

synthetic_xui_end_to_end_test() {
  [ "${VLESS_BACKEND:-legacy}" = "xui" ] || return 1
  local mesh_pid xray_bin tmpdir cfg logf test_pid i result tcp_rc=1 udp_rc=1 test_port udp_port response_file response_size
  mesh_pid="$(get_mesh_container_pid 2>/dev/null || true)"
  xray_bin="$(find_xui_xray_binary)"
  [ -n "$mesh_pid" ] && [ "$mesh_pid" != "0" ] || return 1
  [ -x "$xray_bin" ] || return 1
  command -v socat >/dev/null 2>&1 || return 1

  test_port=39080
  while nsenter -t "$mesh_pid" -n ss -H -lnt 2>/dev/null | grep -Eq "127\.0\.0\.1:${test_port}[[:space:]]"; do
    test_port=$((test_port + 1))
    [ "$test_port" -le 39180 ] || return 1
  done
  udp_port=$((test_port + 101))
  while nsenter -t "$mesh_pid" -n ss -H -lnu 2>/dev/null | grep -Eq "127\.0\.0\.1:${udp_port}[[:space:]]"; do
    udp_port=$((udp_port + 1))
    [ "$udp_port" -le 39380 ] || return 1
  done

  tmpdir="$(mktemp -d)"
  cfg="$tmpdir/client.json"
  logf="$tmpdir/xray.log"
  response_file="$tmpdir/dns-response.bin"
  jq -n \
    --arg uuid "$VLESS_UUID" \
    --argjson port "$VLESS_PORT" \
    --argjson test_port "$test_port" \
    --argjson udp_port "$udp_port" '
    {
      log:{loglevel:"warning"},
      inbounds:[
        {
          listen:"127.0.0.1",port:$test_port,protocol:"socks",
          settings:{udp:true},tag:"test-socks"
        },
        {
          listen:"127.0.0.1",port:$udp_port,protocol:"tunnel",
          settings:{allowedNetwork:"udp",rewriteAddress:"1.1.1.1",rewritePort:53,followRedirect:false,userLevel:0},
          tag:"test-udp-dns"
        }
      ],
      outbounds:[{
        protocol:"vless",
        settings:{address:"127.0.0.1",port:$port,id:$uuid,encryption:"none",flow:""},
        streamSettings:{network:"tcp",security:"none",tcpSettings:{header:{type:"none"}}},
        tag:"mesh-test"
      }]
    }' >"$cfg"

  nsenter -t "$mesh_pid" -n "$xray_bin" run -c "$cfg" >"$logf" 2>&1 &
  test_pid=$!
  for i in $(seq 1 20); do
    if nsenter -t "$mesh_pid" -n ss -H -lnt 2>/dev/null | grep -Fq "127.0.0.1:${test_port}" \
       && nsenter -t "$mesh_pid" -n ss -H -lnu 2>/dev/null | grep -Fq "127.0.0.1:${udp_port}"; then
      break
    fi
    if ! kill -0 "$test_pid" 2>/dev/null; then
      break
    fi
    sleep 0.25
  done

  if kill -0 "$test_pid" 2>/dev/null; then
    result="$(nsenter -t "$mesh_pid" -n curl -4sS --connect-timeout 5 --max-time 12 \
      --socks5-hostname "127.0.0.1:${test_port}" https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null || true)"
    if grep -q '^ip=' <<<"$result"; then
      printf '%s\n' "$result" | grep -E '^(ip|colo|warp)=' || true
      tcp_rc=0
    else
      warn "Synthetic TCP VLESS->3x-ui test did not receive a valid trace response."
    fi

    # Raw DNS query for example.com A (ID 0x1234). The local Xray tunnel inbound
    # forwards this UDP datagram to 1.1.1.1:53 through the same VLESS session.
    # This catches the exact class of UDP breakage that the old WARP Local Proxy
    # experiment failed to detect.
    printf '\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01' \
      | nsenter -t "$mesh_pid" -n socat -T5 - "UDP4:127.0.0.1:${udp_port}" >"$response_file" 2>/dev/null || true
    response_size="$(wc -c <"$response_file" 2>/dev/null || printf '0')"
    if [ "${response_size:-0}" -gt 12 ]; then
      printf 'udp_dns_bytes=%s\n' "$response_size"
      udp_rc=0
    else
      warn "Synthetic UDP VLESS->3x-ui DNS test did not receive a DNS response."
    fi
  else
    warn "Synthetic Xray test client exited before opening its local test listeners."
  fi

  if [ "$tcp_rc" != "0" ] || [ "$udp_rc" != "0" ]; then
    sed -n '1,120p' "$logf" >&2 || true
  fi

  kill "$test_pid" 2>/dev/null || true
  wait "$test_pid" 2>/dev/null || true
  rm -rf "$tmpdir"
  [ "$tcp_rc" = "0" ] && [ "$udp_rc" = "0" ]
}

create_backup_snapshot() {
  mkdir -p "$BACKUP_ROOT"
  chmod 700 "$STATE_DIR" "$BACKUP_ROOT" 2>/dev/null || true
  local stamp dir
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  dir="$(mktemp -d -p "$BACKUP_ROOT" "${stamp}.XXXXXX")"
  chmod 700 "$dir"

  [ -f "$CONFIG_FILE" ] && cp -a "$CONFIG_FILE" "$dir/" || true
  [ -f "$NODE_ENV_FILE" ] && cp -a "$NODE_ENV_FILE" "$dir/" || true
  [ -d "$VLESS_CONFIG_DIR" ] && cp -a "$VLESS_CONFIG_DIR" "$dir/" || true
  [ -f "$XUI_ENV_FILE" ] && cp -a "$XUI_ENV_FILE" "$dir/" || true
  [ -f /etc/x-ui/x-ui.db ] && cp -a /etc/x-ui/x-ui.db "$dir/x-ui.db" || true
  [ -f "$SYSTEMD_UNIT" ] && cp -a "$SYSTEMD_UNIT" "$dir/" || true
  [ -f "$DE_WARP_WATCH_UNIT" ] && cp -a "$DE_WARP_WATCH_UNIT" "$dir/" || true
  [ -f "$XUI_RELAY_UNIT" ] && cp -a "$XUI_RELAY_UNIT" "$dir/" || true
  [ -f /etc/systemd/system/wdtt-warp-proxy-bridge.service ] && cp -a /etc/systemd/system/wdtt-warp-proxy-bridge.service "$dir/" || true
  iptables-save >"$dir/iptables-save.txt" 2>/dev/null || true
  ip -4 addr show >"$dir/ip-addr.txt" 2>/dev/null || true
  ip -4 route show table all >"$dir/ip-route-all.txt" 2>/dev/null || true
  docker inspect "$MESH_CONTAINER" >"$dir/mesh-inspect.json" 2>/dev/null || true
  docker inspect "$VLESS_CONTAINER" >"$dir/legacy-vless-inspect.json" 2>/dev/null || true
  printf '%s\n' "$dir" >"$LAST_BACKUP_FILE"
  chmod 600 "$LAST_BACKUP_FILE"
  log "Rollback snapshot saved: $dir"
}

cleanup_old_proxy_experiment() {
  # v0.2.3/v0.2.4 experimental Local Proxy must not participate in the new
  # data path. Detect it before touching anything so a failed 3x-ui migration
  # never leaves the user on the already-broken SOCKS-only VLESS config.
  local old_bridge_port="${WARP_BRIDGE_PORT:-40001}" had_old_proxy="0"
  if [ "${HIDE_DE_IP:-0}" = "1" ] \
     || [ -f /etc/systemd/system/wdtt-warp-proxy-bridge.service ] \
     || grep -q '"tag"[[:space:]]*:[[:space:]]*"warp-egress"' "$VLESS_CONFIG_FILE" 2>/dev/null; then
    had_old_proxy="1"
  fi

  systemctl disable --now wdtt-warp-proxy-bridge.service >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/wdtt-warp-proxy-bridge.service
  systemctl daemon-reload >/dev/null 2>&1 || true

  while iptables -w 5 -C INPUT -i "$MESH_BRIDGE" -s "${MESH_CONTAINER_IP}/32" -d "${MESH_DOCKER_GW}/32" \
      -p tcp --dport "$old_bridge_port" -m comment --comment WDTT_WARP_PROXY_IN -j ACCEPT 2>/dev/null; do
    iptables -w 5 -D INPUT -i "$MESH_BRIDGE" -s "${MESH_CONTAINER_IP}/32" -d "${MESH_DOCKER_GW}/32" \
      -p tcp --dport "$old_bridge_port" -m comment --comment WDTT_WARP_PROXY_IN -j ACCEPT
  done

  if [ "$had_old_proxy" = "1" ] && [ "${VLESS_BACKEND:-legacy}" = "legacy" ]; then
    warn "Detected the old WARP Local Proxy experiment. Restoring the stable direct legacy VLESS backend before 3x-ui migration."
    deploy_vless_container
  fi
}

rollback_to_legacy_internal() {
  [ "$ROLE" = "de" ] || return 1
  warn "Rolling DE private VLESS backend back to the legacy isolated Xray container."
  stop_xui_relay
  remove_xui_input_rule
  VLESS_BACKEND="legacy"
  write_config
  deploy_vless_container
  install_persistence
  log "Rollback complete: private Mesh VLESS is again served by $VLESS_CONTAINER."
}

enable_xui_egress_saved() {
  need_root
  [ -f "$CONFIG_FILE" ] || die "Configuration not found: $CONFIG_FILE"
  load_config
  [ "$ROLE" = "de" ] || die "enable-xui-egress is valid only on the DE role."

  create_backup_snapshot
  cleanup_old_proxy_experiment
  command -v socat >/dev/null 2>&1 || {
    apt-get update
    apt-get install -y socat
  }

  ensure_xui_installed
  refresh_xui_connection_info || die "3x-ui is installed but its local API could not be authenticated."
  ensure_xui_inbound
  wait_xui_host_listener || die "3x-ui created the inbound, but Xray is not listening on ${MESH_DOCKER_GW}:${VLESS_PORT}."
  ensure_xui_input_rule
  if ! mesh_can_reach_xui_listener; then
    remove_xui_input_rule
    die "Mesh namespace cannot open TCP ${MESH_DOCKER_GW}:${VLESS_PORT}; firewall/listen path is not ready. Legacy VLESS was NOT stopped."
  fi

  # Commit only after all prerequisites are proven. The only interruption starts
  # here, when the old listener is replaced by the relay.
  local migration_rc=0
  VLESS_BACKEND="xui"
  write_config || migration_rc=1
  install_xui_relay_persistence || migration_rc=1
  docker stop "$VLESS_CONTAINER" >/dev/null 2>&1 || true
  docker rm -f "$VLESS_CONTAINER" >/dev/null 2>&1 || true
  systemctl restart wdtt-mesh-xui-relay.service || migration_rc=1
  [ "$migration_rc" = "0" ] && wait_xui_relay_listener || migration_rc=1
  [ "$migration_rc" = "0" ] && synthetic_xui_end_to_end_test || migration_rc=1

  if [ "$migration_rc" != "0" ]; then
    rollback_to_legacy_internal
    die "3x-ui cutover failed; automatic rollback to the legacy VLESS backend completed."
  fi

  write_config
  install_persistence
  log "3x-ui egress backend is active. Mesh endpoint/UUID did not change."
  printf '\n3x-ui management stays on localhost. Retrieve credentials with:\n'
  printf '  sudo cat /etc/x-ui/install-result.env\n'
  printf 'Panel port: %s  path: %s\n' "$XUI_PANEL_PORT" "${XUI_WEB_BASE_PATH:-/}"
  printf 'Use an SSH tunnel/ProxyJump to 127.0.0.1:%s; do not expose the panel over public HTTP.\n' "$XUI_PANEL_PORT"
  printf '\nThe script intentionally did NOT change 3x-ui outbounds/routing. Configure WARP/proxies in 3x-ui, then route inbound tag %s to the desired outbound.\n' "${XUI_INBOUND_TAG:-<see status>}"
}

rollback_saved() {
  need_root
  [ -f "$CONFIG_FILE" ] || die "Configuration not found: $CONFIG_FILE"
  load_config
  [ "$ROLE" = "de" ] || die "rollback is currently meaningful only on the DE role."
  rollback_to_legacy_internal
  if [ -f "$LAST_BACKUP_FILE" ]; then
    log "Last pre-migration snapshot is retained at: $(cat "$LAST_BACKUP_FILE")"
  fi
}

show_xui_routing_summary() {
  load_xui_runtime_secret >/dev/null 2>&1 || { printf '  API credentials: unavailable (run enable-xui-egress to refresh them)\n'; return 0; }
  local response setting_json
  response="$(xui_api POST '/panel/api/xray/' 2>/dev/null || true)"
  setting_json="$(jq -r '.obj.xraySetting // empty' <<<"$response" 2>/dev/null || true)"
  if [ -z "$setting_json" ]; then
    printf '  Xray settings API: unavailable\n'
    return 0
  fi
  printf '  Outbounds (tag -> protocol):\n'
  jq -r '.outbounds[]? | "    \(.tag // "<none>") -> \(.protocol // "<none>")"' <<<"$setting_json" 2>/dev/null || true
  printf '  Rules referencing Mesh inbound tag %s:\n' "${XUI_INBOUND_TAG:-<unknown>}"
  if [ -n "${XUI_INBOUND_TAG:-}" ]; then
    jq -c --arg tag "$XUI_INBOUND_TAG" '.routing.rules[]? | select((.inboundTag // []) | index($tag))' <<<"$setting_json" 2>/dev/null \
      | sed 's/^/    /' || true
  fi
}

selftest_saved() {
  need_root
  [ -f "$CONFIG_FILE" ] || die "Configuration not found: $CONFIG_FILE"
  load_config
  local failed=0 mesh_status pid
  printf '=== WDTT Mesh self-test v%s ===\n' "$VERSION"
  mesh_status="$(docker exec "$MESH_CONTAINER" warp-cli --accept-tos status 2>/dev/null || true)"
  if grep -q 'Status update: Connected' <<<"$mesh_status"; then printf '[OK] Mesh connected\n'; else printf '[FAIL] Mesh not connected\n'; failed=1; fi
  if ip link show "$MESH_BRIDGE" >/dev/null 2>&1; then printf '[OK] bridge %s exists\n' "$MESH_BRIDGE"; else printf '[FAIL] bridge missing\n'; failed=1; fi

  if [ "$ROLE" = "de" ]; then
    if ip route show "$WDTT_NET" | grep -q "via $MESH_CONTAINER_IP"; then printf '[OK] DE return route to %s\n' "$WDTT_NET"; else printf '[FAIL] DE return route missing\n'; failed=1; fi
    if [ "${VLESS_BACKEND:-legacy}" = "xui" ]; then
      if load_xui_runtime_secret >/dev/null 2>&1 && jq -e '.success == true' >/dev/null 2>&1 <<<"$(xui_api GET '/panel/api/inbounds/list' 2>/dev/null || true)"; then
        printf '[OK] 3x-ui API reachable\n'
      else
        printf '[WARN] 3x-ui API credentials unavailable/stale; data path tests continue\n'
      fi
      wait_xui_host_listener && printf '[OK] 3x-ui private VLESS listener\n' || { printf '[FAIL] 3x-ui listener missing\n'; failed=1; }
      wait_xui_relay_listener && printf '[OK] Mesh namespace relay listener\n' || { printf '[FAIL] relay listener missing\n'; failed=1; }
      mesh_can_reach_xui_listener && printf '[OK] Mesh namespace -> 3x-ui TCP reachability\n' || { printf '[FAIL] Mesh namespace cannot reach 3x-ui\n'; failed=1; }
      printf '%s\n' '--- synthetic VLESS -> 3x-ui -> Internet ---'
      synthetic_xui_end_to_end_test && printf '[OK] synthetic end-to-end TCP test\n' || { printf '[FAIL] synthetic end-to-end test\n'; failed=1; }
    else
      wait_vless_listener && printf '[OK] legacy private VLESS listener\n' || { printf '[FAIL] legacy VLESS listener missing\n'; failed=1; }
    fi
    pid="$(get_mesh_container_pid 2>/dev/null || true)"
    [ -n "$pid" ] && [ "$pid" != "0" ] && printf '[OK] Mesh netns pid %s\n' "$pid" || { printf '[FAIL] Mesh netns unavailable\n'; failed=1; }
  fi

  if [ "$failed" = "0" ]; then
    printf 'RESULT: PASS\n'
    return 0
  fi
  printf 'RESULT: FAIL\n'
  return 1
}

ensure_docker_network() {
  if docker network inspect "$MESH_DOCKER_NETWORK" >/dev/null 2>&1; then
    return 0
  fi
  docker network create \
    --driver bridge \
    --subnet "$MESH_DOCKER_NET" \
    --gateway "$MESH_DOCKER_GW" \
    --opt "com.docker.network.bridge.name=${MESH_BRIDGE}" \
    "$MESH_DOCKER_NETWORK" >/dev/null
}

deploy_mesh_container() {
  local srcnat="$1"
  write_node_env "$srcnat"
  ensure_docker_network
  docker pull "$MESH_IMAGE" >/dev/null
  if [ "$ROLE" = "de" ]; then
    systemctl stop wdtt-mesh-xui-relay.service >/dev/null 2>&1 || true
    docker rm -f "$VLESS_CONTAINER" >/dev/null 2>&1 || true
  fi
  docker rm -f "$MESH_CONTAINER" >/dev/null 2>&1 || true
  docker volume create wdtt_mesh_data >/dev/null
  docker run -d \
    --name "$MESH_CONTAINER" \
    --restart unless-stopped \
    --network "$MESH_DOCKER_NETWORK" \
    --ip "$MESH_CONTAINER_IP" \
    --cap-add NET_ADMIN \
    --cap-add NET_RAW \
    --device /dev/net/tun:/dev/net/tun \
    --sysctl net.ipv4.ip_forward=1 \
    --sysctl net.ipv6.conf.all.forwarding=1 \
    --sysctl net.ipv6.conf.default.forwarding=1 \
    --env-file "$NODE_ENV_FILE" \
    -v wdtt_mesh_data:/var/lib/cloudflare-warp \
    "$MESH_IMAGE" >/dev/null
  log "Cloudflare Mesh container started as $NODE_NAME."

  # Explicitly request a connection. The image normally does this itself, but
  # doing it here makes first boot and profile changes deterministic.
  docker exec "$MESH_CONTAINER" warp-cli --accept-tos connect >/dev/null 2>&1 || true

  local i status_text connected="0"
  for i in $(seq 1 30); do
    status_text="$(docker exec "$MESH_CONTAINER" warp-cli --accept-tos status 2>/dev/null || true)"
    if printf '%s\n' "$status_text" | grep -q 'Status update: Connected'; then
      connected="1"
      log "Cloudflare One Client is Connected."
      break
    fi
    sleep 2
  done
  if [ "$connected" != "1" ]; then
    warn "Cloudflare One Client did not reach Connected state within 60 seconds."
    printf '%s\n' "$status_text" >&2
  fi
}

ensure_jump() {
  local chain="$1" comment="$2"
  shift 2
  if ! iptables -w 5 -C FORWARD "$@" -m comment --comment "$comment" -j "$chain" 2>/dev/null; then
    iptables -w 5 -I FORWARD 1 "$@" -m comment --comment "$comment" -j "$chain"
  fi
}

remove_forward_jumps_by_comment() {
  local comment="$1" nums n
  while :; do
    nums="$(iptables -w 5 -L FORWARD --line-numbers -n 2>/dev/null | grep -F "/* $comment */" | awk '{print $1}' | sort -rn || true)"
    [ -n "$nums" ] || break
    while read -r n; do
      [ -n "$n" ] && iptables -w 5 -D FORWARD "$n"
    done <<<"$nums"
  done
}

server_ip_on_wdtt() {
  ip -4 -o addr show dev "$WDTT_IF" | awk 'NR==1{split($4,a,"/"); print a[1]}'
}

apply_msk() {
  ip link show dev "$WDTT_IF" >/dev/null 2>&1 || die "$WDTT_IF does not exist. Start wdtt.service first."
  ip link show dev "$MESH_BRIDGE" >/dev/null 2>&1 || die "$MESH_BRIDGE does not exist. Is the Mesh container running?"

  local wdtt_server_ip
  wdtt_server_ip="$(server_ip_on_wdtt)"
  [ -n "$wdtt_server_ip" ] || die "Could not determine IPv4 address on $WDTT_IF."

  sysctl -q -w net.ipv4.ip_forward=1
  sysctl -q -w "net.ipv4.conf.${WDTT_IF}.rp_filter=2" || true
  sysctl -q -w "net.ipv4.conf.${MESH_BRIDGE}.rp_filter=2" || true

  ip -4 route replace "$WDTT_NET" dev "$WDTT_IF" scope link src "$wdtt_server_ip" table "$ROUTE_TABLE"
  ip -4 route replace default via "$MESH_CONTAINER_IP" dev "$MESH_BRIDGE" table "$ROUTE_TABLE"

  while ip -4 rule del pref "$RULE_PREF" from "$WDTT_NET" table "$ROUTE_TABLE" 2>/dev/null; do :; done
  ip -4 rule add pref "$RULE_PREF" from "$WDTT_NET" table "$ROUTE_TABLE"
  ip -4 route flush cache 2>/dev/null || true

  iptables -w 5 -N "$CHAIN_MSK" 2>/dev/null || true
  iptables -w 5 -F "$CHAIN_MSK"
  iptables -w 5 -A "$CHAIN_MSK" -i "$WDTT_IF" -s "$WDTT_NET" -o "$MESH_BRIDGE" -j ACCEPT
  iptables -w 5 -A "$CHAIN_MSK" -i "$MESH_BRIDGE" -o "$WDTT_IF" -d "$WDTT_NET" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  iptables -w 5 -A "$CHAIN_MSK" -i "$WDTT_IF" -s "$WDTT_NET" -j DROP

  remove_forward_jumps_by_comment "$COMMENT_MSK_OUT"
  remove_forward_jumps_by_comment "$COMMENT_MSK_IN"
  ensure_jump "$CHAIN_MSK" "$COMMENT_MSK_OUT" -i "$WDTT_IF" -s "$WDTT_NET"
  ensure_jump "$CHAIN_MSK" "$COMMENT_MSK_IN" -i "$MESH_BRIDGE" -o "$WDTT_IF" -d "$WDTT_NET"

  log "MSK policy routing is active: $WDTT_NET -> Cloudflare Mesh container."
}

remove_msk_runtime() {
  while ip -4 rule del pref "$RULE_PREF" from "$WDTT_NET" table "$ROUTE_TABLE" 2>/dev/null; do :; done
  ip -4 route flush table "$ROUTE_TABLE" 2>/dev/null || true
  ip -4 route flush cache 2>/dev/null || true
  remove_forward_jumps_by_comment "$COMMENT_MSK_OUT"
  remove_forward_jumps_by_comment "$COMMENT_MSK_IN"
  iptables -w 5 -F "$CHAIN_MSK" 2>/dev/null || true
  iptables -w 5 -X "$CHAIN_MSK" 2>/dev/null || true
}


get_mesh_container_pid() {
  docker inspect -f '{{.State.Pid}}' "$MESH_CONTAINER" 2>/dev/null
}

detect_cloudflare_warp_table() {
  local pid="$1"
  nsenter -t "$pid" -n ip -4 rule show 2>/dev/null \
    | awk '
        /fwmark[[:space:]]+0x100cf/ && /lookup/ {
          for (i = 1; i <= NF; i++) {
            if ($i == "lookup" && (i + 1) <= NF) {
              print $(i + 1)
              exit
            }
          }
        }'
}

ensure_de_warp_return_routes_once() {
  local pid table cidr current changed="0"

  [ "$ROLE" = "de" ] || return 0
  docker inspect "$MESH_CONTAINER" >/dev/null 2>&1 || return 1

  pid="$(get_mesh_container_pid)"
  [ -n "$pid" ] && [ "$pid" != "0" ] || return 1

  nsenter -t "$pid" -n ip link show dev CloudflareWARP >/dev/null 2>&1 || return 1
  table="$(detect_cloudflare_warp_table "$pid")"
  [ -n "$table" ] || return 1

  for cidr in "100.64.0.0/12" "100.96.0.0/12" "$WDTT_NET"; do
    current="$(nsenter -t "$pid" -n ip -4 route show table "$table" "$cidr" 2>/dev/null || true)"
    if ! printf '%s\n' "$current" | grep -Fq "$cidr dev CloudflareWARP"; then
      nsenter -t "$pid" -n ip -4 route replace "$cidr" dev CloudflareWARP table "$table" \
        || return 1
      changed="1"
      log "Restored DE WARP return route: $cidr -> CloudflareWARP (table $table)."
    fi
  done

  if [ "$changed" = "1" ]; then
    nsenter -t "$pid" -n ip -4 route flush cache 2>/dev/null || true
  fi

  return 0
}

ensure_de_warp_return_routes_wait() {
  local i
  for i in $(seq 1 30); do
    if ensure_de_warp_return_routes_once; then
      return 0
    fi
    sleep 2
  done
  warn "Could not install DE CloudflareWARP return routes within 60 seconds."
  return 1
}

watch_de_warp_routes() {
  need_root
  [ -f "$CONFIG_FILE" ] || die "Configuration not found: $CONFIG_FILE"
  load_config
  [ "$ROLE" = "de" ] || die "watch-de-routes is valid only on the DE role."

  log "Watching CloudflareWARP return routes for $WDTT_NET."
  while :; do
    ensure_de_warp_return_routes_once || true
    sleep 3
  done
}

apply_de() {
  ip link show dev "$MESH_BRIDGE" >/dev/null 2>&1 || die "$MESH_BRIDGE does not exist. Is the Mesh container running?"
  if [ -z "$EXT_IF" ]; then
    EXT_IF="$(ip -4 route show table main default | awk 'NR==1{print $5}')"
  fi
  [ -n "$EXT_IF" ] || die "Could not detect the DE public interface. Use --ext-if during install."
  ip link show dev "$EXT_IF" >/dev/null 2>&1 || die "DE public interface $EXT_IF does not exist."

  sysctl -q -w net.ipv4.ip_forward=1
  sysctl -q -w "net.ipv4.conf.${MESH_BRIDGE}.rp_filter=2" || true

  # If the Cloudflare container preserves the original WDTT source, this route
  # gives conntrack-restored return packets a path back to the Mesh node.
  ip -4 route replace "$WDTT_NET" via "$MESH_CONTAINER_IP" dev "$MESH_BRIDGE"

  iptables -w 5 -N "$CHAIN_DE" 2>/dev/null || true
  iptables -w 5 -F "$CHAIN_DE"
  iptables -w 5 -A "$CHAIN_DE" -i "$MESH_BRIDGE" -o "$EXT_IF" -j ACCEPT
  iptables -w 5 -A "$CHAIN_DE" -i "$EXT_IF" -o "$MESH_BRIDGE" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  iptables -w 5 -A "$CHAIN_DE" -j RETURN

  remove_forward_jumps_by_comment "$COMMENT_DE"
  ensure_jump "$CHAIN_DE" "$COMMENT_DE" -i "$MESH_BRIDGE"
  ensure_jump "$CHAIN_DE" "$COMMENT_DE" -i "$EXT_IF" -o "$MESH_BRIDGE" -m conntrack --ctstate RELATED,ESTABLISHED

  if ! iptables -w 5 -t nat -C POSTROUTING -s "$MESH_DOCKER_NET" -o "$EXT_IF" -m comment --comment "$COMMENT_DE_NAT" -j MASQUERADE 2>/dev/null; then
    iptables -w 5 -t nat -I POSTROUTING 1 -s "$MESH_DOCKER_NET" -o "$EXT_IF" -m comment --comment "$COMMENT_DE_NAT" -j MASQUERADE
  fi
  if ! iptables -w 5 -t nat -C POSTROUTING -s "$WDTT_NET" -o "$EXT_IF" -m comment --comment "$COMMENT_DE_NAT" -j MASQUERADE 2>/dev/null; then
    iptables -w 5 -t nat -I POSTROUTING 1 -s "$WDTT_NET" -o "$EXT_IF" -m comment --comment "$COMMENT_DE_NAT" -j MASQUERADE
  fi

  ensure_de_warp_return_routes_wait || true

  log "DE Mesh exit routing is active through $EXT_IF."
}

remove_de_runtime() {
  [ -n "$EXT_IF" ] || EXT_IF="$(ip -4 route show table main default | awk 'NR==1{print $5}')"
  ip -4 route del "$WDTT_NET" via "$MESH_CONTAINER_IP" dev "$MESH_BRIDGE" 2>/dev/null || true
  remove_forward_jumps_by_comment "$COMMENT_DE"
  if [ -n "$EXT_IF" ]; then
    while iptables -w 5 -t nat -C POSTROUTING -s "$MESH_DOCKER_NET" -o "$EXT_IF" -m comment --comment "$COMMENT_DE_NAT" -j MASQUERADE 2>/dev/null; do
      iptables -w 5 -t nat -D POSTROUTING -s "$MESH_DOCKER_NET" -o "$EXT_IF" -m comment --comment "$COMMENT_DE_NAT" -j MASQUERADE
    done
    while iptables -w 5 -t nat -C POSTROUTING -s "$WDTT_NET" -o "$EXT_IF" -m comment --comment "$COMMENT_DE_NAT" -j MASQUERADE 2>/dev/null; do
      iptables -w 5 -t nat -D POSTROUTING -s "$WDTT_NET" -o "$EXT_IF" -m comment --comment "$COMMENT_DE_NAT" -j MASQUERADE
    done
  fi
  iptables -w 5 -F "$CHAIN_DE" 2>/dev/null || true
  iptables -w 5 -X "$CHAIN_DE" 2>/dev/null || true
}

write_config() {
  umask 077
  cat >"$CONFIG_FILE" <<EOF_CONF
ROLE='$ROLE'
ACCOUNT_ID='$ACCOUNT_ID'
TEAM_NAME='$TEAM_NAME'
NODE_NAME='$NODE_NAME'
NODE_ID='$NODE_ID'
EXIT_ROUTE_ID='$EXIT_ROUTE_ID'
EXIT_ROUTE_ID_A='$EXIT_ROUTE_ID_A'
EXIT_ROUTE_ID_B='$EXIT_ROUTE_ID_B'
WDTT_ROUTE_ID='$WDTT_ROUTE_ID'
WDTT_IF='$WDTT_IF'
WDTT_NET='$WDTT_NET'
PROBE_IP='$PROBE_IP'
ROUTE_TABLE='$ROUTE_TABLE'
RULE_PREF='$RULE_PREF'
EXT_IF='$EXT_IF'
MESH_IMAGE='$MESH_IMAGE'
MESH_CONTAINER='$MESH_CONTAINER'
MESH_DOCKER_NETWORK='$MESH_DOCKER_NETWORK'
MESH_BRIDGE='$MESH_BRIDGE'
MESH_DOCKER_NET='$MESH_DOCKER_NET'
MESH_DOCKER_GW='$MESH_DOCKER_GW'
MESH_CONTAINER_IP='$MESH_CONTAINER_IP'
VLESS_CONTAINER='$VLESS_CONTAINER'
VLESS_IMAGE='$VLESS_IMAGE'
VLESS_CONFIG_DIR='$VLESS_CONFIG_DIR'
VLESS_CONFIG_FILE='$VLESS_CONFIG_FILE'
VLESS_UUID_FILE='$VLESS_UUID_FILE'
VLESS_PORT='$VLESS_PORT'
VLESS_UUID='$VLESS_UUID'
VLESS_TAG='$VLESS_TAG'
VLESS_SEND_THROUGH='$VLESS_SEND_THROUGH'
VLESS_MESH_IP='$VLESS_MESH_IP'
VLESS_BACKEND='${VLESS_BACKEND:-legacy}'
XUI_VERSION='$XUI_VERSION'
XUI_INBOUND_REMARK='$XUI_INBOUND_REMARK'
XUI_INBOUND_ID='$XUI_INBOUND_ID'
XUI_INBOUND_TAG='$XUI_INBOUND_TAG'
XUI_INBOUND_CREATED='$XUI_INBOUND_CREATED'
XUI_PANEL_INSTALLED_BY_SCRIPT='$XUI_PANEL_INSTALLED_BY_SCRIPT'
EOF_CONF
  chmod 600 "$CONFIG_FILE"
}

install_persistence() {
  local self
  self="$(readlink -f "$0")"
  [ -x "$self" ] || die "Install this script as an executable file before running install."

  cat >"$SYSTEMD_UNIT" <<EOF_UNIT
[Unit]
Description=WDTT Cloudflare Mesh selective egress
After=docker.service network-online.target
Wants=docker.service network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${self} apply
ExecStop=${self} disable

[Install]
WantedBy=multi-user.target
EOF_UNIT

  if [ "$ROLE" = "msk" ]; then
    rm -f "$DE_WARP_WATCH_UNIT"
    mkdir -p "$WDTT_DROPIN_DIR"
    cat >"$WDTT_DROPIN_FILE" <<EOF_DROPIN
[Unit]
Wants=wdtt-mesh-egress.service
After=wdtt-mesh-egress.service

[Service]
ExecStartPost=${self} apply
EOF_DROPIN
  else
    rm -f "$WDTT_DROPIN_FILE"
    rmdir "$WDTT_DROPIN_DIR" 2>/dev/null || true
    cat >"$DE_WARP_WATCH_UNIT" <<EOF_WATCH
[Unit]
Description=WDTT DE CloudflareWARP return-route keeper
After=docker.service wdtt-mesh-egress.service
Wants=docker.service
PartOf=wdtt-mesh-egress.service

[Service]
Type=simple
ExecStart=${self} watch-de-routes
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF_WATCH
  fi

  systemctl daemon-reload
  systemctl enable wdtt-mesh-egress.service >/dev/null

  if [ "$ROLE" = "de" ]; then
    systemctl enable --now wdtt-mesh-de-warp-routes.service >/dev/null
    if [ "${VLESS_BACKEND:-legacy}" = "xui" ]; then
      install_xui_relay_persistence
      systemctl enable --now wdtt-mesh-xui-relay.service >/dev/null
    else
      systemctl disable --now wdtt-mesh-xui-relay.service >/dev/null 2>&1 || true
    fi
  else
    systemctl disable --now wdtt-mesh-de-warp-routes.service >/dev/null 2>&1 || true
    systemctl disable --now wdtt-mesh-xui-relay.service >/dev/null 2>&1 || true
  fi
}

remove_persistence() {
  systemctl disable --now wdtt-mesh-de-warp-routes.service >/dev/null 2>&1 || true
  systemctl disable --now wdtt-mesh-xui-relay.service >/dev/null 2>&1 || true
  systemctl disable wdtt-mesh-egress.service >/dev/null 2>&1 || true
  rm -f "$SYSTEMD_UNIT" "$DE_WARP_WATCH_UNIT" "$XUI_RELAY_UNIT" "$WDTT_DROPIN_FILE"
  rmdir "$WDTT_DROPIN_DIR" 2>/dev/null || true
  systemctl daemon-reload
}

install_role() {
  need_root
  ROLE="$1"; shift
  [ "$ROLE" = "de" ] || [ "$ROLE" = "msk" ] || die "Invalid role: $ROLE"
  NODE_NAME="wdtt-${ROLE}"
  parse_install_options "$@"
  validate_install_config
  install_prereqs

  ensure_cf_account_settings
  ensure_cf_mesh_profile
  ensure_cf_node

  if [ "$ROLE" = "de" ]; then
    # Do not rely on a competing 0.0.0.0/0 route. Two /1 routes are more
    # specific than the normal Internet default and therefore force public
    # IPv4 traffic selected for Mesh toward the German node.
    remove_cf_route_by_network_if_owned "0.0.0.0/0"
    ensure_cf_route "0.0.0.0/1" "WDTT German Internet exit A"
    EXIT_ROUTE_ID_A="$ROUTE_ID"
    ensure_cf_route "128.0.0.0/1" "WDTT German Internet exit B"
    EXIT_ROUTE_ID_B="$ROUTE_ID"

    if [ -z "$EXT_IF" ]; then
      EXT_IF="$(ip -4 route show table main default | awk 'NR==1{print $5}')"
    fi
    deploy_mesh_container "true"
    VLESS_BACKEND="legacy"
    ensure_vless_credentials
    VLESS_MESH_IP="$(wait_mesh_virtual_ipv4 || true)"
    [ -n "$VLESS_MESH_IP" ] || die "DE Mesh connected, but CloudflareWARP IPv4 was not assigned."
  else
    ensure_cf_route "$WDTT_NET" "WDTT client return route to MSK"
    WDTT_ROUTE_ID="$ROUTE_ID"

    # The Moscow node is the ingress/router side. Do not enable local source
    # NAT there: otherwise forwarded WDTT traffic may obtain a usable local
    # Internet path through the MSK container instead of being forced across
    # Mesh. The German exit node keeps SRCNAT enabled.
    deploy_mesh_container "false"
  fi

  write_config
  install_persistence
  if [ "$ROLE" = "de" ]; then
    apply_de
    deploy_vless_container
    print_vless_profile
    if [ "$XUI_ENABLE_ON_INSTALL" = "1" ]; then
      enable_xui_egress_saved
    fi
  else
    apply_msk
  fi

  log "Installation complete for role: $ROLE"
  warn "Cloudflare requires one human-only setting: enable 'Allow all Cloudflare One traffic to reach enrolled devices' in the dashboard if it is not already enabled."
  warn "The device profile '$PROFILE_NAME' is FULL-TUNNEL for ALL Mesh nodes matching warp_connector@${TEAM_NAME}.cloudflareaccess.com. A dedicated Zero Trust account is strongly recommended."
}

apply_saved() {
  need_root
  [ -f "$CONFIG_FILE" ] || die "Configuration not found: $CONFIG_FILE"
  load_config
  command -v docker >/dev/null 2>&1 || die "Docker is not installed."
  docker inspect "$MESH_CONTAINER" >/dev/null 2>&1 || die "Mesh container $MESH_CONTAINER is missing."
  docker start "$MESH_CONTAINER" >/dev/null 2>&1 || true
  if [ "$ROLE" = "de" ]; then
    apply_de
    if [ "${VLESS_BACKEND:-legacy}" = "xui" ]; then
      command -v socat >/dev/null 2>&1 || die "socat is required for the 3x-ui relay."
      systemctl start "$XUI_SERVICE" >/dev/null 2>&1 || die "Could not start 3x-ui."
      ensure_xui_input_rule
      wait_xui_host_listener || die "3x-ui private listener ${MESH_DOCKER_GW}:${VLESS_PORT} is not ready. Use rollback if 3x-ui cannot be restored."
      install_xui_relay_persistence
      systemctl restart wdtt-mesh-xui-relay.service
      wait_xui_relay_listener || die "Mesh->3x-ui relay is not listening. Use rollback to return to the legacy VLESS backend."
    else
      ensure_vless_container
    fi
  elif [ "$ROLE" = "msk" ]; then
    apply_msk
  else
    die "Unknown saved role: $ROLE"
  fi
}

disable_saved() {
  need_root
  [ -f "$CONFIG_FILE" ] || { warn "Configuration not found; nothing to disable."; return 0; }
  load_config
  if [ "$ROLE" = "de" ]; then
    systemctl stop wdtt-mesh-de-warp-routes.service >/dev/null 2>&1 || true
    if [ "${VLESS_BACKEND:-legacy}" = "xui" ]; then
      systemctl stop wdtt-mesh-xui-relay.service >/dev/null 2>&1 || true
      remove_xui_input_rule
    else
      docker stop "$VLESS_CONTAINER" >/dev/null 2>&1 || true
    fi
    remove_de_runtime
  elif [ "$ROLE" = "msk" ]; then
    remove_msk_runtime
  fi
  log "Runtime WDTT Mesh egress rules removed. Mesh container remains installed."
}

enable_saved() {
  apply_saved
  install_persistence
  log "WDTT Mesh egress enabled."
  if [ "$ROLE" = "de" ]; then
    print_vless_profile
  fi
}

show_status() {
  need_root
  [ -f "$CONFIG_FILE" ] || die "Configuration not found: $CONFIG_FILE"
  load_config

  local pid warp_table srcnat mesh_status xui_inbound api_list
  printf 'WDTT Mesh egress router v%s\n' "$VERSION"
  printf 'Report time (UTC): %s\n\n' "$(date -u '+%Y-%m-%d %H:%M:%S')"

  printf '==================== SAVED CONFIG ====================\n'
  printf 'Role:                 %s\n' "$ROLE"
  printf 'Node:                 %s (%s)\n' "$NODE_NAME" "$NODE_ID"
  printf 'WDTT network:         %s\n' "$WDTT_NET"
  printf 'Mesh Docker network:  %s\n' "$MESH_DOCKER_NET"
  printf 'Docker bridge:        %s (%s -> %s)\n' "$MESH_BRIDGE" "$MESH_DOCKER_GW" "$MESH_CONTAINER_IP"
  printf 'Mesh image:           %s\n' "$MESH_IMAGE"
  printf 'VLESS endpoint:       %s:%s\n' "$(get_mesh_virtual_ipv4 2>/dev/null || printf '%s' "${VLESS_MESH_IP:-<unknown>}")" "$VLESS_PORT"
  printf 'VLESS backend:        %s\n' "${VLESS_BACKEND:-legacy}"
  printf 'MSK outbound tag:     %s\n' "$VLESS_TAG"
  printf 'MSK sendThrough:      %s\n' "$VLESS_SEND_THROUGH"
  if [ "$ROLE" = "de" ]; then
    printf 'DE external iface:    %s\n' "$EXT_IF"
    printf 'CF exit route IDs:    %s / %s\n' "${EXIT_ROUTE_ID_A:-<none>}" "${EXIT_ROUTE_ID_B:-<none>}"
  else
    printf 'CF WDTT route ID:     %s\n' "${WDTT_ROUTE_ID:-<none>}"
  fi
  if [ -f "$LAST_BACKUP_FILE" ]; then
    printf 'Last rollback backup: %s\n' "$(cat "$LAST_BACKUP_FILE" 2>/dev/null || true)"
  fi

  printf '\n==================== HOST NETWORK ====================\n'
  printf 'IPv4 forwarding: '
  sysctl -n net.ipv4.ip_forward 2>/dev/null || true
  ip -br -4 addr show "$MESH_BRIDGE" 2>/dev/null || true
  [ -n "$EXT_IF" ] && ip -br -4 addr show "$EXT_IF" 2>/dev/null || true
  printf '\nMain default route:\n'
  ip -4 route show table main default 2>/dev/null || true

  printf '\n==================== CLOUDFLARE MESH ====================\n'
  docker ps -a --filter "name=^/${MESH_CONTAINER}$" --format '  {{.Names}}  {{.Status}}  {{.Image}}' 2>/dev/null || true
  srcnat="$(sed -n 's/^SRCNAT_ENABLED=//p' "$NODE_ENV_FILE" 2>/dev/null | tail -n1)"
  printf 'SRCNAT_ENABLED: %s\n' "${srcnat:-<unknown>}"
  mesh_status="$(docker exec "$MESH_CONTAINER" warp-cli --accept-tos status 2>/dev/null || true)"
  printf '%s\n' "$mesh_status"
  printf '\nCloudflare One settings (relevant excerpt):\n'
  docker exec "$MESH_CONTAINER" warp-cli --accept-tos settings 2>/dev/null \
    | grep -E 'Mode:|WARP tunnel protocol:|Exclude mode|Organization:|Profile ID:|Register Tunnel Interface IP:' \
    || true

  pid="$(get_mesh_container_pid 2>/dev/null || true)"
  if [ -n "$pid" ] && [ "$pid" != "0" ]; then
    printf '\nMesh namespace PID: %s\n' "$pid"
    printf 'Namespace addresses:\n'
    nsenter -t "$pid" -n ip -br -4 addr 2>/dev/null | sed 's/^/  /' || true
    printf 'Namespace policy rules:\n'
    nsenter -t "$pid" -n ip -4 rule 2>/dev/null | sed 's/^/  /' || true
    warp_table="$(detect_cloudflare_warp_table "$pid" 2>/dev/null || true)"
    if [ -n "$warp_table" ]; then
      printf 'CloudflareWARP policy table: %s\n' "$warp_table"
      nsenter -t "$pid" -n ip -4 route show table "$warp_table" 2>/dev/null \
        | grep -E "^(${WDTT_NET//./\\.}|100\\.64\\.0\\.0/12|100\\.96\\.0\\.0/12) " \
        | sed 's/^/  /' || true
    fi
  else
    printf 'Mesh namespace: unavailable\n'
  fi

  if [ "$ROLE" = "msk" ]; then
    printf '\n==================== MSK POLICY ROUTING ====================\n'
    ip -4 rule show | grep -E "^${RULE_PREF}:" || true
    printf '\nTable %s:\n' "$ROUTE_TABLE"
    ip -4 route show table "$ROUTE_TABLE" 2>/dev/null || true
    printf '\nFirewall chain %s:\n' "$CHAIN_MSK"
    iptables -w 5 -vnL "$CHAIN_MSK" 2>/dev/null || true
  else
    printf '\n==================== DE RETURN / FORWARD ====================\n'
    printf 'Route back to WDTT clients:\n'
    ip -4 route show "$WDTT_NET" 2>/dev/null || true
    printf '\nFirewall chain %s:\n' "$CHAIN_DE"
    iptables -w 5 -vnL "$CHAIN_DE" 2>/dev/null || true
    printf '\nNAT rules owned by this script:\n'
    iptables -w 5 -t nat -vnL POSTROUTING 2>/dev/null | grep -F "$COMMENT_DE_NAT" || true
    printf '\nPrivate INPUT exception for 3x-ui backend:\n'
    iptables -w 5 -vnL INPUT --line-numbers 2>/dev/null | grep -F "$XUI_INPUT_COMMENT" || true

    printf '\n==================== PRIVATE VLESS BACKEND ====================\n'
    if [ "${VLESS_BACKEND:-legacy}" = "xui" ]; then
      printf 'Mode: Mesh namespace RAW/TCP relay -> local 3x-ui/Xray\n'
      printf 'No TLS/REALITY/encryption is added on the DE-internal hop.\n'
      printf '\n3x-ui service:\n'
      systemctl --no-pager --full status "$XUI_SERVICE" 2>/dev/null | sed -n '1,10p' || true
      printf '\n3x-ui binary version:\n'
      "$XUI_BIN" -v 2>/dev/null | head -n3 || true
      printf '\nSaved Mesh inbound: id=%s tag=%s remark=%s\n' \
        "${XUI_INBOUND_ID:-<unknown>}" "${XUI_INBOUND_TAG:-<unknown>}" "$XUI_INBOUND_REMARK"
      printf 'Host listener expected: %s:%s\n' "$MESH_DOCKER_GW" "$VLESS_PORT"
      ss -H -lntp 2>/dev/null | grep -F "${MESH_DOCKER_GW}:${VLESS_PORT}" | sed 's/^/  /' || true

      printf '\nRelay service:\n'
      systemctl --no-pager --full status wdtt-mesh-xui-relay.service 2>/dev/null | sed -n '1,12p' || true
      if [ -n "$pid" ] && [ "$pid" != "0" ]; then
        printf 'Mesh namespace listeners on port %s:\n' "$VLESS_PORT"
        nsenter -t "$pid" -n ss -H -lntp 2>/dev/null | grep -E "[:.]${VLESS_PORT}[[:space:]]" | sed 's/^/  /' || true
      fi

      printf '\n3x-ui API/inbound verification (secrets redacted):\n'
      if load_xui_runtime_secret >/dev/null 2>&1; then
        api_list="$(xui_api GET '/panel/api/inbounds/list' 2>/dev/null || true)"
        xui_inbound="$(jq -c --arg remark "$XUI_INBOUND_REMARK" '.obj[]? | select(.remark == $remark)' <<<"$api_list" 2>/dev/null | head -n1)"
        if [ -n "$xui_inbound" ]; then
          jq '{id,remark,tag,listen,port,protocol,enable,settings:{clients:[.settings.clients[]? | {email,enable,flow,id:"<redacted>"}],decryption:.settings.decryption},streamSettings,sniffing}' \
            <<<"$xui_inbound" 2>/dev/null || true
        else
          printf '  inbound not returned by API\n'
        fi
        printf '\n3x-ui routing/outbound summary:\n'
        show_xui_routing_summary
      else
        printf '  local API token cache unavailable; data-path checks below do not depend on it.\n'
      fi
    else
      printf 'Mode: legacy isolated Xray container in cloudflare-mesh network namespace\n'
      docker ps -a --filter "name=^/${VLESS_CONTAINER}$" --format '  {{.Names}}  {{.Status}}  {{.Image}}' 2>/dev/null || true
      if [ -n "$pid" ] && [ "$pid" != "0" ]; then
        nsenter -t "$pid" -n ss -H -lntp 2>/dev/null | grep -E "[:.]${VLESS_PORT}[[:space:]]" | sed 's/^/  /' || true
      fi
    fi

    printf '\n==================== DE ROUTE KEEPER ====================\n'
    systemctl --no-pager --full status wdtt-mesh-de-warp-routes.service 2>/dev/null | sed -n '1,10p' || true
  fi

  printf '\n==================== RECENT LOGS ====================\n'
  printf '%s\n' '--- wdtt-mesh-egress.service ---'
  journalctl -u wdtt-mesh-egress.service -n 30 --no-pager 2>/dev/null || true
  if [ "$ROLE" = "de" ] && [ "${VLESS_BACKEND:-legacy}" = "xui" ]; then
    printf '%s\n' '--- wdtt-mesh-xui-relay.service ---'
    journalctl -u wdtt-mesh-xui-relay.service -n 30 --no-pager 2>/dev/null || true
    printf '%s\n' '--- x-ui.service ---'
    journalctl -u x-ui.service -n 30 --no-pager 2>/dev/null | sed -E 's/(apiToken|token|password|privateKey)[=:][^ ]+/\1=<redacted>/Ig' || true
  fi

  printf '\nFor an active path test run:\n  sudo %s selftest\n' "$(readlink -f "$0")"
  if [ "$ROLE" = "de" ] && [ "${VLESS_BACKEND:-legacy}" = "xui" ]; then
    printf 'Emergency network rollback:\n  sudo %s rollback\n' "$(readlink -f "$0")"
  fi
}
delete_cloudflare_resources() {
  [ -n "${CLOUDFLARE_API_TOKEN:-}" ] || die "CLOUDFLARE_API_TOKEN is required with --delete-cloudflare."
  [ -n "$ACCOUNT_ID" ] || die "Saved ACCOUNT_ID is empty."

  local rid
  for rid in "$EXIT_ROUTE_ID" "$EXIT_ROUTE_ID_A" "$EXIT_ROUTE_ID_B" "$WDTT_ROUTE_ID"; do
    [ -n "$rid" ] || continue
    cf_api DELETE "teamnet/routes/${rid}" >/dev/null || warn "Could not delete Cloudflare route $rid (it may already be gone)."
  done
  if [ -n "$NODE_ID" ]; then
    cf_api DELETE "warp_connector/${NODE_ID}" >/dev/null || warn "Could not delete Cloudflare Mesh node $NODE_ID (it may already be gone)."
  fi
  log "Saved Cloudflare route/node resources were removed where present."
}

uninstall_saved() {
  need_root
  DELETE_CLOUDFLARE="0"
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --delete-cloudflare) DELETE_CLOUDFLARE="1"; shift ;;
      -h|--help) usage; return 0 ;;
      *) die "Unknown uninstall option: $1" ;;
    esac
  done
  [ -f "$CONFIG_FILE" ] || die "Configuration not found: $CONFIG_FILE"
  load_config

  if [ "$ROLE" = "de" ]; then
    stop_xui_relay
    remove_xui_input_rule
    remove_de_runtime
  elif [ "$ROLE" = "msk" ]; then
    remove_msk_runtime
  fi
  remove_persistence
  docker rm -f "$VLESS_CONTAINER" >/dev/null 2>&1 || true
  docker rm -f "$MESH_CONTAINER" >/dev/null 2>&1 || true
  docker network rm "$MESH_DOCKER_NETWORK" >/dev/null 2>&1 || true
  docker volume rm wdtt_mesh_data >/dev/null 2>&1 || true

  if [ "$DELETE_CLOUDFLARE" = "1" ]; then
    delete_cloudflare_resources
  fi

  rm -f "$NODE_ENV_FILE" "$CONFIG_FILE" "$XUI_ENV_FILE"
  rm -rf "$VLESS_CONFIG_DIR"
  log "Local Cloudflare Mesh egress deployment removed. 3x-ui itself was left installed and untouched."
  if [ "$DELETE_CLOUDFLARE" != "1" ]; then
    log "Cloudflare account resources were kept. Use uninstall --delete-cloudflare with CLOUDFLARE_API_TOKEN to remove this host's node/route."
  fi
}

ACTION="${1:-}"
[ -n "$ACTION" ] || { usage; exit 1; }
shift || true

case "$ACTION" in
  install-de) install_role de "$@" ;;
  install-msk) install_role msk "$@" ;;
  apply) [ "$#" -eq 0 ] || die "apply accepts no options"; apply_saved ;;
  watch-de-routes) [ "$#" -eq 0 ] || die "watch-de-routes accepts no options"; watch_de_warp_routes ;;
  relay-xui) [ "$#" -eq 0 ] || die "relay-xui accepts no options"; relay_xui_forever ;;
  status) [ "$#" -eq 0 ] || die "status accepts no options"; show_status ;;
  selftest) [ "$#" -eq 0 ] || die "selftest accepts no options"; selftest_saved ;;
  profile) [ "$#" -eq 0 ] || die "profile accepts no options"; need_root; [ -f "$CONFIG_FILE" ] || die "Configuration not found: $CONFIG_FILE"; load_config; print_vless_profile ;;
  enable-xui-egress) [ "$#" -eq 0 ] || die "enable-xui-egress accepts no options"; enable_xui_egress_saved ;;
  rollback) [ "$#" -eq 0 ] || die "rollback accepts no options"; rollback_saved ;;
  disable) [ "$#" -eq 0 ] || die "disable accepts no options"; disable_saved ;;
  enable) [ "$#" -eq 0 ] || die "enable accepts no options"; enable_saved ;;
  uninstall) uninstall_saved "$@" ;;
  -h|--help|help) usage ;;
  *) die "Unknown action: $ACTION" ;;
esac
