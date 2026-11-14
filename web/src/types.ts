export interface Status {
  agent_version: string
  hostname: string
  os: string
  arch: string
  kernel: string
  public_iface: string
  public_ipv4: string
  uptime_sec: number
  load1: number
  mem_total_mb: number
  mem_avail_mb: number
  disk_free_mb: number
  spec_role: string
  spec_applied: string
  spec_hash: string
  mesh_installed: boolean
  mesh_status: string
  mesh_ip: string
  mesh_version: string
  xray_installed: boolean
  xray_version: string
  xray_active: string
  firewall_active: boolean
  firewall_ports: string[] | null
  revert_pending: boolean
  wdtt_installed: boolean
  wdtt_active: string
  wdtt_iface: boolean
  wdtt_peers: number
  wdtt?: WDTTRuntime
  wdtt_turnvk?: { installed: boolean; active: string; iface: boolean; runtime?: WDTTRuntime }
  xui_installed: boolean
  xui_active: string
  xui_ports: number[] | null
  net_rx_bytes?: number
  net_tx_bytes?: number
  hardening?: HardeningStatus
  problems: string[] | null
}

export interface HardeningStatus {
  ssh_password_auth: boolean
  ssh_root_login: string
  root_keys: number
  auto_updates: boolean
  reboot_required: boolean
}

export interface Hardening {
  ssh_keys_only?: boolean
  auto_updates?: boolean
  admin_keys?: string[]
}

export interface NodeView {
  id: number
  name: string
  host: string
  ssh_port: number
  fingerprint: string
  local: boolean
  mesh_ip: string
  cf_node_id: string
  cf_node_name: string
  hop_port: number
  ssh_public: boolean
  ssh_allow: string[]
  allow_ping: boolean
  firewall: boolean
  hardening: Hardening
  status: Status
  last_seen: string
  last_error: string
  created_at: string
  role: 'entry' | 'relay' | 'exit' | 'idle'
  in_chain: boolean
  position: number
  out_of_sync: boolean
}

export interface Job {
  id: number
  kind: string
  node_id: number
  title: string
  status: 'queued' | 'running' | 'success' | 'failed'
  log?: string
  error: string
  created_by: string
  created_at: string
  started_at: string
  finished_at: string
}

export interface Probe {
  ok: boolean
  exit_ip: string
  colo: string
  tcp_ms: number
  udp_ok: boolean
  udp_ms: number
  error?: string
  at: string
  exit_node: string
  expected_ip: string
  match: boolean
}

export interface EntrySettings {
  wdtt_enabled: boolean
  wdtt_dtls_port: number
  wdtt_wg_port: number
  wdtt_dns: string
  wdtt_mtu?: number
  xui_enabled: boolean
  xui_route_via_chain: boolean
  xui_public_sub?: boolean
  panel_port: number
  panel_allow: string[]
  turnvk: WDTTServerSettings
}

export interface WDTTServerSettings {
  enabled: boolean
  dtls_port: number
  wg_port: number
  dns: string
  mtu: number
}

/** The two WDTT servers: one for standard WDTT clients, one for TurnVK. */
export type WDTTKind = 'standard' | 'turnvk'


export interface Overview {
  nodes: NodeView[]
  chain: number[]
  plan_error: string
  probe: Probe | null
  services: EntrySettings
  cloudflare: boolean
  jobs: Job[]
  active_jobs: number
  version: string
}

export interface Check {
  key: string
  ok: boolean
  title: string
  detail: string
  fix?: string
  fix_arg?: string
}

export interface WDTTDevice {
  id: string
  ip: string
  sessions: number
  up_bytes: number
  down_bytes: number
  last_seen?: number
  bound_at?: number
}

export interface WDTTKeyRuntime {
  sessions: number
  device_id?: string
  device_ip?: string
  up_bytes: number
  down_bytes: number
  last_seen?: number
  devices?: WDTTDevice[]
}

export interface WDTTRuntime {
  version: string
  started_at: number
  updated_at: number
  sessions: number
  devices: number
  handshake_failures: number
  auth_failures: number
  keys: Record<string, WDTTKeyRuntime>
}

export interface WDTTKey {
  id: string
  name: string
  vk_hash: string
  expires_at: number
  disabled: boolean
  created_at: string
  state: 'active' | 'disabled' | 'expired'
  kind: WDTTKind
  max_devices: number
  devices: WDTTDevice[]
  device_id: string
  device_ip: string
  sessions: number
  up_bytes: number
  down_bytes: number
  last_seen: number
}

export interface WDTTRuntimeView {
  sessions: number
  devices: number
  version: string
  started_at: number
  updated_at: number
  auth_failures: number
  handshake_failures: number
  main?: WDTTKeyRuntime
}

export interface WDTTServerView {
  kind: WDTTKind
  label: string
  enabled: boolean
  dtls_port: number
  main_vk_hash: string
  runtime?: WDTTRuntimeView
  main?: WDTTKeyRuntime
}

/** A device of any key (or of the owner password, key_id "main"). */
export interface WDTTDeviceRow extends WDTTDevice {
  kind: WDTTKind
  key_id: string
  key_name: string
}

export interface WDTTKeysData {
  keys: WDTTKey[]
  limit: number
  max_devices: number
  servers: Record<WDTTKind, WDTTServerView>
  devices: WDTTDeviceRow[]
  main_vk_hash: string
  runtime?: WDTTRuntimeView
}

export interface WDTTLink {
  password: string
  host: string
  port: string
  link?: string
  kind: WDTTKind
  client: string
}
