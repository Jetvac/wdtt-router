// The app's local API (served by the Windows app itself, not the panel).

export interface Server {
  id: string
  name: string
  host: string
  port: number
  user: string
  added: string
  last_used?: string
  version?: string
  active: boolean
}

export interface AppState {
  version: string
  device: string
  public_key: string
  active: string
  connecting: string
  error: string
  level: 'ok' | 'bad' | 'off' | 'wait'
  text: string
  servers: Server[]
}

export type ServerState = 'ready' | 'old_panel' | 'stopped' | 'no_panel' | 'agent_only' | 'unsupported' | 'need_login'

export interface CheckResult {
  server_id?: string
  state: ServerState
  version?: string
  os?: string
  login?: string
  password?: string
}

export interface OpView {
  done: boolean
  error: string
  result: CheckResult | null
  log: string[]
}

export async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
  let res: Response
  try {
    res = await fetch('/_app/api/' + path, {
      method,
      headers: { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: 'same-origin',
    })
  } catch {
    throw new Error('Приложение не отвечает')
  }
  const data = await res.json().catch(() => null)
  if (!res.ok) throw new Error(data?.error || `Ошибка ${res.status}`)
  return data as T
}

/** Starts an operation and calls onUpdate with its log until it ends. */
export async function runOp(start: Promise<{ op: string }>, onUpdate: (v: OpView) => void): Promise<OpView> {
  const { op } = await start
  for (;;) {
    const v = await call<OpView>('GET', 'ops/' + op)
    onUpdate(v)
    if (v.done) return v
    await new Promise((r) => setTimeout(r, 600))
  }
}
