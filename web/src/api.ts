// Thin API client: session cookie + CSRF header, JSON in/out, Russian errors.

let csrf = ''

export function setCsrf(token: string) {
  csrf = token
}

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

let onUnauthorized: () => void = () => {}
export function setUnauthorizedHandler(fn: () => void) {
  onUnauthorized = fn
}

export async function api<T = unknown>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {}
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  if (method !== 'GET') headers['X-CSRF-Token'] = csrf
  let res: Response
  try {
    res = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), credentials: 'same-origin' })
  } catch {
    throw new ApiError(0, 'Панель недоступна. Проверьте соединение.')
  }
  const text = await res.text()
  let data: any = null
  try {
    data = text ? JSON.parse(text) : null
  } catch {
    data = null
  }
  if (!res.ok) {
    if (res.status === 401 && path !== '/api/login') onUnauthorized()
    throw new ApiError(res.status, data?.error || `Ошибка ${res.status}`)
  }
  return data as T
}

export const get = <T,>(p: string) => api<T>('GET', p)
export const post = <T,>(p: string, b?: unknown) => api<T>('POST', p, b)
export const put = <T,>(p: string, b?: unknown) => api<T>('PUT', p, b)
export const patch = <T,>(p: string, b?: unknown) => api<T>('PATCH', p, b)
export const del = <T,>(p: string) => api<T>('DELETE', p)
