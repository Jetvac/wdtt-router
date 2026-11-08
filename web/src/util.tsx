import { useCallback, useEffect, useRef, useState } from 'react'
import { Badge, Tag, Tooltip } from 'antd'
import dayjs from 'dayjs'
import relativeTime from 'dayjs/plugin/relativeTime'
import 'dayjs/locale/ru'
import { get } from './api'
import type { NodeView } from './types'

dayjs.extend(relativeTime)
dayjs.locale('ru')

/** Fetches a resource and refreshes it every `interval` ms while mounted. */
export function usePoll<T>(path: string | null, interval = 0) {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<string>('')
  const [loading, setLoading] = useState(true)
  const alive = useRef(true)
  const load = useCallback(async () => {
    if (!path) return
    try {
      const d = await get<T>(path)
      if (alive.current) {
        setData(d)
        setError('')
      }
    } catch (e: any) {
      if (alive.current) setError(e.message)
    } finally {
      if (alive.current) setLoading(false)
    }
  }, [path])
  useEffect(() => {
    alive.current = true
    load()
    if (!interval) return () => { alive.current = false }
    const t = setInterval(() => {
      if (document.visibilityState === 'visible') load()
    }, interval)
    return () => {
      alive.current = false
      clearInterval(t)
    }
  }, [load, interval])
  return { data, error, loading, reload: load, setData }
}

export const fromNow = (s?: string) => (s ? dayjs(s).fromNow() : '—')
export const fmtTime = (s?: string) => (s ? dayjs(s).format('DD.MM.YYYY HH:mm:ss') : '—')

export function uptime(sec: number) {
  if (!sec) return '—'
  const d = Math.floor(sec / 86400)
  const h = Math.floor((sec % 86400) / 3600)
  const m = Math.floor((sec % 3600) / 60)
  return d ? `${d} д ${h} ч` : h ? `${h} ч ${m} мин` : `${m} мин`
}

export const roleMeta: Record<string, { label: string; color: string }> = {
  entry: { label: 'Вход', color: 'blue' },
  relay: { label: 'Промежуточный', color: 'purple' },
  exit: { label: 'Выход', color: 'green' },
  idle: { label: 'Не в цепочке', color: 'default' },
}

export function RoleTag({ role }: { role: string }) {
  const m = roleMeta[role] || roleMeta.idle
  return <Tag color={m.color}>{m.label}</Tag>
}

/** Overall health of a node: online, problems, or unreachable. */
export function nodeHealth(n: NodeView): { status: 'success' | 'warning' | 'error' | 'default'; text: string } {
  if (n.last_error) return { status: 'error', text: 'Нет связи' }
  if (!n.last_seen) return { status: 'default', text: 'Нет данных' }
  if (n.status?.problems?.length) return { status: 'warning', text: 'Есть проблемы' }
  return { status: 'success', text: 'В сети' }
}

export function HealthBadge({ n }: { n: NodeView }) {
  const h = nodeHealth(n)
  const tip = n.last_error || n.status?.problems?.join('; ') || `Обновлено ${fromNow(n.last_seen)}`
  return (
    <Tooltip title={tip}>
      <Badge status={h.status} text={h.text} />
    </Tooltip>
  )
}

export function MeshTag({ n }: { n: NodeView }) {
  if (!n.cf_node_id) return <Tag>Не подключён</Tag>
  const ok = n.status?.mesh_status === 'Connected'
  return (
    <Tooltip title={n.cf_node_name}>
      <Tag color={ok ? 'success' : 'warning'}>{ok ? n.mesh_ip || 'Подключён' : n.status?.mesh_status || 'Нет связи'}</Tag>
    </Tooltip>
  )
}

export const jobStatus: Record<string, { color: string; text: string }> = {
  queued: { color: 'default', text: 'В очереди' },
  running: { color: 'processing', text: 'Выполняется' },
  success: { color: 'success', text: 'Готово' },
  failed: { color: 'error', text: 'Ошибка' },
}

export function fmtBytes(n?: number) {
  if (!n) return '0 Б'
  const u = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ']
  let i = 0
  let v = n
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024
    i++
  }
  return `${v < 10 && i > 0 ? v.toFixed(1) : Math.round(v)} ${u[i]}`
}
