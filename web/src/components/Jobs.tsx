import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from 'react'
import { Alert, App as AntApp, Badge, Button, Descriptions, Drawer, Space, Tag, Typography } from 'antd'
import { get } from '../api'
import type { Job } from '../types'
import { fmtTime, jobStatus } from '../util'

interface JobsCtx {
  /** Opens the live log of a job and calls onDone when it finishes. */
  track: (id: number, onDone?: (j: Job) => void) => void
  open: (id: number) => void
  active: number
  setActive: (n: number) => void
  version: number
}

const Ctx = createContext<JobsCtx>({ track: () => {}, open: () => {}, active: 0, setActive: () => {}, version: 0 })
export const useJobs = () => useContext(Ctx)

export function JobsProvider({ children }: { children: ReactNode }) {
  const [current, setCurrent] = useState<number | null>(null)
  const [active, setActive] = useState(0)
  const [version, setVersion] = useState(0)
  const callbacks = useRef(new Map<number, (j: Job) => void>())
  const watching = useRef(new Set<number>())
  const { notification } = AntApp.useApp()

  const watch = useCallback(
    (id: number) => {
      if (watching.current.has(id)) return
      watching.current.add(id)
      const tick = async () => {
        try {
          const j = await get<Job>(`/api/jobs/${id}`)
          if (j.status === 'success' || j.status === 'failed') {
            watching.current.delete(id)
            setVersion((v) => v + 1)
            const cb = callbacks.current.get(id)
            callbacks.current.delete(id)
            cb?.(j)
            if (j.status === 'success') notification.success({ title: j.title, description: 'Выполнено', placement: 'bottomRight' })
            else notification.error({ title: j.title, description: j.error, placement: 'bottomRight', duration: 0 })
            return
          }
        } catch {
          /* transient: retry */
        }
        setTimeout(tick, 1500)
      }
      tick()
    },
    [notification],
  )

  const track = useCallback(
    (id: number, onDone?: (j: Job) => void) => {
      if (onDone) callbacks.current.set(id, onDone)
      setCurrent(id)
      setActive((a) => a + 1)
      watch(id)
    },
    [watch],
  )

  return (
    <Ctx.Provider value={{ track, open: setCurrent, active, setActive, version }}>
      {children}
      <JobDrawer id={current} onClose={() => setCurrent(null)} />
    </Ctx.Provider>
  )
}

export function JobStatusTag({ status }: { status: string }) {
  const s = jobStatus[status] || jobStatus.queued
  return <Badge status={s.color as any} text={s.text} />
}

function JobDrawer({ id, onClose }: { id: number | null; onClose: () => void }) {
  const [job, setJob] = useState<Job | null>(null)
  const logRef = useRef<HTMLPreElement>(null)
  useEffect(() => {
    if (id == null) return
    let stop = false
    setJob(null)
    const load = async () => {
      try {
        const j = await get<Job>(`/api/jobs/${id}`)
        if (stop) return
        setJob(j)
        if (j.status === 'queued' || j.status === 'running') setTimeout(load, 1200)
      } catch {
        if (!stop) setTimeout(load, 3000)
      }
    }
    load()
    return () => {
      stop = true
    }
  }, [id])
  useEffect(() => {
    const el = logRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [job?.log])
  const running = job && (job.status === 'queued' || job.status === 'running')
  return (
    <Drawer
      open={id != null}
      onClose={onClose}
      size={640}
      title={
        <Space>
          {job?.title || 'Задача'}
          {job && <JobStatusTag status={job.status} />}
        </Space>
      }
      extra={<Button onClick={onClose}>{running ? 'Свернуть' : 'Закрыть'}</Button>}
    >
      {job && (
        <Space direction="vertical" size="middle" style={{ width: '100%' }}>
          {running && <Alert type="info" showIcon title="Задача выполняется на серверах. Окно можно закрыть — работа продолжится." />}
          {job.status === 'failed' && <Alert type="error" showIcon title="Ошибка" description={job.error} />}
          <Descriptions size="small" column={2} bordered>
            <Descriptions.Item label="№">{job.id}</Descriptions.Item>
            <Descriptions.Item label="Запустил">{job.created_by || '—'}</Descriptions.Item>
            <Descriptions.Item label="Начало">{fmtTime(job.started_at)}</Descriptions.Item>
            <Descriptions.Item label="Окончание">{fmtTime(job.finished_at)}</Descriptions.Item>
          </Descriptions>
          <Typography.Text type="secondary">Журнал выполнения</Typography.Text>
          <pre ref={logRef} className="job-log">
            {job.log || 'Ожидание запуска…'}
          </pre>
          {job.kind && <Tag>{job.kind}</Tag>}
        </Space>
      )}
    </Drawer>
  )
}
