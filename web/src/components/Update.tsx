import { useEffect, useState } from 'react'
import { Alert, App, Button, Card, Descriptions, Popconfirm, Space, Typography } from 'antd'
import { get, post } from '../api'
import { useJobs } from './Jobs'
import { navigate } from '../App'

export interface UpdateData {
  current: string
  latest: { tag: string; name: string; notes: string; url: string; published: string }
  available: boolean
  checked: string
  error?: string
  rollback: string
}

export function useUpdate() {
  const [data, setData] = useState<UpdateData | null>(null)
  const load = () => get<UpdateData>('/api/update').then(setData).catch(() => {})
  useEffect(() => {
    load()
    const t = setInterval(load, 10 * 60 * 1000)
    return () => clearInterval(t)
  }, [])
  return { data, setData, load }
}

function useRun() {
  const { message } = App.useApp()
  const { track } = useJobs()
  return async (action: 'update' | 'rollback') => {
    try {
      const r = await post<{ job_id: number }>('/api/update', { action })
      track(r.job_id)
      message.info('Панель перезапустится через несколько секунд — страница обновится сама.')
      // Reload once the restarted panel answers again.
      setTimeout(() => {
        const t = setInterval(() => get('/api/me').then(() => (clearInterval(t), location.reload())).catch(() => {}), 3000)
      }, 8000)
    } catch (e: any) {
      message.error(e.message)
    }
  }
}

/** A banner above every page when a newer release is out. */
export function UpdateBanner() {
  const { data } = useUpdate()
  const run = useRun()
  const [hidden, setHidden] = useState(() => sessionStorage.getItem('update-hidden') || '')
  if (!data?.available || hidden === data.latest.tag) return null
  return (
    <Alert
      type="info"
      showIcon
      banner
      closable
      onClose={() => {
        sessionStorage.setItem('update-hidden', data.latest.tag)
        setHidden(data.latest.tag)
      }}
      title={
        <Space wrap>
          <span>
            Доступна версия <b>{data.latest.tag}</b> (у вас {data.current}).
          </span>
          <Popconfirm title={`Обновить панель до ${data.latest.tag}?`} description="Подпись релиза проверяется. Если новая версия не запустится, вернётся текущая." okText="Обновить" cancelText="Отмена" onConfirm={() => run('update')}>
            <Button size="small" type="primary">
              Обновить
            </Button>
          </Popconfirm>
          <Button size="small" type="link" onClick={() => navigate('/settings')}>
            Что нового
          </Button>
        </Space>
      }
    />
  )
}

/** Version, release notes, update and rollback (Settings page). */
export function UpdateCard() {
  const { data, setData } = useUpdate()
  const run = useRun()
  const [checking, setChecking] = useState(false)
  const { message } = App.useApp()
  if (!data) return <Card title="Обновления" loading />
  const check = async () => {
    setChecking(true)
    try {
      const d = await post<UpdateData>('/api/update/check')
      setData(d)
      if (!d.available && !d.error) message.success('Установлена последняя версия')
    } catch (e: any) {
      message.error(e.message)
    } finally {
      setChecking(false)
    }
  }
  return (
    <Card title="Обновления">
      <Descriptions column={1} size="small" bordered>
        <Descriptions.Item label="Установлена">{data.current}</Descriptions.Item>
        <Descriptions.Item label="Последний релиз">
          {data.latest.tag ? (
            <a href={data.latest.url} target="_blank" rel="noreferrer">
              {data.latest.tag}
            </a>
          ) : (
            '—'
          )}
        </Descriptions.Item>
        <Descriptions.Item label="Проверено">{data.checked ? new Date(data.checked).toLocaleString() : 'ещё нет'}</Descriptions.Item>
      </Descriptions>
      {data.error && <Alert style={{ marginTop: 12 }} type="warning" showIcon title="Не удалось проверить обновления" description={data.error} />}
      {data.available && data.latest.notes && (
        <Typography.Paragraph style={{ marginTop: 12, whiteSpace: 'pre-wrap', maxHeight: 220, overflow: 'auto' }} type="secondary">
          {data.latest.notes}
        </Typography.Paragraph>
      )}
      <Space wrap style={{ marginTop: 12 }}>
        {data.available && (
          <Popconfirm title={`Обновить панель до ${data.latest.tag}?`} description="Подпись релиза проверяется. Если новая версия не запустится, вернётся текущая." okText="Обновить" cancelText="Отмена" onConfirm={() => run('update')}>
            <Button type="primary">Обновить до {data.latest.tag}</Button>
          </Popconfirm>
        )}
        <Button loading={checking} onClick={check}>
          Проверить сейчас
        </Button>
        {data.rollback && (
          <Popconfirm title={`Вернуть версию ${data.rollback}?`} description="Панель и её база вернутся к состоянию перед последним обновлением." okText="Вернуть" cancelText="Отмена" onConfirm={() => run('rollback')}>
            <Button>Откатить к {data.rollback}</Button>
          </Popconfirm>
        )}
      </Space>
      <Typography.Paragraph type="secondary" style={{ marginTop: 12, marginBottom: 0 }}>
        Релизы подписаны ключом проекта: панель и установщик отказываются ставить сборку, подпись которой не совпадает.
      </Typography.Paragraph>
    </Card>
  )
}
