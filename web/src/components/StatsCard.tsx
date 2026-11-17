import { useEffect, useState } from 'react'
import { App, Button, Card, InputNumber, Popconfirm, Progress, Space, Switch, Typography } from 'antd'
import { DeleteOutlined, DownloadOutlined } from '@ant-design/icons'
import dayjs from 'dayjs'
import { download, post, put } from '../api'
import { fmtBytes, usePoll } from '../util'

interface StatsInfo {
  enabled: boolean
  limit_mb: number
  default_mb: number
  bytes: number
  files: number
  oldest?: number
  newest?: number
  disk_free: number
  disk_total: number
}

/** Statistics TurnVK clients send about their connections: size, limit, clearing. */
export default function StatsCard() {
  const { data, setData } = usePoll<StatsInfo>('/api/stats', 30000)
  const [limit, setLimit] = useState<number | null>(null)
  const [enabled, setEnabled] = useState(true)
  const [busy, setBusy] = useState('')
  const { message } = App.useApp()

  useEffect(() => {
    if (data && limit === null) {
      setLimit(data.limit_mb)
      setEnabled(data.enabled)
    }
  }, [data, limit])

  const run = async (what: string, fn: () => Promise<void>) => {
    setBusy(what)
    try {
      await fn()
    } catch (e: any) {
      message.error(e.message)
    } finally {
      setBusy('')
    }
  }
  const save = (on = enabled, mb = limit) =>
    run('save', async () => {
      const d = await put<StatsInfo>('/api/stats', { enabled: on, limit_mb: mb })
      setData(d)
      message.success(on ? `Сохранено: не больше ${mb} МБ` : 'Сбор статистики выключен')
    })
  const clear = () =>
    run('clear', async () => {
      setData(await post<StatsInfo>('/api/stats/clear'))
      message.success('Статистика удалена')
    })
  const get = () => run('download', () => download('/api/stats/download', {}, 'turnvk-stats.zip'))

  const used = data ? Math.min(100, Math.round((data.bytes / ((data.limit_mb || data.default_mb) * 1048576)) * 100)) : 0
  const changed = data && (limit !== data.limit_mb || enabled !== data.enabled)

  return (
    <Card title="Статистика TurnVK">
      <Typography.Paragraph type="secondary">
        Клиенты TurnVK раз в минуту сообщают серверу, как идёт подключение: трафик, маршруты, задержки, потери, переподключения и
        предупреждения. Сервер добавляет то, что видит сам. Адреса сайтов и содержимое трафика не собираются. Записи хранятся по часам, старые сжимаются;
        при достижении лимита удаляются самые старые.
      </Typography.Paragraph>
      {data && (
        <>
          <Progress percent={used} status={used >= 95 ? 'exception' : 'normal'} format={() => `${fmtBytes(data.bytes)} из ${data.limit_mb} МБ`} />
          <Typography.Paragraph type="secondary" style={{ marginTop: 4 }}>
            {data.files > 0 && data.oldest
              ? `Записи с ${dayjs.unix(data.oldest).format('DD.MM.YYYY HH:00')} по ${dayjs.unix(data.newest!).format('DD.MM.YYYY HH:59')} ( , файлов: ${data.files}).`
              : 'Записей пока нет.'}
            {data.disk_total > 0 && ` Свободно на диске: ${fmtBytes(data.disk_free)} из ${fmtBytes(data.disk_total)}.`}
          </Typography.Paragraph>
          <Space wrap align="center" style={{ marginBottom: 16 }}>
            <Switch checked={enabled} onChange={setEnabled} />
            <span>Собирать</span>
            <span style={{ marginLeft: 12 }}>Лимит</span>
            <InputNumber min={10} max={102400} step={100} value={limit} onChange={(v) => setLimit(v)} addonAfter="МБ" style={{ width: 150 }} disabled={!enabled} />
            <Button type="primary" disabled={!changed || !limit} loading={busy === 'save'} onClick={() => save()}>
              Сохранить
            </Button>
          </Space>
          <Space wrap>
            <Button icon={<DownloadOutlined />} disabled={!data.files} loading={busy === 'download'} onClick={get}>
              Скачать
            </Button>
            <Popconfirm title="Удалить всю статистику?" description="Записи удалятся с сервера без возможности восстановления." okText="Удалить" okButtonProps={{ danger: true }} cancelText="Отмена" onConfirm={clear}>
              <Button danger icon={<DeleteOutlined />} disabled={!data.files} loading={busy === 'clear'}>
                Очистить
              </Button>
            </Popconfirm>
          </Space>
        </>
      )}
    </Card>
  )
}
