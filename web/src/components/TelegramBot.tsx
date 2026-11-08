import { useEffect, useState } from 'react'
import { Alert, App, Button, Card, Checkbox, Form, Input, List, Popconfirm, Select, Space, Typography } from 'antd'
import { DeleteOutlined, SendOutlined } from '@ant-design/icons'
import { del, get, post, put } from '../api'
import { useJobs } from './Jobs'
import type { NodeView } from '../types'

interface BotData {
  node_id: number
  has_token: boolean
  chats: { id: number; name: string; added: string }[]
  alerts: Record<string, boolean>
  pair_code?: string
  pair_expires?: string
  bot_seen?: string
  bot_telegram?: string
}

const ALERTS: [string, string][] = [
  ['servers', 'Сервер недоступен / снова на связи'],
  ['chain', 'Цепочка не работает / восстановилась'],
  ['wdtt', 'Сервер WDTT остановился / запустился'],
  ['security', 'Вход в панель с нового адреса, подбор пароля, нужна перезагрузка'],
  ['jobs', 'Ошибки задач'],
]

/** Telegram bot: where it runs, its token, alerts and paired chats. */
export default function TelegramBot({ nodes }: { nodes: NodeView[] }) {
  const [data, setData] = useState<BotData | null>(null)
  const [busy, setBusy] = useState(false)
  const [form] = Form.useForm()
  const { message } = App.useApp()
  const { track } = useJobs()
  const load = () => get<BotData>('/api/bot').then(setData).catch((e) => message.error(e.message))
  useEffect(() => {
    load()
    const t = setInterval(load, 10000)
    return () => clearInterval(t)
  }, [])
  useEffect(() => {
    if (data) form.setFieldsValue({ node_id: data.node_id || undefined, alerts: Object.keys(data.alerts).filter((k) => data.alerts[k]) })
  }, [data?.node_id, JSON.stringify(data?.alerts)])
  if (!data) return <Card title="Telegram-бот" loading />

  const save = async (nodeID?: number) => {
    const v = form.getFieldsValue()
    setBusy(true)
    try {
      const alerts = Object.fromEntries(ALERTS.map(([k]) => [k, (v.alerts || []).includes(k)]))
      const r = await put<{ job_id?: number }>('/api/bot', { node_id: nodeID ?? v.node_id ?? 0, token: v.token || '', alerts })
      form.setFieldValue('token', '')
      if (r.job_id) track(r.job_id, () => load())
      else message.success('Сохранено')
      load()
    } catch (e: any) {
      message.error(e.message)
    } finally {
      setBusy(false)
    }
  }
  const code = async () => {
    try {
      await post('/api/bot/code')
      load()
    } catch (e: any) {
      message.error(e.message)
    }
  }
  const test = async () => {
    await post('/api/bot/test')
    message.success('Сообщение отправится в течение 10 секунд')
  }
  const options = nodes.filter((n) => n.local || n.cf_node_id).map((n) => ({ value: n.id, label: n.local ? `${n.name} (сервер панели)` : n.name }))
  const enabled = data.node_id > 0

  return (
    <Card title="Telegram-бот">
      <Typography.Paragraph type="secondary">
        Присылает уведомления и отвечает на <Typography.Text code>/status</Typography.Text> — состояние серверов, цепочки и WDTT без адресов и ключей. Бот не открывает портов: он сам обращается к Telegram и к панели через Mesh. Выберите сервер, с которого Telegram доступен (обычно выходной).
      </Typography.Paragraph>
      <Form form={form} layout="vertical">
        <Form.Item name="token" label="Токен бота" extra={data.has_token ? 'Токен сохранён. Введите новый, чтобы заменить.' : 'Создайте бота у @BotFather и вставьте токен.'}>
          <Input.Password placeholder={data.has_token ? '••••••••' : '123456789:AA…'} autoComplete="off" />
        </Form.Item>
        <Form.Item name="node_id" label="Сервер, на котором работает бот">
          <Select allowClear placeholder="Бот выключен" options={options} />
        </Form.Item>
        <Form.Item name="alerts" label="Уведомлять о событиях">
          <Checkbox.Group options={ALERTS.map(([value, label]) => ({ value, label }))} style={{ display: 'grid', gap: 4 }} />
        </Form.Item>
        <Space wrap>
          <Button type="primary" loading={busy} onClick={() => save()}>
            Сохранить и применить
          </Button>
          {enabled && (
            <Popconfirm title="Выключить бота?" okText="Выключить" cancelText="Отмена" onConfirm={() => save(0)}>
              <Button danger>Выключить</Button>
            </Popconfirm>
          )}
        </Space>
      </Form>
      {enabled && (
        <>
          {(() => {
            const seen = data.bot_seen ? (Date.now() - new Date(data.bot_seen).getTime()) / 1000 : Infinity
            if (seen > 90) return <Alert style={{ marginTop: 16 }} type="warning" showIcon title="Бот не выходит на связь с панелью" description="Он запускается после применения настроек; если сообщение не исчезает через минуту, проверьте журнал задач." />
            if (data.bot_telegram && data.bot_telegram !== 'ok')
              return <Alert style={{ marginTop: 16 }} type="error" showIcon title="С этого сервера Telegram недоступен" description={`${data.bot_telegram}. Выберите сервер за пределами сетей, где Telegram заблокирован.`} />
            return <Alert style={{ marginTop: 16 }} type="success" showIcon title="Бот работает: панель и Telegram доступны" />
          })()}
          <Typography.Title level={5} style={{ marginTop: 20 }}>
            Чаты
          </Typography.Title>
          {data.pair_code ? (
            <Alert
              type="info"
              showIcon
              title={
                <span>
                  Отправьте боту: <Typography.Text code copyable>{`/start ${data.pair_code}`}</Typography.Text>
                </span>
              }
              description={`Код одноразовый, действует до ${new Date(data.pair_expires!).toLocaleTimeString()}.`}
            />
          ) : (
            <Button onClick={code}>Привязать чат</Button>
          )}
          <List
            style={{ marginTop: 12 }}
            size="small"
            locale={{ emptyText: 'Чатов пока нет' }}
            dataSource={data.chats}
            renderItem={(c) => (
              <List.Item
                actions={[
                  <Popconfirm key="d" title="Отвязать чат?" okText="Отвязать" cancelText="Отмена" onConfirm={() => del(`/api/bot/chats/${c.id}`).then(load)}>
                    <Button type="text" size="small" danger icon={<DeleteOutlined />} />
                  </Popconfirm>,
                ]}
              >
                {c.name || c.id} <Typography.Text type="secondary">· с {new Date(c.added).toLocaleDateString()}</Typography.Text>
              </List.Item>
            )}
          />
          {data.chats.length > 0 && (
            <Button icon={<SendOutlined />} style={{ marginTop: 8 }} onClick={test}>
              Проверить уведомления
            </Button>
          )}
        </>
      )}
    </Card>
  )
}
