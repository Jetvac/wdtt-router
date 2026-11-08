import { useEffect, useState } from 'react'
import { Alert, App, Button, Card, Col, Descriptions, Form, Input, InputNumber, Popconfirm, Row, Space, Switch, Tag, Typography } from 'antd'
import { EyeOutlined, KeyOutlined } from '@ant-design/icons'
import { get, post, put } from '../api'
import { useJobs } from '../components/Jobs'
import type { EntrySettings, Status } from '../types'
import { usePoll } from '../util'

interface ServicesData {
  settings: EntrySettings
  status: Status
  public_host: string
  xui_credentials: boolean
}

function StateTag({ installed, active }: { installed: boolean; active?: string }) {
  if (!installed) return <Tag>не установлен</Tag>
  return active === 'active' ? <Tag color="success">работает</Tag> : <Tag color="error">{active || 'остановлен'}</Tag>
}

export default function Services() {
  const { data, reload } = usePoll<ServicesData>('/api/services', 15000)
  const { version } = useJobs()
  useEffect(() => {
    reload()
  }, [version, reload])
  if (!data) return <Card loading />
  return (
    <Space orientation="vertical" size="middle" style={{ width: '100%' }}>
      <Alert
        type="info"
        showIcon
        title="Сервисы работают на сервере панели и независимы друг от друга"
        description="Включайте WDTT, 3x-ui или оба. Трафик клиентов любого из них уходит только в цепочку: если цепочка недоступна, у клиентов пропадает Интернет, но трафик никогда не выходит напрямую с адреса сервера панели."
      />
      <Row gutter={[16, 16]}>
        <Col xs={24} xl={12}>
          <WDTTCard data={data} reload={reload} />
        </Col>
        <Col xs={24} xl={12}>
          <XUICard data={data} reload={reload} />
        </Col>
      </Row>
    </Space>
  )
}

function useQueue(reload: () => void) {
  const { track } = useJobs()
  const { message } = App.useApp()
  return async (p: Promise<{ job_id: number }>) => {
    try {
      const r = await p
      track(r.job_id, () => reload())
    } catch (e: any) {
      message.error(e.message)
    }
  }
}

function WDTTCard({ data, reload }: { data: ServicesData; reload: () => void }) {
  const s = data.settings
  const st = data.status
  const [form] = Form.useForm()
  const [secret, setSecret] = useState<Record<string, string> | null>(null)
  const queue = useQueue(reload)
  const { message } = App.useApp()
  useEffect(() => {
    form.setFieldsValue({ dtls_port: s.wdtt_dtls_port, dns: s.wdtt_dns })
  }, [s.wdtt_dtls_port, s.wdtt_dns, form])

  const submit = (enabled: boolean, rotate = false) => {
    const v = form.getFieldsValue()
    setSecret(null)
    queue(put('/api/services/wdtt', { enabled, dtls_port: v.dtls_port, dns: v.dns, rotate_password: rotate }))
  }
  const reveal = async () => {
    try {
      setSecret(await get('/api/services/wdtt/secret'))
    } catch (e: any) {
      message.error(e.message)
    }
  }

  return (
    <Card
      title={
        <Space>
          WDTT
          <StateTag installed={st.wdtt_installed} active={st.wdtt_active} />
        </Space>
      }
      extra={
        <Popconfirm
          title={s.wdtt_enabled ? 'Удалить WDTT с сервера?' : 'Установить WDTT?'}
          description={s.wdtt_enabled ? 'Клиенты отключатся. База клиентов сохранится.' : 'Первая установка собирает сервер из исходников (~2 минуты).'}
          okText="Да"
          cancelText="Нет"
          onConfirm={() => submit(!s.wdtt_enabled)}
        >
          <Switch checked={s.wdtt_enabled} checkedChildren="вкл" unCheckedChildren="выкл" />
        </Popconfirm>
      }
    >
      <Typography.Paragraph type="secondary">
        WireGuard поверх DTLS через медиасерверы VK — для клиентов WDTT (Android). Наружу открыт только UDP-порт DTLS, порт WireGuard слушает локально.
      </Typography.Paragraph>
      <Form form={form} layout="vertical">
        <Row gutter={12}>
          <Col span={10}>
            <Form.Item name="dtls_port" label="UDP-порт DTLS">
              <InputNumber min={1024} max={65534} style={{ width: '100%' }} />
            </Form.Item>
          </Col>
          <Col span={14}>
            <Form.Item name="dns" label="DNS для клиентов">
              <Input placeholder="1.1.1.1" />
            </Form.Item>
          </Col>
        </Row>
      </Form>
      {s.wdtt_enabled && (
        <Descriptions size="small" bordered column={1} style={{ marginBottom: 16 }}>
          <Descriptions.Item label="Интерфейс wdtt0">{st.wdtt_iface ? <Tag color="success">есть</Tag> : <Tag color="error">нет</Tag>}</Descriptions.Item>
          <Descriptions.Item label="Устройств">{st.wdtt_peers}</Descriptions.Item>
          <Descriptions.Item label="Подключение">
            {secret ? (
              <Space orientation="vertical" size={0}>
                <Typography.Text copyable className="mono">{`${secret.host}:${secret.port}`}</Typography.Text>
                <Typography.Text copyable={{ text: secret.password }} className="mono">
                  пароль: {secret.password}
                </Typography.Text>
              </Space>
            ) : (
              <Button size="small" icon={<EyeOutlined />} onClick={reveal}>
                Показать адрес и пароль
              </Button>
            )}
          </Descriptions.Item>
        </Descriptions>
      )}
      <Space wrap>
        <Button type="primary" onClick={() => submit(s.wdtt_enabled)} disabled={!s.wdtt_enabled}>
          Сохранить параметры
        </Button>
        {s.wdtt_enabled && (
          <Popconfirm title="Сменить пароль WDTT?" description="Всем клиентам нужно будет ввести новый пароль." onConfirm={() => submit(true, true)} okText="Сменить" cancelText="Отмена">
            <Button icon={<KeyOutlined />}>Сменить пароль</Button>
          </Popconfirm>
        )}
      </Space>
    </Card>
  )
}

function XUICard({ data, reload }: { data: ServicesData; reload: () => void }) {
  const s = data.settings
  const st = data.status
  const [creds, setCreds] = useState<Record<string, string> | null>(null)
  const queue = useQueue(reload)
  const { message } = App.useApp()
  const set = (enabled: boolean, route: boolean) => {
    setCreds(null)
    queue(put('/api/services/xui', { enabled, route_via_chain: route }))
  }
  const reveal = async () => {
    try {
      setCreds(await get('/api/services/xui/secret'))
    } catch (e: any) {
      message.error(e.message)
    }
  }
  return (
    <Card
      title={
        <Space>
          3x-ui
          <StateTag installed={st.xui_installed} active={st.xui_active} />
        </Space>
      }
      extra={
        <Popconfirm
          title={s.xui_enabled ? 'Удалить 3x-ui?' : 'Установить 3x-ui?'}
          description={s.xui_enabled ? 'Панель, её база и все подключения 3x-ui будут удалены.' : 'Будет установлена 3x-ui v3.11.0, веб-интерфейс доступен только через SSH-туннель.'}
          okText="Да"
          cancelText="Нет"
          onConfirm={() => set(!s.xui_enabled, s.xui_route_via_chain)}
        >
          <Switch checked={s.xui_enabled} checkedChildren="вкл" unCheckedChildren="выкл" />
        </Popconfirm>
      }
    >
      <Typography.Paragraph type="secondary">
        Панель Xray для клиентских подключений (VLESS Reality и др.). Веб-интерфейс и подписки слушают только 127.0.0.1. Порты включённых подключений открываются в firewall автоматически.
      </Typography.Paragraph>
      <Descriptions size="small" bordered column={1} style={{ marginBottom: 16 }}>
        <Descriptions.Item label="Трафик через цепочку">
          <Switch size="small" checked={s.xui_route_via_chain} disabled={!s.xui_enabled} onChange={(v) => set(true, v)} />
          {!s.xui_route_via_chain && s.xui_enabled && <Typography.Text type="warning"> трафик выходит напрямую с сервера панели</Typography.Text>}
        </Descriptions.Item>
        <Descriptions.Item label="Открытые порты">{st.xui_ports?.length ? st.xui_ports.map((p) => <Tag key={p}>{p}</Tag>) : '—'}</Descriptions.Item>
        {s.xui_enabled && (
          <Descriptions.Item label="Доступ к панели">
            {creds ? (
              <Space orientation="vertical" size={4} style={{ width: '100%' }}>
                <Typography.Text type="secondary">1. Туннель с вашего компьютера:</Typography.Text>
                <Typography.Text copyable className="mono" style={{ fontSize: 12 }}>
                  {creds.ssh_tunnel}
                </Typography.Text>
                <Typography.Text type="secondary">2. Откройте:</Typography.Text>
                <Typography.Text copyable className="mono" style={{ fontSize: 12 }}>
                  {creds.url}
                </Typography.Text>
                <Typography.Text copyable={{ text: creds.XUI_USERNAME }}>логин: <span className="mono">{creds.XUI_USERNAME}</span></Typography.Text>
                <Typography.Text copyable={{ text: creds.XUI_PASSWORD }}>пароль: <span className="mono">{creds.XUI_PASSWORD}</span></Typography.Text>
              </Space>
            ) : (
              <Space wrap>
                <Button size="small" icon={<EyeOutlined />} onClick={reveal} disabled={!data.xui_credentials}>
                  Показать доступ
                </Button>
                <Popconfirm title="Задать 3x-ui новые логин и пароль?" onConfirm={() => queue(post('/api/services/xui/reset'))} okText="Да" cancelText="Нет">
                  <Button size="small" icon={<KeyOutlined />}>
                    Сбросить логин и пароль
                  </Button>
                </Popconfirm>
              </Space>
            )}
          </Descriptions.Item>
        )}
      </Descriptions>
    </Card>
  )
}
