import { useEffect, useState } from 'react'
import { Alert, App, Button, Card, Col, Descriptions, Form, Input, InputNumber, Modal, Popconfirm, Row, Space, Switch, Tag, Typography } from 'antd'
import { EyeOutlined, KeyOutlined, LinkOutlined } from '@ant-design/icons'
import { get, post, put } from '../api'
import { useJobs } from '../components/Jobs'
import { LinkModal, useWDTTKeys } from '../components/WDTTKeys'
import { navigate } from '../App'
import type { EntrySettings, Status, WDTTKeysData } from '../types'
import { fmtBytes, usePoll } from '../util'

export interface ServicesData {
  settings: EntrySettings
  status: Status
  public_host: string
  xui_credentials: boolean
}

export function StateTag({ installed, active }: { installed: boolean; active?: string }) {
  if (!installed) return <Tag>не установлен</Tag>
  return active === 'active' ? <Tag color="success">работает</Tag> : <Tag color="error">{active || 'остановлен'}</Tag>
}

export default function Services() {
  const { data, reload } = usePoll<ServicesData>('/api/services', 15000)
  const { version } = useJobs()
  useEffect(() => {
    reload()
  }, [version, reload])
  const keys = useWDTTKeys(!!data?.settings.wdtt_enabled)
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
          <Card
            title={
              <Space>
                WDTT
                <StateTag installed={data.status.wdtt_installed} active={data.status.wdtt_active} />
              </Space>
            }
            extra={<Button type="primary" onClick={() => navigate('/wdtt')}>Открыть</Button>}
          >
            <Typography.Paragraph type="secondary" style={{ marginBottom: 0 }}>
              WireGuard через TURN-серверы VK для клиентов WDTT. Настройки сервера, ключи доступа, ссылки и QR-коды — на странице WDTT.
              {keys.data ? ` Ключей: ${keys.data.keys.length}.` : ''}
            </Typography.Paragraph>
          </Card>
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

export function WDTTCard({ data, keys, reload }: { data: ServicesData; keys: WDTTKeysData | null; reload: () => void }) {
  const s = data.settings
  const st = data.status
  const rt = keys?.runtime
  const [form] = Form.useForm()
  const [linkOpen, setLinkOpen] = useState(false)
  const [ownerOpen, setOwnerOpen] = useState(false)
  const [ownerForm] = Form.useForm()
  const queue = useQueue(reload)
  const mainHash = keys?.main_vk_hash
  useEffect(() => {
    form.setFieldsValue({ dtls_port: s.wdtt_dtls_port, dns: s.wdtt_dns, mtu: s.wdtt_mtu || 1280 })
  }, [s.wdtt_dtls_port, s.wdtt_dns, s.wdtt_mtu, form])
  useEffect(() => {
    if (mainHash !== undefined) form.setFieldsValue({ vk_hash: mainHash })
  }, [mainHash, form])

  const submit = (enabled: boolean, extra: Record<string, unknown> = {}) => {
    const v = form.getFieldsValue()
    queue(put('/api/services/wdtt', { enabled, dtls_port: v.dtls_port, dns: v.dns, mtu: v.mtu, vk_hash: v.vk_hash ?? '', ...extra }))
  }
  const setOwner = async () => {
    const v = await ownerForm.validateFields()
    setOwnerOpen(false)
    submit(true, { password: v.password })
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
          title={s.wdtt_enabled ? 'Удалить WDTT с сервера?' : 'Включить WDTT?'}
          description={s.wdtt_enabled ? 'Клиенты отключатся. Ключи и устройства сохранятся.' : 'Сервер WDTT встроен в панель и запускается за несколько секунд.'}
          okText="Да"
          cancelText="Нет"
          onConfirm={() => submit(!s.wdtt_enabled)}
        >
          <Switch checked={s.wdtt_enabled} checkedChildren="вкл" unCheckedChildren="выкл" />
        </Popconfirm>
      }
    >
      <Typography.Paragraph type="secondary">
        WireGuard поверх DTLS, замаскированный под медиатрафик звонка, через TURN-серверы VK — для стандартных клиентов WDTT. Наружу открыт только UDP-порт DTLS; на чужие пакеты сервер не отвечает.
      </Typography.Paragraph>
      <Form form={form} layout="vertical">
        <Row gutter={12}>
          <Col xs={24} sm={8}>
            <Form.Item name="dtls_port" label="UDP-порт DTLS">
              <InputNumber min={1024} max={65534} style={{ width: '100%' }} />
            </Form.Item>
          </Col>
          <Col xs={24} sm={10}>
            <Form.Item name="dns" label="DNS для клиентов">
              <Input placeholder="1.1.1.1" />
            </Form.Item>
          </Col>
          <Col xs={24} sm={6}>
            <Form.Item
              name="mtu"
              label="MTU туннеля"
              tooltip="Размер пакета внутри туннеля. По умолчанию 1280. Уменьшите, если на некоторых сетях соединение рвётся или зависает: меньше 1280 учитывают клиенты, которые берут MTU с сервера (стандартный клиент WDTT не опускается ниже 1280). Больше 1340 не помещается в обычную сеть."
            >
              <InputNumber min={1200} max={1340} step={20} style={{ width: '100%' }} />
            </Form.Item>
          </Col>
          <Col span={24}>
            <Form.Item name="vk_hash" label="Хеш звонка VK для ссылки владельца" extra="Ссылка на звонок или её последняя часть; несколько — через запятую.">
              <Input placeholder="https://vk.com/call/join/…" />
            </Form.Item>
          </Col>
        </Row>
      </Form>
      {s.wdtt_enabled && (
        <Descriptions size="small" bordered column={1} style={{ marginBottom: 16 }}>
          <Descriptions.Item label="Сейчас">
            {rt ? (
              <Space wrap size={4}>
                <Tag color={rt.sessions ? 'processing' : 'default'}>сессий: {rt.sessions}</Tag>
                <Tag>устройств: {rt.devices}</Tag>
                {rt.main && (
                  <Tag>
                    владелец ↓{fmtBytes(rt.main.down_bytes)} ↑{fmtBytes(rt.main.up_bytes)}
                  </Tag>
                )}
              </Space>
            ) : (
              <Typography.Text type="secondary">нет данных</Typography.Text>
            )}
          </Descriptions.Item>
          {rt && rt.auth_failures + rt.handshake_failures > 0 && (
            <Descriptions.Item label="Отклонено">
              <Typography.Text type="secondary">
                чужих пакетов: {rt.auth_failures}, незавершённых рукопожатий: {rt.handshake_failures}
              </Typography.Text>
            </Descriptions.Item>
          )}
          <Descriptions.Item label="Владелец">
            <Space wrap>
              <Button size="small" icon={<LinkOutlined />} onClick={() => setLinkOpen(true)}>
                Ссылка и пароль
              </Button>
              <Button size="small" icon={<EyeOutlined />} onClick={() => setOwnerOpen(true)}>
                Задать свой пароль
              </Button>
            </Space>
          </Descriptions.Item>
        </Descriptions>
      )}
      <Space wrap>
        <Button type="primary" onClick={() => submit(s.wdtt_enabled)} disabled={!s.wdtt_enabled}>
          Сохранить параметры
        </Button>
        {s.wdtt_enabled && (
          <Popconfirm
            title="Сменить пароль владельца?"
            description="Устройствам с паролем владельца нужно будет ввести новый. Ключи доступа не изменятся."
            onConfirm={() => submit(true, { rotate_password: true })}
            okText="Сменить"
            cancelText="Отмена"
          >
            <Button icon={<KeyOutlined />}>Сменить пароль владельца</Button>
          </Popconfirm>
        )}
      </Space>
      <LinkModal id={linkOpen ? 'main' : null} title="Подключение владельца" onClose={() => setLinkOpen(false)} />
      <Modal open={ownerOpen} title="Пароль владельца" onCancel={() => setOwnerOpen(false)} onOk={setOwner} okText="Сохранить" cancelText="Отмена" destroyOnHidden>
        <Typography.Paragraph type="secondary">
          Например, пароль прежнего сервера WDTT — тогда его клиентам ничего не придётся менять. Пароль владельца не привязывается к устройству.
        </Typography.Paragraph>
        <Form form={ownerForm} layout="vertical" requiredMark={false}>
          <Form.Item name="password" label="Пароль" rules={[{ required: true, pattern: /^[A-Za-z0-9._-]{16,128}$/, message: '16–128 символов: латиница, цифры, точка, дефис, подчёркивание' }]}>
            <Input.Password autoComplete="new-password" />
          </Form.Item>
        </Form>
      </Modal>
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
