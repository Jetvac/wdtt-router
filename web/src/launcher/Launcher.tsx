import { useCallback, useEffect, useRef, useState } from 'react'
import {
  Alert,
  App as AntApp,
  Avatar,
  Badge,
  Button,
  Card,
  Collapse,
  Dropdown,
  Form,
  Input,
  InputNumber,
  List,
  Modal,
  Result,
  Space,
  Spin,
  Steps,
  Tag,
  Typography,
  theme,
} from 'antd'
import {
  CheckCircleOutlined,
  CloudServerOutlined,
  DeleteOutlined,
  EditOutlined,
  MoonOutlined,
  MoreOutlined,
  PlusOutlined,
  ReloadOutlined,
  SafetyCertificateOutlined,
  SunOutlined,
  SyncOutlined,
} from '@ant-design/icons'
import { call, runOp, type AppState, type CheckResult, type OpView, type Server } from './api'
import { useThemeMode } from '../theme'
import { fromNow } from '../util'

const auto = new URLSearchParams(window.location.search).has('auto')

/** The app's start screen: the list of panel servers and adding a new one. */
export default function Launcher() {
  const [state, setState] = useState<AppState | null>(null)
  const [adding, setAdding] = useState(false)
  // The welcome wizard stays until it is finished, even once the server is
  // saved (an install may still be ahead).
  const [firstRun, setFirstRun] = useState<boolean | null>(null)
  const [manage, setManage] = useState<{ server: Server; action: 'check' | 'update' | 'restart' } | null>(null)
  const { message, modal } = AntApp.useApp()
  const { token } = theme.useToken()

  const load = useCallback(async () => {
    try {
      const s = await call<AppState>('GET', 'state')
      setState(s)
      setFirstRun((f) => (f === null ? s.servers.length === 0 : f))
      // Started with the app: go straight to the panel once connected.
      if (auto && s.active) window.location.replace('/')
    } catch {
      /* the app is shutting down */
    }
  }, [])
  useEffect(() => {
    load()
    const t = setInterval(load, 2000)
    return () => clearInterval(t)
  }, [load])

  const [opening, setOpening] = useState('')
  const open = async (s: Server) => {
    if (s.active) {
      window.location.assign('/')
      return
    }
    setOpening(s.id)
    try {
      await call('POST', `servers/${s.id}/connect`)
      window.location.assign('/')
    } catch (e: any) {
      message.error({ content: e.message, duration: 8 })
      load()
    } finally {
      setOpening('')
    }
  }

  const rename = (s: Server) => {
    let name = s.name
    modal.confirm({
      title: 'Название сервера',
      icon: <EditOutlined />,
      content: <Input defaultValue={s.name} maxLength={60} onChange={(e) => (name = e.target.value)} />,
      okText: 'Сохранить',
      onOk: async () => {
        await call('PATCH', `servers/${s.id}`, { name })
        load()
      },
    })
  }
  const remove = (s: Server) =>
    modal.confirm({
      title: `Убрать «${s.name}» из списка?`,
      content: 'Панель на сервере продолжит работать. Ключ приложения останется на сервере — добавить сервер снова можно будет без пароля.',
      okText: 'Убрать',
      okButtonProps: { danger: true },
      onOk: async () => {
        await call('DELETE', `servers/${s.id}`)
        load()
      },
    })

  if (!state) return <Spin fullscreen />
  const connecting = state.servers.find((s) => s.id === state.connecting)

  return (
    <div style={{ minHeight: '100vh', background: token.colorBgLayout }}>
      <div style={{ maxWidth: 880, margin: '0 auto', padding: '24px 16px 48px' }}>
        <Header state={state} />
        {connecting && (
          <Alert style={{ marginBottom: 16 }} type="info" showIcon icon={<Spin size="small" />} title={`Подключение к ${connecting.name}…`} />
        )}
        {state.error && !connecting && <Alert style={{ marginBottom: 16 }} type="error" showIcon title={state.error} />}
        {firstRun ? (
          <Card>
            <Typography.Title level={4} style={{ marginTop: 0 }}>
              Добро пожаловать
            </Typography.Title>
            <Typography.Paragraph type="secondary">
              Укажите сервер с панелью WDTT Router — или чистый сервер с Debian или Ubuntu, и приложение само установит на него панель. Панель работает на сервере
              круглосуточно: статистика, Telegram-бот и проверки цепочки не зависят от того, включён ли компьютер. Приложение подключается к ней по SSH, поэтому
              порт панели можно закрыть для Интернета.
            </Typography.Paragraph>
            <AddServer state={state} onDone={load} onClose={() => setFirstRun(false)} />
          </Card>
        ) : (
          <Card
            title="Серверы с панелью"
            extra={
              <Button type="primary" icon={<PlusOutlined />} onClick={() => setAdding(true)}>
                Добавить сервер
              </Button>
            }
          >
            <List
              dataSource={state.servers}
              renderItem={(s) => (
                <List.Item
                  actions={[
                    <Button key="open" type={s.active ? 'primary' : 'default'} loading={opening === s.id} disabled={!!opening && opening !== s.id} onClick={() => open(s)}>
                      Открыть панель
                    </Button>,
                    <Dropdown
                      key="more"
                      trigger={['click']}
                      menu={{
                        items: [
                          { key: 'check', icon: <ReloadOutlined />, label: 'Проверить сервер', onClick: () => setManage({ server: s, action: 'check' }) },
                          { key: 'update', icon: <SyncOutlined />, label: 'Обновить панель', onClick: () => setManage({ server: s, action: 'update' }) },
                          { key: 'restart', icon: <ReloadOutlined />, label: 'Перезапустить панель', onClick: () => setManage({ server: s, action: 'restart' }) },
                          { key: 'rename', icon: <EditOutlined />, label: 'Переименовать', onClick: () => rename(s) },
                          { type: 'divider' },
                          { key: 'remove', icon: <DeleteOutlined />, danger: true, label: 'Убрать из списка', onClick: () => remove(s) },
                        ],
                      }}
                    >
                      <Button type="text" icon={<MoreOutlined />} aria-label="Действия" />
                    </Dropdown>,
                  ]}
                >
                  <List.Item.Meta
                    avatar={
                      <Badge dot={s.active} color={levelColor(state.level, token)} offset={[-4, 30]}>
                        <Avatar shape="square" size={40} icon={<CloudServerOutlined />} style={{ background: s.active ? token.colorPrimary : token.colorFillSecondary }} />
                      </Badge>
                    }
                    title={
                      <Space size={8} wrap>
                        <span>{s.name}</span>
                        {s.active && <Tag color="success">подключено</Tag>}
                      </Space>
                    }
                    description={
                      <Space size={12} wrap>
                        <Typography.Text type="secondary">
                          {s.user}@{s.host}
                          {s.port !== 22 ? `:${s.port}` : ''}
                        </Typography.Text>
                        {s.version && <Typography.Text type="secondary">панель {s.version}</Typography.Text>}
                        {s.last_used && <Typography.Text type="secondary">открывали {fromNow(s.last_used)}</Typography.Text>}
                      </Space>
                    }
                  />
                </List.Item>
              )}
            />
          </Card>
        )}
        {state.active && state.text && (
          <Card size="small" style={{ marginTop: 16 }} title="Состояние">
            <Typography.Paragraph style={{ whiteSpace: 'pre-wrap', marginBottom: 0 }}>{state.text}</Typography.Paragraph>
          </Card>
        )}
        <KeyCard state={state} />
      </div>
      <Modal open={adding} title="Добавить сервер" footer={null} width={640} destroyOnHidden onCancel={() => setAdding(false)}>
        <AddServer
          state={state}
          onDone={() => {
            load()
          }}
          onClose={() => setAdding(false)}
        />
      </Modal>
      {manage && <ManageModal server={manage.server} action={manage.action} onClose={() => (setManage(null), load())} onOpen={() => open(manage.server)} />}
    </div>
  )
}

function Header({ state }: { state: AppState }) {
  const { mode, toggle } = useThemeMode()
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20, gap: 12 }}>
      <Space size={12}>
        <img src="/_app/favicon.svg" width={36} height={36} alt="" />
        <div>
          <Typography.Title level={4} style={{ margin: 0 }}>
            WDTT Router
          </Typography.Title>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            Приложение {state.version} · {state.device}
          </Typography.Text>
        </div>
      </Space>
      <Button type="text" icon={mode === 'dark' ? <SunOutlined /> : <MoonOutlined />} onClick={toggle} aria-label="Тема" />
    </div>
  )
}

function levelColor(level: string, token: ReturnType<typeof theme.useToken>['token']) {
  return level === 'ok' ? token.colorSuccess : level === 'bad' ? token.colorError : level === 'wait' ? token.colorWarning : token.colorTextQuaternary
}

/** The app's public key, for adding it in a hosting provider's control panel. */
function KeyCard({ state }: { state: AppState }) {
  return (
    <Collapse
      style={{ marginTop: 16 }}
      items={[
        {
          key: 'key',
          label: (
            <Space>
              <SafetyCertificateOutlined />
              Ключ приложения на этом компьютере
            </Space>
          ),
          children: (
            <>
              <Typography.Paragraph type="secondary">
                Приложение входит на сервер с панелью по этому SSH-ключу. Закрытая часть хранится в зашифрованном виде и привязана к вашей учётной записи Windows —
                скопированный на другой компьютер файл не сработает. Пароль root нужен только при добавлении сервера, а если добавить этот ключ на сервер заранее (например,
                в панели хостинга), пароль не понадобится вовсе.
              </Typography.Paragraph>
              <Typography.Paragraph code copyable style={{ wordBreak: 'break-all', marginBottom: 0 }}>
                {state.public_key}
              </Typography.Paragraph>
            </>
          ),
        },
      ]}
    />
  )
}

// ---- adding a server ----------------------------------------------------------------

interface AddForm {
  host: string
  password?: string
  port?: number
  user?: string
  name?: string
  key?: string
  passphrase?: string
}

function AddServer({ state, onDone, onClose }: { state: AppState; onDone: () => void; onClose?: () => void }) {
  const [form] = Form.useForm<AddForm>()
  const [step, setStep] = useState(0)
  const [view, setView] = useState<OpView | null>(null)
  const [result, setResult] = useState<CheckResult | null>(null)
  const [error, setError] = useState('')
  const [needLogin, setNeedLogin] = useState(false)
  const [busy, setBusy] = useState(false)

  const submit = async () => {
    const v = await form.validateFields()
    setBusy(true)
    setError('')
    setStep(1)
    try {
      const r = await runOp(call('POST', 'servers', { ...v, port: v.port || 22, user: v.user || 'root' }), setView)
      if (r.error) throw new Error(r.error)
      if (r.result?.state === 'need_login') {
        setNeedLogin(true)
        setStep(0)
        return
      }
      setResult(r.result)
      setStep(2)
      onDone()
    } catch (e: any) {
      setError(e.message)
    } finally {
      setBusy(false)
      form.setFieldValue('password', '')
    }
  }

  return (
    <>
      <Steps size="small" current={step} style={{ margin: '8px 0 20px' }} items={[{ title: 'Сервер' }, { title: 'Проверка' }, { title: 'Панель' }]} />
      {step === 0 && (
        <Form form={form} layout="vertical" requiredMark={false} onFinish={submit} initialValues={{ port: 22, user: 'root' }}>
          <Form.Item name="host" label="IP-адрес сервера" rules={[{ required: true, message: 'Укажите адрес' }]}>
            <Input placeholder="203.0.113.10" autoFocus size="large" />
          </Form.Item>
          {needLogin && (
            <Alert
              style={{ marginBottom: 16 }}
              type="info"
              showIcon
              title="Сервер ещё не знает ключ приложения"
              description="Введите пароль root (его присылает хостинг). Он нужен один раз: приложение добавит на сервер свой ключ и дальше будет входить по нему. Пароль нигде не сохраняется."
            />
          )}
          <Form.Item
            name="password"
            label="Пароль root"
            extra={
              needLogin
                ? 'Или добавьте на сервер ключ приложения (внизу страницы) и нажмите «Подключить» без пароля.'
                : 'Не нужен, если ключ приложения уже добавлен на сервер. Пароль используется один раз и не сохраняется.'
            }
          >
            <Input.Password size="large" autoComplete="off" />
          </Form.Item>
          <Collapse
            ghost
            size="small"
            style={{ marginBottom: 12 }}
            items={[
              {
                key: 'more',
                label: 'Другой порт, пользователь или вход по SSH-ключу',
                children: (
                  <>
                    <Space wrap>
                      <Form.Item name="port" label="Порт SSH">
                        <InputNumber min={1} max={65535} />
                      </Form.Item>
                      <Form.Item name="user" label="Пользователь" extra="Нужен root">
                        <Input style={{ width: 160 }} />
                      </Form.Item>
                      <Form.Item name="name" label="Название в списке">
                        <Input style={{ width: 220 }} placeholder="как адрес" />
                      </Form.Item>
                    </Space>
                    <Form.Item name="key" label="Закрытый SSH-ключ (вместо пароля)" extra="Содержимое файла id_ed25519 или id_rsa. Используется один раз и не сохраняется.">
                      <Input.TextArea rows={3} placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" style={{ fontFamily: 'monospace', fontSize: 12 }} />
                    </Form.Item>
                    <Form.Item name="passphrase" label="Пароль ключа, если есть">
                      <Input.Password autoComplete="off" style={{ width: 260 }} />
                    </Form.Item>
                  </>
                ),
              },
            ]}
          />
          {error && <Alert style={{ marginBottom: 16 }} type="error" showIcon title={error} />}
          <Space>
            <Button type="primary" size="large" htmlType="submit" loading={busy}>
              Подключить
            </Button>
            {onClose && state.servers.length > 0 && <Button onClick={onClose}>Отмена</Button>}
          </Space>
        </Form>
      )}
      {step === 1 && (
        <>
          <OpLog view={view} />
          {error && (
            <>
              <Alert style={{ marginTop: 16 }} type="error" showIcon title={error} />
              <Button style={{ marginTop: 12 }} onClick={() => setStep(0)}>
                Назад
              </Button>
            </>
          )}
        </>
      )}
      {step === 2 && result && <ServerOutcome initial={result} server={state.servers.find((s) => s.id === result.server_id)} log={view} onClose={onClose} />}
    </>
  )
}

/** What to do with a server after checking it: open, install, update. */
function ServerOutcome({ initial, server, log, onClose }: { initial: CheckResult; server?: Server; log: OpView | null; onClose?: () => void }) {
  const [res, setRes] = useState(initial)
  const [view, setView] = useState<OpView | null>(log)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [publicHost, setPublicHost] = useState(server?.host || '')
  const [creds, setCreds] = useState<{ login?: string; password?: string } | null>(null)
  const { message } = AntApp.useApp()
  const id = res.server_id || server?.id || ''

  const act = async (action: 'install' | 'update' | 'restart') => {
    setBusy(true)
    setError('')
    try {
      const r = await runOp(call('POST', `servers/${id}/${action}`, { public_host: publicHost }), setView)
      if (r.result?.password) setCreds({ login: r.result.login, password: r.result.password })
      if (r.error) throw new Error(r.error)
      if (r.result) setRes(r.result)
    } catch (e: any) {
      setError(e.message)
    } finally {
      setBusy(false)
    }
  }
  const [opening, setOpening] = useState(false)
  const open = async () => {
    setOpening(true)
    try {
      await call('POST', `servers/${id}/connect`)
      window.location.assign('/')
    } catch (e: any) {
      message.error({ content: e.message, duration: 8 })
    } finally {
      setOpening(false)
    }
  }

  return (
    <>
      {creds?.password && (
        <Alert
          style={{ marginBottom: 16 }}
          type="warning"
          showIcon
          title="Сохраните пароль панели — он показан один раз"
          description={
            <>
              Приложению пароль не нужен: оно входит по SSH-ключу. Пароль пригодится, чтобы открыть панель в браузере.
              <div style={{ marginTop: 8 }}>
                Логин: <Typography.Text code>{creds.login || 'admin'}</Typography.Text> Пароль:{' '}
                <Typography.Text code copyable>
                  {creds.password}
                </Typography.Text>
              </div>
            </>
          }
        />
      )}
      {res.state === 'ready' && (
        <Result
          status="success"
          icon={<CheckCircleOutlined />}
          title={`Панель ${res.version || ''} готова`}
          subTitle="Приложение подключится к ней по SSH. Порт панели можно закрыть для Интернета: Настройки → Доступ к веб-панели."
          extra={
            <Button type="primary" size="large" loading={opening} onClick={open}>
              Открыть панель
            </Button>
          }
        />
      )}
      {res.state === 'no_panel' && (
        <Card size="small" title="Установить панель на этот сервер?">
          <Typography.Paragraph>
            На сервере ({res.os}) панели нет. Приложение загрузит последний релиз WDTT Router с GitHub — установщик проверит его подпись — и запустит панель. Это займёт
            одну-три минуты.
          </Typography.Paragraph>
          <Form layout="vertical">
            <Form.Item label="Публичный адрес сервера" extra="По нему будут подключаться клиенты WDTT. Обычно это тот же IP.">
              <Input value={publicHost} onChange={(e) => setPublicHost(e.target.value)} style={{ maxWidth: 320 }} />
            </Form.Item>
          </Form>
          <Button type="primary" loading={busy} onClick={() => act('install')}>
            Установить панель
          </Button>
        </Card>
      )}
      {res.state === 'old_panel' && (
        <Card size="small" title="Нужно обновить панель">
          <Typography.Paragraph>
            На сервере панель {res.version}: эта версия ещё не умеет работать с приложением. Обновление сохранит все настройки и при ошибке вернёт прежнюю версию.
          </Typography.Paragraph>
          <Button type="primary" loading={busy} onClick={() => act('update')}>
            Обновить панель
          </Button>
        </Card>
      )}
      {res.state === 'stopped' && (
        <Card size="small" title="Панель не запущена">
          <Typography.Paragraph>Панель {res.version} установлена, но служба не работает.</Typography.Paragraph>
          <Button type="primary" loading={busy} onClick={() => act('restart')}>
            Перезапустить панель
          </Button>
        </Card>
      )}
      {res.state === 'agent_only' && (
        <Result
          status="warning"
          title="Это сервер цепочки, а не сервер панели"
          subTitle="Им уже управляет панель WDTT Router на другом сервере. Добавьте в приложение тот сервер, где установлена панель (обычно это входной сервер)."
        />
      )}
      {res.state === 'unsupported' && <Result status="warning" title="Система не поддерживается" subTitle={`На сервере ${res.os}. Панель устанавливается на Debian или Ubuntu.`} />}
      {error && <Alert style={{ marginTop: 16 }} type="error" showIcon title={error} />}
      {view && (busy || error || res.state !== 'ready') && <OpLog view={view} style={{ marginTop: 16 }} />}
      {onClose && res.state !== 'ready' && !busy && (
        <Button style={{ marginTop: 16 }} onClick={onClose}>
          Закрыть
        </Button>
      )}
    </>
  )
}

function ManageModal({ server, action, onClose }: { server: Server; action: 'check' | 'update' | 'restart'; onClose: () => void; onOpen: () => void }) {
  const [view, setView] = useState<OpView | null>(null)
  const [res, setRes] = useState<CheckResult | null>(null)
  const [error, setError] = useState('')
  const started = useRef(false)
  useEffect(() => {
    if (started.current) return
    started.current = true
    runOp(call('POST', `servers/${server.id}/${action}`, {}), setView)
      .then((r) => {
        if (r.error) setError(r.error)
        if (r.result) setRes(r.result)
      })
      .catch((e) => setError(e.message))
  }, [server.id, action])
  const titles = { check: 'Проверка сервера', update: 'Обновление панели', restart: 'Перезапуск панели' }
  return (
    <Modal open title={`${titles[action]}: ${server.name}`} footer={null} width={680} onCancel={onClose} maskClosable={false}>
      {res && !error ? <ServerOutcome initial={res} server={server} log={view} onClose={onClose} /> : <OpLog view={view} />}
      {error && <Alert style={{ marginTop: 16 }} type="error" showIcon title={error} />}
    </Modal>
  )
}

/** A live log of an operation. */
function OpLog({ view, style }: { view: OpView | null; style?: React.CSSProperties }) {
  const ref = useRef<HTMLPreElement>(null)
  useEffect(() => {
    ref.current?.scrollTo({ top: ref.current.scrollHeight })
  }, [view?.log.length])
  return (
    <div style={style}>
      {!view?.done && (
        <Space style={{ marginBottom: 8 }}>
          <Spin size="small" />
          <Typography.Text type="secondary">Выполняется…</Typography.Text>
        </Space>
      )}
      <pre ref={ref} className="op-log">
        {(view?.log || ['…']).join('\n')}
      </pre>
    </div>
  )
}
