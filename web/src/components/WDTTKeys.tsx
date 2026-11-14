import { useEffect, useState } from 'react'
import { App, Button, Card, Dropdown, Empty, Form, Input, InputNumber, Modal, QRCode, Segmented, Select, Space, Table, Tag, Tooltip, Typography } from 'antd'
import type { MenuProps } from 'antd'
import { DeleteOutlined, DisconnectOutlined, EditOutlined, LinkOutlined, MoreOutlined, PauseCircleOutlined, PlayCircleOutlined, PlusOutlined } from '@ant-design/icons'
import dayjs from 'dayjs'
import { del, get, patch, post } from '../api'
import { useJobs } from './Jobs'
import type { WDTTDevice, WDTTDeviceRow, WDTTKey, WDTTKeysData, WDTTKind, WDTTLink } from '../types'
import { fmtBytes } from '../util'

const terms = [
  { label: '7 дн.', value: 7 },
  { label: '30 дн.', value: 30 },
  { label: '90 дн.', value: 90 },
  { label: 'Год', value: 365 },
  { label: 'Бессрочно', value: 0 },
]

const stateTag: Record<WDTTKey['state'], { color: string; text: string }> = {
  active: { color: 'success', text: 'активен' },
  disabled: { color: 'default', text: 'отключён' },
  expired: { color: 'warning', text: 'истёк' },
}

/** How each WDTT server is labelled everywhere in the panel. */
export const wdttKinds: Record<WDTTKind, { title: string; short: string; color: string; app: string }> = {
  standard: { title: 'Стандартный клиент WDTT', short: 'WDTT', color: 'blue', app: 'WDTT' },
  turnvk: { title: 'Клиент TurnVK', short: 'TurnVK', color: 'purple', app: 'TurnVK' },
}

export function KindTag({ kind }: { kind: WDTTKind }) {
  return <Tag color={wdttKinds[kind].color}>{wdttKinds[kind].short}</Tag>
}

export const devicesText = (n: number, max: number) => (max > 0 ? `${n} / ${max}` : `${n} / ∞`)

export function useWDTTKeys(enabled: boolean) {
  const [data, setData] = useState<WDTTKeysData | null>(null)
  const { version } = useJobs()
  const load = async () => {
    try {
      setData(await get<WDTTKeysData>('/api/wdtt/keys'))
    } catch {
      /* the services page shows errors */
    }
  }
  useEffect(() => {
    if (!enabled) return
    load()
    const t = setInterval(load, 15000)
    return () => clearInterval(t)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, version])
  return { data, reload: load }
}

/** Shows the password and the wdtt:// link (with a QR code) of a key; for
 * "main" (an owner password) kind says which server. */
export function LinkModal({ id, kind, title, onClose }: { id: string | null; kind?: WDTTKind; title: string; onClose: () => void }) {
  const [link, setLink] = useState<WDTTLink | null>(null)
  const { message } = App.useApp()
  useEffect(() => {
    setLink(null)
    if (!id) return
    get<WDTTLink>(`/api/wdtt/keys/${id}/link${id === 'main' ? `?kind=${kind || 'standard'}` : ''}`)
      .then(setLink)
      .catch((e) => {
        message.error(e.message)
        onClose()
      })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id, kind])
  const app = link ? wdttKinds[link.kind || 'standard'].app : ''
  return (
    <Modal open={!!id} title={title} onCancel={onClose} footer={<Button onClick={onClose}>Закрыть</Button>} destroyOnHidden>
      {link && (
        <Space orientation="vertical" size="middle" style={{ width: '100%' }}>
          <Space>
            Для: <KindTag kind={link.kind || 'standard'} />
            <Typography.Text type="secondary">{wdttKinds[link.kind || 'standard'].title}</Typography.Text>
          </Space>
          {link.link ? (
            <>
              <div style={{ display: 'flex', justifyContent: 'center' }}>
                <QRCode value={link.link} size={220} />
              </div>
              <Typography.Paragraph copyable className="mono" style={{ wordBreak: 'break-all', marginBottom: 0 }}>
                {link.link}
              </Typography.Paragraph>
              <Typography.Text type="secondary">
                {link.kind === 'turnvk' ? 'Откройте в приложении TurnVK: вставьте ссылку или отсканируйте QR-код.' : 'Откройте в приложении WDTT: «Настройки» → «Ссылка wdtt://».'} Другим приложением эта ссылка не подойдёт: у {app} свой сервер.
              </Typography.Text>
            </>
          ) : (
            <Typography.Text type="warning">Укажите хеш звонка VK, чтобы получить ссылку wdtt://. Без неё введите данные вручную:</Typography.Text>
          )}
          <Typography.Text copyable={{ text: `${link.host}:${link.port}` }}>
            сервер: <span className="mono">{`${link.host}:${link.port}`}</span>
          </Typography.Text>
          <Typography.Text copyable={{ text: link.password }}>
            пароль: <span className="mono">{link.password}</span>
          </Typography.Text>
        </Space>
      )}
    </Modal>
  )
}

const deviceOptions = [
  { label: '1', value: 1 },
  { label: '2', value: 2 },
  { label: '3', value: 3 },
  { label: '5', value: 5 },
  { label: 'Без ограничения', value: 0 },
]

function KeyForm({ open, kind, edit, maxDevices, onClose, onSaved }: { open: boolean; kind: WDTTKind; edit: WDTTKey | null; maxDevices: number; onClose: () => void; onSaved: (job?: number, created?: { id: string; name: string }) => void }) {
  const [form] = Form.useForm()
  const [busy, setBusy] = useState(false)
  const [custom, setCustom] = useState(false)
  const { message } = App.useApp()
  useEffect(() => {
    if (!open) return
    const md = edit ? edit.max_devices : 0
    setCustom(!deviceOptions.some((o) => o.value === md))
    form.setFieldsValue(edit ? { name: edit.name, vk_hash: edit.vk_hash, days: undefined, max_devices: md } : { name: '', vk_hash: '', days: 30, max_devices: 0 })
  }, [open, edit, form])
  const save = async () => {
    const v = await form.validateFields()
    setBusy(true)
    try {
      if (edit) {
        const body: Record<string, unknown> = { name: v.name, vk_hash: v.vk_hash || '', max_devices: v.max_devices ?? 0 }
        if (v.days !== undefined) body.days = v.days
        const r = await patch<{ job_id?: number }>(`/api/wdtt/keys/${edit.id}`, body)
        onSaved(r.job_id)
      } else {
        const r = await post<{ job_id: number; id?: string }>('/api/wdtt/keys', { name: v.name, days: v.days, vk_hash: v.vk_hash || '', kind, max_devices: v.max_devices ?? 0 })
        onSaved(r.job_id, r.id ? { id: r.id, name: v.name } : undefined)
      }
      onClose()
    } catch (e: any) {
      message.error(e.message)
    } finally {
      setBusy(false)
    }
  }
  const bound = edit?.devices?.length || 0
  return (
    <Modal open={open} title={edit ? `Ключ «${edit.name}»` : `Новый ключ: ${wdttKinds[kind].title}`} onCancel={onClose} onOk={save} okText="Сохранить" cancelText="Отмена" confirmLoading={busy} destroyOnHidden>
      <Form form={form} layout="vertical" requiredMark={false}>
        <Form.Item name="name" label="Название" rules={[{ required: true, whitespace: true, max: 64, message: 'До 64 символов' }]}>
          <Input placeholder="Семья Ивановых" maxLength={64} />
        </Form.Item>
        <Form.Item name="days" label={edit ? 'Новый срок (от сегодня)' : 'Срок действия'} extra={edit ? 'Не выбирайте ничего, чтобы оставить текущий срок.' : undefined}>
          <Segmented block options={terms} />
        </Form.Item>
        <Form.Item
          label="Устройств на ключ"
          extra={
            edit && bound > 0
              ? `Сейчас привязано: ${bound}. Если уменьшить число, уже привязанные устройства останутся — новые подключатся, когда освободится место (отвяжите лишние).`
              : 'Ключ привязывается к первым подключившимся устройствам. Остальным сервер отказывает, пока место не освободится.'
          }
        >
          <Space wrap>
            <Form.Item name="max_devices" noStyle>
              {custom ? (
                <InputNumber min={0} max={maxDevices} style={{ width: 120 }} addonAfter="шт." />
              ) : (
                <Segmented options={deviceOptions} />
              )}
            </Form.Item>
            <Button type="link" size="small" onClick={() => setCustom(!custom)}>
              {custom ? 'Выбрать из списка' : 'Другое число'}
            </Button>
          </Space>
        </Form.Item>
        <Form.Item name="vk_hash" label="Хеш звонка VK" extra="Ссылка на звонок или её последняя часть; несколько — через запятую. Нужен, чтобы собрать ссылку wdtt://.">
          <Input placeholder="https://vk.com/call/join/…" />
        </Form.Item>
      </Form>
    </Modal>
  )
}

function seen(d: { sessions: number; last_seen?: number }) {
  return d.sessions > 0 ? <Tag color="processing">в сети · {d.sessions}</Tag> : d.last_seen ? <Typography.Text type="secondary">{dayjs.unix(d.last_seen).fromNow()}</Typography.Text> : '—'
}

/** Devices of one key, with a button that unbinds each. */
function KeyDevices({ k, onUnbind }: { k: WDTTKey; onUnbind: (d: WDTTDevice) => void }) {
  if (!k.devices?.length) return <Typography.Text type="secondary">Устройств ещё нет — ключ привяжется к первому подключившемуся.</Typography.Text>
  return (
    <Table<WDTTDevice>
      rowKey="id"
      size="small"
      pagination={false}
      dataSource={k.devices}
      columns={[
        {
          title: 'Устройство',
          dataIndex: 'id',
          render: (id: string) => (
            <Typography.Text className="mono" ellipsis={{ tooltip: id }} style={{ maxWidth: 240 }}>
              {id}
            </Typography.Text>
          ),
        },
        { title: 'Адрес', dataIndex: 'ip', render: (ip: string) => <span className="mono">{ip}</span> },
        { title: 'Сейчас', render: (_, d) => seen(d) },
        { title: 'Трафик', render: (_, d) => <span className="mono">↓{fmtBytes(d.down_bytes)} ↑{fmtBytes(d.up_bytes)}</span> },
        { title: 'Привязано', dataIndex: 'bound_at', render: (t?: number) => (t ? dayjs.unix(t).format('DD.MM.YYYY HH:mm') : '—') },
        {
          title: '',
          width: 48,
          render: (_, d) => (
            <Tooltip title="Отвязать устройство">
              <Button size="small" icon={<DisconnectOutlined />} onClick={() => onUnbind(d)} />
            </Tooltip>
          ),
        },
      ]}
    />
  )
}

export function WDTTKeysCard({ data, kind, reload }: { data: WDTTKeysData | null; kind: WDTTKind; reload: () => void }) {
  const { track } = useJobs()
  const { message, modal } = App.useApp()
  const [form, setForm] = useState<{ open: boolean; edit: WDTTKey | null }>({ open: false, edit: null })
  const [linkFor, setLinkFor] = useState<WDTTKey | null>(null)
  const [query, setQuery] = useState('')
  const q = query.trim().toLowerCase()
  const mine = (data?.keys || []).filter((k) => (k.kind || 'standard') === kind)
  const shown = mine.filter((k) => !q || k.name.toLowerCase().includes(q) || (k.devices || []).some((d) => d.id.toLowerCase().includes(q) || d.ip.includes(q)))

  const done = (job?: number) => {
    if (job) track(job, reload)
    else reload()
  }
  const act = async (fn: () => Promise<{ job_id?: number }>) => {
    try {
      done((await fn()).job_id)
    } catch (e: any) {
      message.error(e.message)
    }
  }
  const unbind = (k: WDTTKey, d: WDTTDevice) =>
    modal.confirm({
      title: `Отвязать устройство от ключа «${k.name}»?`,
      content: (
        <>
          <Typography.Text className="mono">{d.id}</Typography.Text> отключится, его место освободится. Если с ключом снова подключится новое устройство, оно займёт это место.
        </>
      ),
      okText: 'Отвязать',
      cancelText: 'Отмена',
      onOk: () => act(() => patch(`/api/wdtt/keys/${k.id}`, { unbind_device: d.id })),
    })
  const menu = (k: WDTTKey): MenuProps['items'] => [
    { key: 'edit', icon: <EditOutlined />, label: 'Изменить', onClick: () => setForm({ open: true, edit: k }) },
    k.disabled
      ? { key: 'on', icon: <PlayCircleOutlined />, label: 'Включить', onClick: () => act(() => patch(`/api/wdtt/keys/${k.id}`, { disabled: false })) }
      : { key: 'off', icon: <PauseCircleOutlined />, label: 'Отключить', onClick: () => act(() => patch(`/api/wdtt/keys/${k.id}`, { disabled: true })) },
    {
      key: 'unbind',
      icon: <DisconnectOutlined />,
      label: 'Отвязать все устройства',
      disabled: !k.devices?.length,
      onClick: () =>
        modal.confirm({
          title: `Отвязать все устройства от ключа «${k.name}»?`,
          content: 'Все устройства ключа отключатся. Ключ снова привяжется к первым подключившимся.',
          okText: 'Отвязать',
          cancelText: 'Отмена',
          onOk: () => act(() => patch(`/api/wdtt/keys/${k.id}`, { reset_device: true })),
        }),
    },
    { type: 'divider' },
    {
      key: 'del',
      icon: <DeleteOutlined />,
      danger: true,
      label: 'Удалить',
      onClick: () =>
        modal.confirm({
          title: `Удалить ключ «${k.name}»?`,
          content: 'Устройства с этим ключом сразу отключатся.',
          okText: 'Удалить',
          okButtonProps: { danger: true },
          cancelText: 'Отмена',
          onOk: () => act(() => del(`/api/wdtt/keys/${k.id}`)),
        }),
    },
  ]

  return (
    <Card
      title={
        <Space>
          Ключи доступа
          <KindTag kind={kind} />
        </Space>
      }
      extra={
        <Button type="primary" icon={<PlusOutlined />} onClick={() => setForm({ open: true, edit: null })} disabled={!data || data.keys.length >= data.limit}>
          Ключ
        </Button>
      }
    >
      <Typography.Paragraph type="secondary">
        Отдельный пароль для каждого человека или семьи. Ключ привязывается к первым подключившимся устройствам — столько, сколько вы разрешили; его можно ограничить по сроку, отключить, отвязать отдельное устройство, не трогая остальных. Ключи этого сервера подходят только для {wdttKinds[kind].app}.
      </Typography.Paragraph>
      {mine.length > 5 && <Input.Search allowClear placeholder="Поиск по названию, устройству или адресу" value={query} onChange={(e) => setQuery(e.target.value)} style={{ marginBottom: 12, maxWidth: 360 }} />}
      <Table<WDTTKey>
        rowKey="id"
        size="small"
        loading={!data}
        dataSource={shown}
        pagination={false}
        scroll={{ x: 720 }}
        expandable={{
          expandedRowRender: (k) => <KeyDevices k={k} onUnbind={(d) => unbind(k, d)} />,
          rowExpandable: () => true,
        }}
        locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="Ключей нет — пока подключается только пароль владельца" /> }}
        columns={[
          {
            title: 'Ключ',
            dataIndex: 'name',
            render: (n, k) => (
              <Space orientation="vertical" size={0}>
                <Typography.Text strong>{n}</Typography.Text>
                <Tag color={stateTag[k.state].color}>{stateTag[k.state].text}</Tag>
              </Space>
            ),
          },
          {
            title: 'Устройства',
            render: (_, k) => {
              const n = k.devices?.length || 0
              const full = k.max_devices > 0 && n >= k.max_devices
              return (
                <Space orientation="vertical" size={0}>
                  <Tooltip title={k.max_devices > 0 ? `Привязано ${n} из ${k.max_devices}` : `Привязано ${n}, без ограничения`}>
                    <Tag color={full ? 'warning' : undefined}>{devicesText(n, k.max_devices)}</Tag>
                  </Tooltip>
                  {k.devices?.[0] ? (
                    <Typography.Text type="secondary" className="mono" ellipsis={{ tooltip: k.devices[0].id }} style={{ maxWidth: 180 }}>
                      {k.devices[0].id}
                    </Typography.Text>
                  ) : (
                    <Typography.Text type="secondary">ещё не подключались</Typography.Text>
                  )}
                </Space>
              )
            },
          },
          {
            title: 'Сейчас',
            render: (_, k) => (k.sessions > 0 ? <Tag color="processing">в сети · {k.sessions}</Tag> : k.last_seen ? <Typography.Text type="secondary">{dayjs.unix(k.last_seen).fromNow()}</Typography.Text> : '—'),
          },
          {
            title: 'Трафик',
            render: (_, k) => (
              <Tooltip title="к клиенту / от клиента">
                <span className="mono">
                  ↓{fmtBytes(k.down_bytes)} ↑{fmtBytes(k.up_bytes)}
                </span>
              </Tooltip>
            ),
          },
          {
            title: 'Действует до',
            dataIndex: 'expires_at',
            render: (e: number) => (e ? dayjs.unix(e).format('DD.MM.YYYY') : 'бессрочно'),
          },
          {
            title: '',
            width: 96,
            fixed: 'right',
            render: (_, k) => (
              <Space size={4}>
                <Tooltip title="Ссылка и пароль">
                  <Button size="small" icon={<LinkOutlined />} onClick={() => setLinkFor(k)} />
                </Tooltip>
                <Dropdown menu={{ items: menu(k) }} trigger={['click']}>
                  <Button size="small" icon={<MoreOutlined />} />
                </Dropdown>
              </Space>
            ),
          },
        ]}
      />
      <KeyForm
        open={form.open}
        kind={kind}
        edit={form.edit}
        maxDevices={data?.max_devices || 249}
        onClose={() => setForm({ open: false, edit: null })}
        onSaved={(job, created) => {
          done(job)
          // A new key: show its link and QR code right away.
          if (created) setLinkFor({ id: created.id, name: created.name } as WDTTKey)
        }}
      />
      <LinkModal id={linkFor?.id ?? null} title={linkFor ? `Подключение: ${linkFor.name}` : ''} onClose={() => setLinkFor(null)} />
    </Card>
  )
}

/** Every device of both WDTT servers in one list. */
export function WDTTDevicesCard({ data, reload }: { data: WDTTKeysData | null; reload: () => void }) {
  const { track } = useJobs()
  const { message, modal } = App.useApp()
  const [query, setQuery] = useState('')
  const [kind, setKind] = useState<WDTTKind | 'all'>('all')
  const [online, setOnline] = useState(false)
  const q = query.trim().toLowerCase()
  const rows = (data?.devices || []).filter(
    (d) => (kind === 'all' || d.kind === kind) && (!online || d.sessions > 0) && (!q || d.id.toLowerCase().includes(q) || d.ip.includes(q) || d.key_name.toLowerCase().includes(q)),
  )
  const unbind = (d: WDTTDeviceRow) =>
    modal.confirm({
      title: `Отвязать устройство от ключа «${d.key_name}»?`,
      content: (
        <>
          <Typography.Text className="mono">{d.id}</Typography.Text> отключится, место в ключе освободится.
        </>
      ),
      okText: 'Отвязать',
      cancelText: 'Отмена',
      onOk: async () => {
        try {
          const r = await patch<{ job_id?: number }>(`/api/wdtt/keys/${d.key_id}`, { unbind_device: d.id })
          if (r.job_id) track(r.job_id, reload)
          else reload()
        } catch (e: any) {
          message.error(e.message)
        }
      },
    })
  return (
    <Card title="Устройства">
      <Typography.Paragraph type="secondary">
        Все устройства, которые подключались к серверам WDTT: с какого ключа, с каким адресом в туннеле, сколько передали и когда были в сети. Устройства пароля владельца не привязываются и не ограничиваются.
      </Typography.Paragraph>
      <Space wrap style={{ marginBottom: 12 }}>
        <Input.Search allowClear placeholder="Устройство, адрес или ключ" value={query} onChange={(e) => setQuery(e.target.value)} style={{ width: 280 }} />
        <Select
          value={kind}
          onChange={setKind}
          style={{ width: 220 }}
          options={[
            { value: 'all', label: 'Оба сервера' },
            { value: 'standard', label: wdttKinds.standard.title },
            { value: 'turnvk', label: wdttKinds.turnvk.title },
          ]}
        />
        <Segmented
          value={online ? 'online' : 'all'}
          onChange={(v) => setOnline(v === 'online')}
          options={[
            { label: 'Все', value: 'all' },
            { label: 'В сети', value: 'online' },
          ]}
        />
      </Space>
      <Table<WDTTDeviceRow>
        rowKey={(d) => `${d.kind}/${d.key_id}/${d.id}`}
        size="small"
        loading={!data}
        dataSource={rows}
        pagination={rows.length > 50 ? { pageSize: 50, showSizeChanger: false } : false}
        scroll={{ x: 820 }}
        locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="Устройств пока нет" /> }}
        columns={[
          {
            title: 'Устройство',
            dataIndex: 'id',
            render: (id: string) => (
              <Typography.Text className="mono" ellipsis={{ tooltip: id }} style={{ maxWidth: 220 }}>
                {id}
              </Typography.Text>
            ),
          },
          { title: 'Клиент', dataIndex: 'kind', render: (k: WDTTKind) => <KindTag kind={k} /> },
          { title: 'Ключ', dataIndex: 'key_name', render: (n: string, d) => (d.key_id === 'main' ? <Typography.Text type="secondary">{n}</Typography.Text> : n) },
          { title: 'Адрес', dataIndex: 'ip', render: (ip: string) => <span className="mono">{ip}</span> },
          { title: 'Сейчас', render: (_, d) => seen(d) },
          { title: 'Трафик', render: (_, d) => <span className="mono">↓{fmtBytes(d.down_bytes)} ↑{fmtBytes(d.up_bytes)}</span> },
          {
            title: '',
            width: 48,
            render: (_, d) =>
              d.key_id !== 'main' && (
                <Tooltip title="Отвязать устройство">
                  <Button size="small" icon={<DisconnectOutlined />} onClick={() => unbind(d)} />
                </Tooltip>
              ),
          },
        ]}
      />
    </Card>
  )
}
