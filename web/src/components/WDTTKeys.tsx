import { useEffect, useState } from 'react'
import { App, Button, Card, Dropdown, Empty, Form, Input, Modal, QRCode, Segmented, Space, Table, Tag, Tooltip, Typography } from 'antd'
import type { MenuProps } from 'antd'
import { DeleteOutlined, DisconnectOutlined, EditOutlined, LinkOutlined, MoreOutlined, PauseCircleOutlined, PlayCircleOutlined, PlusOutlined } from '@ant-design/icons'
import dayjs from 'dayjs'
import { del, get, patch, post } from '../api'
import { useJobs } from './Jobs'
import type { WDTTKey, WDTTKeysData, WDTTLink } from '../types'
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

/** Shows the password and the wdtt:// link (with a QR code) of a key. */
export function LinkModal({ id, title, onClose }: { id: string | null; title: string; onClose: () => void }) {
  const [link, setLink] = useState<WDTTLink | null>(null)
  const { message } = App.useApp()
  useEffect(() => {
    setLink(null)
    if (!id) return
    get<WDTTLink>(`/api/wdtt/keys/${id}/link`)
      .then(setLink)
      .catch((e) => {
        message.error(e.message)
        onClose()
      })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id])
  return (
    <Modal open={!!id} title={title} onCancel={onClose} footer={<Button onClick={onClose}>Закрыть</Button>} destroyOnHidden>
      {link && (
        <Space orientation="vertical" size="middle" style={{ width: '100%' }}>
          {link.link ? (
            <>
              <div style={{ display: 'flex', justifyContent: 'center' }}>
                <QRCode value={link.link} size={220} />
              </div>
              <Typography.Paragraph copyable className="mono" style={{ wordBreak: 'break-all', marginBottom: 0 }}>
                {link.link}
              </Typography.Paragraph>
              <Typography.Text type="secondary">Откройте в приложении WDTT: «Настройки» → «Ссылка wdtt://».</Typography.Text>
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

function KeyForm({ open, edit, onClose, onSaved }: { open: boolean; edit: WDTTKey | null; onClose: () => void; onSaved: (job?: number) => void }) {
  const [form] = Form.useForm()
  const [busy, setBusy] = useState(false)
  const { message } = App.useApp()
  useEffect(() => {
    if (open) form.setFieldsValue(edit ? { name: edit.name, vk_hash: edit.vk_hash, days: undefined } : { name: '', vk_hash: '', days: 30 })
  }, [open, edit, form])
  const save = async () => {
    const v = await form.validateFields()
    setBusy(true)
    try {
      if (edit) {
        const body: Record<string, unknown> = { name: v.name, vk_hash: v.vk_hash || '' }
        if (v.days !== undefined) body.days = v.days
        const r = await patch<{ job_id?: number }>(`/api/wdtt/keys/${edit.id}`, body)
        onSaved(r.job_id)
      } else {
        const r = await post<{ job_id: number }>('/api/wdtt/keys', { name: v.name, days: v.days, vk_hash: v.vk_hash || '' })
        onSaved(r.job_id)
      }
      onClose()
    } catch (e: any) {
      message.error(e.message)
    } finally {
      setBusy(false)
    }
  }
  return (
    <Modal open={open} title={edit ? `Ключ «${edit.name}»` : 'Новый ключ доступа'} onCancel={onClose} onOk={save} okText="Сохранить" cancelText="Отмена" confirmLoading={busy} destroyOnHidden>
      <Form form={form} layout="vertical" requiredMark={false}>
        <Form.Item name="name" label="Название" rules={[{ required: true, whitespace: true, max: 64, message: 'До 64 символов' }]}>
          <Input placeholder="Телефон Анны" maxLength={64} />
        </Form.Item>
        <Form.Item name="days" label={edit ? 'Новый срок (от сегодня)' : 'Срок действия'} extra={edit ? 'Не выбирайте ничего, чтобы оставить текущий срок.' : undefined}>
          <Segmented block options={terms} />
        </Form.Item>
        <Form.Item name="vk_hash" label="Хеш звонка VK" extra="Ссылка на звонок или её последняя часть; несколько — через запятую. Нужен, чтобы собрать ссылку wdtt://.">
          <Input placeholder="https://vk.com/call/join/…" />
        </Form.Item>
      </Form>
    </Modal>
  )
}

export function WDTTKeysCard({ data, reload }: { data: WDTTKeysData | null; reload: () => void }) {
  const { track } = useJobs()
  const { message, modal } = App.useApp()
  const [form, setForm] = useState<{ open: boolean; edit: WDTTKey | null }>({ open: false, edit: null })
  const [linkFor, setLinkFor] = useState<WDTTKey | null>(null)

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
  const menu = (k: WDTTKey): MenuProps['items'] => [
    { key: 'edit', icon: <EditOutlined />, label: 'Изменить', onClick: () => setForm({ open: true, edit: k }) },
    k.disabled
      ? { key: 'on', icon: <PlayCircleOutlined />, label: 'Включить', onClick: () => act(() => patch(`/api/wdtt/keys/${k.id}`, { disabled: false })) }
      : { key: 'off', icon: <PauseCircleOutlined />, label: 'Отключить', onClick: () => act(() => patch(`/api/wdtt/keys/${k.id}`, { disabled: true })) },
    {
      key: 'unbind',
      icon: <DisconnectOutlined />,
      label: 'Отвязать устройство',
      disabled: !k.device_id,
      onClick: () =>
        modal.confirm({
          title: `Отвязать устройство от ключа «${k.name}»?`,
          content: 'Ключ привяжется к первому устройству, которое подключится с ним снова.',
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
          content: 'Устройство с этим ключом сразу отключится.',
          okText: 'Удалить',
          okButtonProps: { danger: true },
          cancelText: 'Отмена',
          onOk: () => act(() => del(`/api/wdtt/keys/${k.id}`)),
        }),
    },
  ]

  return (
    <Card
      title="Ключи доступа WDTT"
      extra={
        <Button type="primary" icon={<PlusOutlined />} onClick={() => setForm({ open: true, edit: null })} disabled={!data || data.keys.length >= data.limit}>
          Ключ
        </Button>
      }
    >
      <Typography.Paragraph type="secondary">
        Отдельный пароль для каждого человека или устройства. Ключ привязывается к первому подключившемуся устройству; его можно ограничить по сроку, отключить или отвязать, не трогая остальных.
      </Typography.Paragraph>
      <Table<WDTTKey>
        rowKey="id"
        size="small"
        loading={!data}
        dataSource={data?.keys}
        pagination={false}
        scroll={{ x: 720 }}
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
            title: 'Устройство',
            render: (_, k) =>
              k.device_id ? (
                <Space orientation="vertical" size={0}>
                  <Typography.Text className="mono" ellipsis={{ tooltip: k.device_id }} style={{ maxWidth: 180 }}>
                    {k.device_id}
                  </Typography.Text>
                  <Typography.Text type="secondary" className="mono">
                    {k.device_ip}
                  </Typography.Text>
                </Space>
              ) : (
                <Typography.Text type="secondary">ещё не подключалось</Typography.Text>
              ),
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
      <KeyForm open={form.open} edit={form.edit} onClose={() => setForm({ open: false, edit: null })} onSaved={done} />
      <LinkModal id={linkFor?.id ?? null} title={linkFor ? `Подключение: ${linkFor.name}` : ''} onClose={() => setLinkFor(null)} />
    </Card>
  )
}
