import { useEffect, useState } from 'react'
import {
  Alert,
  App,
  Button,
  Card,
  Descriptions,
  Drawer,
  Dropdown,
  Empty,
  Form,
  Input,
  InputNumber,
  Modal,
  Progress,
  Select,
  Space,
  Switch,
  Table,
  Tabs,
  Tag,
  Tooltip,
  Typography,
} from 'antd'
import { CloudSyncOutlined, DeleteOutlined, DisconnectOutlined, MoreOutlined, PlusOutlined, ReloadOutlined, SendOutlined } from '@ant-design/icons'
import { get, patch, post } from '../api'
import { RowItem, Rows } from '../components/Rows'
import { useJobs } from '../components/Jobs'
import type { NodeView } from '../types'
import { fmtTime, fromNow, HealthBadge, MeshTag, RoleTag, uptime, usePoll } from '../util'

export default function Servers() {
  const { data, loading, reload } = usePoll<{ nodes: NodeView[]; plan_error: string }>('/api/nodes', 15000)
  const [adding, setAdding] = useState(false)
  const [selected, setSelected] = useState<number | null>(null)
  const { track, version } = useJobs()
  const { message, modal } = App.useApp()
  useEffect(() => {
    reload()
  }, [version, reload])

  const nodes = data?.nodes || []
  const current = nodes.find((n) => n.id === selected) || null

  const action = async (n: NodeView, act: string, body?: unknown) => {
    try {
      const r = await post<{ job_id: number }>(`/api/nodes/${n.id}/${act}`, body)
      track(r.job_id, () => reload())
    } catch (e: any) {
      message.error(e.message)
    }
  }

  const confirmLeave = (n: NodeView) =>
    modal.confirm({
      title: `Отключить «${n.name}» от Mesh?`,
      content: n.local
        ? 'Сервер выйдет из Mesh, и его Mesh-узел будет удалён в Cloudflare.'
        : 'Сервер выйдет из Mesh, и его Mesh-узел будет удалён в Cloudflare. Панель будет подключаться к нему по публичному адресу — если SSH сервера был закрыт для Интернета, панель сначала откроет его.',
      okText: 'Отключить',
      cancelText: 'Отмена',
      onOk: () => action(n, 'leave'),
    })

  const confirmRemove = (n: NodeView) =>
    modal.confirm({
      title: `Удалить сервер «${n.name}»?`,
      content: 'Панель удалит с сервера агент, звено цепочки, правила firewall и клиент Cloudflare, а также Mesh-узел в Cloudflare.',
      okText: 'Удалить',
      okButtonProps: { danger: true },
      cancelText: 'Отмена',
      onOk: () => action(n, 'remove'),
    })

  return (
    <Card
      title="Серверы"
      extra={
        <Space>
          <Button icon={<ReloadOutlined />} onClick={reload}>
            Обновить
          </Button>
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setAdding(true)}>
            Добавить сервер
          </Button>
        </Space>
      }
    >
      {data?.plan_error && <Alert style={{ marginBottom: 16 }} type="warning" showIcon title={data.plan_error} />}
      <Table
        rowKey="id"
        loading={loading && !data}
        dataSource={nodes}
        scroll={{ x: 900 }}
        pagination={false}
        onRow={(n) => ({ onClick: () => setSelected(n.id), style: { cursor: 'pointer' } })}
        columns={[
          {
            title: 'Сервер',
            render: (_, n) => (
              <Space orientation="vertical" size={0}>
                <Space>
                  <Typography.Text strong>{n.name}</Typography.Text>
                  {n.local && <Tag color="geekblue">панель</Tag>}
                </Space>
                <Typography.Text type="secondary" className="mono" style={{ fontSize: 12 }}>
                  {n.host}
                </Typography.Text>
              </Space>
            ),
          },
          { title: 'Роль', render: (_, n) => <RoleTag role={n.role} /> },
          { title: 'Mesh', render: (_, n) => <MeshTag n={n} /> },
          { title: 'Состояние', render: (_, n) => <HealthBadge n={n} /> },
          {
            title: 'Публичный SSH',
            render: (_, n) => (n.local || n.ssh_public || !n.firewall ? <Tag color="orange">открыт</Tag> : <Tag color="green">только Mesh</Tag>),
          },
          {
            title: 'Память',
            render: (_, n) =>
              n.status?.mem_total_mb ? (
                <Tooltip title={`Свободно ${n.status.mem_avail_mb} из ${n.status.mem_total_mb} МБ`}>
                  <Progress percent={Math.round(100 - (n.status.mem_avail_mb / n.status.mem_total_mb) * 100)} size="small" style={{ width: 90 }} />
                </Tooltip>
              ) : (
                '—'
              ),
          },
          { title: 'Обновлено', render: (_, n) => fromNow(n.last_seen) },
          {
            title: '',
            width: 48,
            render: (_, n) => (
              <div onClick={(e) => e.stopPropagation()}>
                <Dropdown
                  trigger={['click']}
                  menu={{
                    items: [
                      { key: 'apply', icon: <SendOutlined />, label: 'Применить настройки', onClick: () => action(n, 'apply') },
                      n.cf_node_id
                        ? { key: 'leave', icon: <DisconnectOutlined />, label: 'Отключить от Mesh', disabled: n.in_chain, onClick: () => confirmLeave(n) }
                        : { key: 'enroll', icon: <CloudSyncOutlined />, label: 'Подключить к Mesh', onClick: () => action(n, 'enroll') },
                      { type: 'divider' },
                      { key: 'remove', icon: <DeleteOutlined />, danger: true, label: 'Удалить', disabled: n.local || n.in_chain, onClick: () => confirmRemove(n) },
                    ],
                  }}
                >
                  <Button type="text" icon={<MoreOutlined />} aria-label="Действия" />
                </Dropdown>
              </div>
            ),
          },
        ]}
      />
      <AddServer open={adding} onClose={() => setAdding(false)} onQueued={(id) => track(id, () => reload())} />
      <ServerDrawer node={current} onClose={() => setSelected(null)} onChanged={reload} onAction={action} />
    </Card>
  )
}

function AddServer({ open, onClose, onQueued }: { open: boolean; onClose: () => void; onQueued: (id: number) => void }) {
  const [form] = Form.useForm()
  const [busy, setBusy] = useState(false)
  const [sshKey, setSSHKey] = useState('')
  const { message } = App.useApp()
  useEffect(() => {
    if (open) get<{ panel_ssh_key?: string }>('/api/settings').then((s) => setSSHKey(s.panel_ssh_key || '')).catch(() => {})
  }, [open])
  const keyCommand = sshKey ? `mkdir -p ~/.ssh && echo '${sshKey}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys` : ''
  const submit = async () => {
    const v = await form.validateFields()
    setBusy(true)
    try {
      const r = await post<{ job_id: number }>('/api/nodes', v)
      form.resetFields()
      onClose()
      onQueued(r.job_id)
    } catch (e: any) {
      message.error(e.message)
    } finally {
      setBusy(false)
    }
  }
  return (
    <Modal open={open} title="Добавить сервер" okText="Добавить" cancelText="Отмена" onOk={submit} confirmLoading={busy} onCancel={onClose} destroyOnHidden>
      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 16 }}
        title="Пароль root нужен один раз (или ключ панели на сервере)"
        description="Панель подключится по своему ключу или по паролю, добавит свой SSH-ключ и установит агент. Пароль не сохраняется. После подключения к Mesh публичный SSH сервера будет закрыт — управление пойдёт через Mesh."
      />
      <Form form={form} layout="vertical" initialValues={{ port: 22 }} requiredMark="optional">
        <Form.Item name="name" label="Название" rules={[{ required: true, message: 'Укажите название' }, { pattern: /^[\p{L}\p{N} ._-]{1,40}$/u, message: 'До 40 букв, цифр, пробелов, точек и дефисов' }]}>
          <Input placeholder="Например, exit-de" maxLength={40} />
        </Form.Item>
        <Space.Compact block>
          <Form.Item name="host" label="IP-адрес или имя" style={{ flex: 1 }} rules={[{ required: true, message: 'Укажите адрес' }]}>
            <Input placeholder="203.0.113.10" className="mono" />
          </Form.Item>
          <Form.Item name="port" label="Порт SSH" style={{ width: 120 }} rules={[{ required: true }]}>
            <InputNumber min={1} max={65535} style={{ width: '100%' }} />
          </Form.Item>
        </Space.Compact>
        <Form.Item
          name="password"
          label="Пароль root"
          extra="Не нужен, если на сервере уже есть ключ панели (например, вход по паролю отключён). Чтобы добавить ключ, выполните на сервере под root команду ниже."
        >
          <Input.Password autoComplete="off" />
        </Form.Item>
        {keyCommand && (
          <Typography.Paragraph copyable={{ text: keyCommand }} className="mono" style={{ fontSize: 12, wordBreak: 'break-all' }} type="secondary">
            {keyCommand}
          </Typography.Paragraph>
        )}
      </Form>
    </Modal>
  )
}

function ServerDrawer({ node, onClose, onChanged, onAction }: { node: NodeView | null; onClose: () => void; onChanged: () => void; onAction: (n: NodeView, act: string) => void }) {
  const [plan, setPlan] = useState<string>('')
  const [refreshing, setRefreshing] = useState(false)
  const { message } = App.useApp()
  useEffect(() => {
    setPlan('')
    if (node) get(`/api/nodes/${node.id}/plan`).then((p) => setPlan(JSON.stringify(p, null, 2))).catch((e) => setPlan('// ' + e.message))
  }, [node?.id, node?.out_of_sync])
  if (!node) return <Drawer open={false} />
  const s = node.status || ({} as NodeView['status'])

  const save = async (body: Record<string, unknown>) => {
    try {
      await patch(`/api/nodes/${node.id}`, body)
      message.success('Сохранено. Нажмите «Применить», чтобы изменить правила на сервере.')
      onChanged()
    } catch (e: any) {
      message.error(e.message)
    }
  }
  const refresh = async () => {
    setRefreshing(true)
    try {
      await post(`/api/nodes/${node.id}/refresh`)
      onChanged()
    } catch (e: any) {
      message.error(e.message)
    } finally {
      setRefreshing(false)
    }
  }

  return (
    <Drawer
      open
      onClose={onClose}
      size={720}
      title={
        <Space>
          {node.name}
          <RoleTag role={node.role} />
        </Space>
      }
      extra={
        <Space>
          <Button icon={<ReloadOutlined />} loading={refreshing} onClick={refresh}>
            Опросить
          </Button>
          <Button type="primary" icon={<SendOutlined />} onClick={() => onAction(node, 'apply')}>
            Применить
          </Button>
        </Space>
      }
    >
      {node.last_error && <Alert type="error" showIcon style={{ marginBottom: 16 }} title="Сервер недоступен" description={node.last_error} />}
      {!!s.problems?.length && <Alert type="warning" showIcon style={{ marginBottom: 16 }} title="Проблемы" description={s.problems.join('; ')} />}
      {node.out_of_sync && <Alert type="info" showIcon style={{ marginBottom: 16 }} title="Настройки сервера отличаются от плана — примените изменения." />}
      <Tabs
        items={[
          {
            key: 'state',
            label: 'Состояние',
            children: (
              <Space orientation="vertical" size="middle" style={{ width: '100%' }}>
                <Descriptions bordered size="small" column={{ xs: 1, sm: 2 }}>
                  <Descriptions.Item label="Публичный адрес">
                    <span className="mono">{node.host}</span>
                  </Descriptions.Item>
                  <Descriptions.Item label="Mesh-адрес">
                    <span className="mono">{node.mesh_ip || '—'}</span>
                  </Descriptions.Item>
                  <Descriptions.Item label="Система">{s.os || '—'}</Descriptions.Item>
                  <Descriptions.Item label="Архитектура">{s.arch || '—'}</Descriptions.Item>
                  <Descriptions.Item label="Работает">{uptime(s.uptime_sec)}</Descriptions.Item>
                  <Descriptions.Item label="Нагрузка">{s.load1 ?? '—'}</Descriptions.Item>
                  <Descriptions.Item label="Память">{s.mem_total_mb ? `${s.mem_avail_mb} / ${s.mem_total_mb} МБ свободно` : '—'}</Descriptions.Item>
                  <Descriptions.Item label="Диск">{s.disk_free_mb ? `${(s.disk_free_mb / 1024).toFixed(1)} ГБ свободно` : '—'}</Descriptions.Item>
                  <Descriptions.Item label="Агент">{s.agent_version || '—'}</Descriptions.Item>
                  <Descriptions.Item label="Опрошен">{fmtTime(node.last_seen)}</Descriptions.Item>
                </Descriptions>
                <Descriptions title="Компоненты" bordered size="small" column={1}>
                  <Descriptions.Item label="Cloudflare Mesh">
                    <Space wrap>
                      <MeshTag n={node} />
                      {node.cf_node_name && <Typography.Text type="secondary">{node.cf_node_name}</Typography.Text>}
                      {s.mesh_version && <Typography.Text type="secondary">клиент {s.mesh_version}</Typography.Text>}
                    </Space>
                  </Descriptions.Item>
                  <Descriptions.Item label="Звено цепочки (Xray)">
                    {s.xray_installed ? <Tag color={s.xray_active === 'active' ? 'success' : 'default'}>{s.xray_active === 'active' ? `работает · ${s.xray_version}` : s.xray_active}</Tag> : <Tag>не установлено</Tag>}
                    {node.hop_port ? <Typography.Text type="secondary">порт {node.hop_port} (только Mesh)</Typography.Text> : null}
                  </Descriptions.Item>
                  <Descriptions.Item label="Firewall">
                    {s.firewall_active ? <Tag color="success">включён</Tag> : <Tag color="warning">выключен</Tag>}
                    {s.revert_pending && <Tag color="processing">ожидает подтверждения</Tag>}
                  </Descriptions.Item>
                  {node.local && (
                    <>
                      <Descriptions.Item label="WDTT">{s.wdtt_installed ? <Tag color={s.wdtt_active === 'active' ? 'success' : 'error'}>{s.wdtt_active}</Tag> : <Tag>не установлен</Tag>}</Descriptions.Item>
                      <Descriptions.Item label="3x-ui">{s.xui_installed ? <Tag color={s.xui_active === 'active' ? 'success' : 'error'}>{s.xui_active}</Tag> : <Tag>не установлен</Tag>}</Descriptions.Item>
                    </>
                  )}
                </Descriptions>
                {node.fingerprint && (
                  <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                    Отпечаток SSH: <span className="mono">{node.fingerprint}</span>
                  </Typography.Text>
                )}
              </Space>
            ),
          },
          {
            key: 'security',
            label: 'Безопасность',
            children: <NodeSecurity node={node} onSave={save} />,
          },
          {
            key: 'plan',
            label: 'План',
            children: (
              <Space orientation="vertical" style={{ width: '100%' }}>
                <Typography.Text type="secondary">Желаемое состояние сервера, которое применит панель (секреты скрыты).</Typography.Text>
                <pre className="job-log">{plan || 'Загрузка…'}</pre>
              </Space>
            ),
          },
        ]}
      />
    </Drawer>
  )
}

function NodeSecurity({ node, onSave }: { node: NodeView; onSave: (b: Record<string, unknown>) => void }) {
  const s = node.status
  return (
    <Space orientation="vertical" size="middle" style={{ width: '100%' }}>
      <Rows bordered>
        <RowItem
          title="Firewall"
          description="Закрыты все входящие порты, кроме необходимых. Изменения применяются с автоматическим откатом через 2 минуты, если панель потеряет связь."
          extra={<Switch checked={node.firewall} onChange={(v) => onSave({ firewall: v })} />}
        />
        {!node.local && (
          <RowItem
            title="Публичный SSH"
            description={node.cf_node_id ? 'Выключено — SSH доступен только через Mesh, сервер не принимает подключения из Интернета.' : 'Закрыть публичный SSH можно после подключения к Mesh.'}
            extra={<Switch checked={node.ssh_public} disabled={!node.cf_node_id} onChange={(v) => onSave({ ssh_public: v })} />}
          />
        )}
        <RowItem
          title="Отвечать на ping"
          description="Если выключено, сервер не отвечает на ICMP echo. Служебные ICMP (MTU) работают всегда."
          extra={<Switch checked={node.allow_ping} onChange={(v) => onSave({ allow_ping: v })} />}
        />
      </Rows>
      {(node.local || node.ssh_public) && (
        <Card size="small" title="Откуда разрешён SSH">
          <Select
            mode="tags"
            style={{ width: '100%' }}
            placeholder="Пусто — из любого адреса (с защитой от перебора)"
            defaultValue={node.ssh_allow}
            onChange={(v) => onSave({ ssh_allow: v })}
            tokenSeparators={[',', ' ']}
          />
        </Card>
      )}
      <Card size="small" title="Открытые порты на сервере">
        {s?.firewall_ports?.length ? (
          <Rows>
            {s.firewall_ports.map((l) => (
              <RowItem key={l} compact title={<span className="mono" style={{ fontSize: 12, fontWeight: 400 }}>{l}</span>} />
            ))}
          </Rows>
        ) : (
          <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={s?.firewall_active ? 'Только Mesh' : 'Firewall не активен'} />
        )}
      </Card>
    </Space>
  )
}
