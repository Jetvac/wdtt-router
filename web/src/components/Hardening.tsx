import { useState } from 'react'
import { App, Button, Input, List, Popconfirm, Space, Switch, Tag, Typography } from 'antd'
import { DeleteOutlined, KeyOutlined } from '@ant-design/icons'
import { patch, post } from '../api'
import { useJobs } from './Jobs'
import type { NodeView } from '../types'

/** Host protection of one server: SSH by key only, automatic security
 * updates and the administrator's SSH keys. Changes are saved and applied
 * to the server right away. */
export default function HardeningPanel({ node, reload }: { node: NodeView; reload: () => void }) {
  const h = node.hardening || {}
  const st = node.status?.hardening
  const keys = h.admin_keys || []
  const [newKey, setNewKey] = useState('')
  const [busy, setBusy] = useState(false)
  const { message } = App.useApp()
  const { track } = useJobs()

  const change = async (body: Record<string, unknown>) => {
    setBusy(true)
    try {
      await patch(`/api/nodes/${node.id}`, { hardening: body })
      const r = await post<{ job_id: number }>(`/api/nodes/${node.id}/apply`)
      track(r.job_id, () => reload())
      reload()
      return true
    } catch (e: any) {
      message.error(e.message)
      return false
    } finally {
      setBusy(false)
    }
  }
  const addKey = async () => {
    if (await change({ admin_keys: [...keys, newKey.trim()] })) setNewKey('')
  }
  const short = (k: string) => {
    const [type, body, ...comment] = k.split(' ')
    return `${type} …${body?.slice(-12) || ''}${comment.length ? ' ' + comment.join(' ') : ''}`
  }
  const noKey = keys.length === 0 && (st?.root_keys ?? 0) === 0

  return (
    <Space orientation="vertical" size={10} style={{ width: '100%' }}>
      <Space wrap>
        <Switch
          checked={!!h.ssh_keys_only}
          loading={busy}
          disabled={!h.ssh_keys_only && noKey}
          onChange={(v) => change({ ssh_keys_only: v })}
        />
        <span>Вход по SSH только по ключу</span>
        {st && <Tag color={st.ssh_password_auth ? 'orange' : 'green'}>{st.ssh_password_auth ? 'пароли разрешены' : 'пароли выключены'}</Tag>}
      </Space>
      {!h.ssh_keys_only && noKey && (
        <Typography.Text type="secondary">Сначала добавьте свой SSH-ключ ниже — иначе войти на сервер можно будет только через консоль провайдера.</Typography.Text>
      )}
      <Space wrap>
        <Switch checked={!!h.auto_updates} loading={busy} onChange={(v) => change({ auto_updates: v })} />
        <span>Автоматические обновления безопасности</span>
        {st && <Tag color={st.auto_updates ? 'green' : 'default'}>{st.auto_updates ? 'включены' : 'выключены'}</Tag>}
        {st?.reboot_required && <Tag color="orange">нужна перезагрузка</Tag>}
      </Space>
      <Typography.Text type="secondary" style={{ display: 'block' }}>
        Ваши SSH-ключи для root{st ? ` · всего ключей на сервере: ${st.root_keys}` : ''}
      </Typography.Text>
      {keys.length > 0 && (
        <List
          size="small"
          bordered
          dataSource={keys}
          renderItem={(k) => (
            <List.Item
              actions={[
                <Popconfirm
                  key="del"
                  title="Удалить ключ с сервера?"
                  description={h.ssh_keys_only && keys.length === 1 ? 'Это последний ваш ключ: убедитесь, что у вас есть другой способ входа.' : undefined}
                  okText="Удалить"
                  cancelText="Отмена"
                  onConfirm={() => change({ admin_keys: keys.filter((x) => x !== k) })}
                >
                  <Button type="text" size="small" danger icon={<DeleteOutlined />} />
                </Popconfirm>,
              ]}
            >
              <Space>
                <KeyOutlined />
                <span className="mono" style={{ fontSize: 12, wordBreak: 'break-all' }}>{short(k)}</span>
              </Space>
            </List.Item>
          )}
        />
      )}
      <Space.Compact style={{ width: '100%' }}>
        <Input placeholder="ssh-ed25519 AAAA… user@pc" value={newKey} onChange={(e) => setNewKey(e.target.value)} onPressEnter={() => newKey.trim() && addKey()} />
        <Button type="primary" disabled={!newKey.trim()} loading={busy} onClick={addKey}>
          Добавить
        </Button>
      </Space.Compact>
    </Space>
  )
}
