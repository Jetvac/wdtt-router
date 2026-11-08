import { useEffect } from 'react'
import { Alert, Button, Card, Col, Empty, Row, Space, Table, Tag, Typography } from 'antd'
import { RowItem, Rows } from '../components/Rows'
import { CheckCircleFilled, ExclamationCircleFilled } from '@ant-design/icons'
import { navigate } from '../App'
import { useJobs } from '../components/Jobs'
import type { NodeView, Overview } from '../types'
import { RoleTag, usePoll } from '../util'

interface Finding {
  ok: boolean
  text: string
}

function audit(n: NodeView, d: Overview): Finding[] {
  const f: Finding[] = []
  f.push({ ok: n.firewall && !!n.status?.firewall_active, text: n.firewall ? (n.status?.firewall_active ? 'Firewall активен: открыты только нужные порты' : 'Firewall включён в настройках, но не применён') : 'Firewall выключен' })
  if (!n.local) {
    f.push({ ok: !n.ssh_public, text: n.ssh_public ? 'SSH открыт из Интернета' : 'SSH доступен только через Mesh' })
    f.push({ ok: !!n.cf_node_id, text: n.cf_node_id ? 'Связь с другими серверами — только через Mesh' : 'Сервер не подключён к Mesh' })
  } else {
    f.push({ ok: n.ssh_allow.length > 0, text: n.ssh_allow.length ? `SSH разрешён только с: ${n.ssh_allow.join(', ')}` : 'SSH панели открыт для всех (с защитой от перебора)' })
    f.push({ ok: d.services.panel_allow.length > 0, text: d.services.panel_allow.length ? `Веб-панель доступна только с: ${d.services.panel_allow.join(', ')}` : 'Веб-панель доступна из любого адреса' })
    if (d.services.xui_enabled) f.push({ ok: d.services.xui_route_via_chain, text: d.services.xui_route_via_chain ? 'Трафик 3x-ui идёт через цепочку' : 'Трафик 3x-ui выходит напрямую' })
  }
  f.push({ ok: !n.allow_ping, text: n.allow_ping ? 'Отвечает на ping' : 'Не отвечает на ping' })
  if (n.status?.revert_pending) f.push({ ok: false, text: 'Изменение firewall ожидает подтверждения' })
  return f
}

export default function Security() {
  const { data, reload } = usePoll<Overview>('/api/overview', 15000)
  const { version } = useJobs()
  useEffect(() => {
    reload()
  }, [version, reload])
  if (!data) return <Card loading />
  const all = data.nodes.flatMap((n) => audit(n, data))
  const bad = all.filter((x) => !x.ok).length
  return (
    <Space orientation="vertical" size="middle" style={{ width: '100%' }}>
      <Alert
        type={bad ? 'warning' : 'success'}
        showIcon
        title={bad ? `Рекомендаций по усилению защиты: ${bad}` : 'Все рекомендации выполнены'}
        description="Каждый сервер пропускает только необходимые подключения: звено цепочки и SSH — только из Mesh, сервисы — только на сервере панели. Изменения firewall применяются с автоматическим откатом, если панель потеряет связь с сервером."
      />
      <Row gutter={[16, 16]}>
        {data.nodes.map((n) => (
          <Col xs={24} lg={12} key={n.id}>
            <Card
              title={
                <Space>
                  {n.name}
                  <RoleTag role={n.role} />
                </Space>
              }
              extra={<Button type="link" onClick={() => navigate('/servers')}>Настроить</Button>}
            >
              <Rows>
                {audit(n, data).map((x, i) => (
                  <RowItem
                    key={i}
                    compact
                    avatar={x.ok ? <CheckCircleFilled style={{ color: '#52c41a' }} /> : <ExclamationCircleFilled style={{ color: '#faad14' }} />}
                    title={<span style={{ fontWeight: 400 }}>{x.text}</span>}
                  />
                ))}
              </Rows>
              <Typography.Text type="secondary" style={{ display: 'block', margin: '12px 0 6px' }}>
                Входящие подключения
              </Typography.Text>
              {n.status?.firewall_ports?.length ? (
                <Table
                  size="small"
                  pagination={false}
                  rowKey={(r) => r}
                  dataSource={n.status.firewall_ports}
                  columns={[{ title: 'Правило', render: (r: string) => <span className="mono" style={{ fontSize: 12 }}>{r}</span> }]}
                />
              ) : (
                <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={n.status?.firewall_active ? 'Только Mesh (SSH и звено цепочки)' : 'Нет данных'} />
              )}
              {n.hop_port > 0 && n.in_chain && !n.local && <Tag style={{ marginTop: 8 }}>Звено цепочки: TCP {n.hop_port}, только из Mesh</Tag>}
            </Card>
          </Col>
        ))}
      </Row>
    </Space>
  )
}
