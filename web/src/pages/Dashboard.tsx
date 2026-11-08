import { useEffect } from 'react'
import { Alert, App, Badge, Button, Card, Col, Empty, Flex, Row, Skeleton, Space, Statistic, Steps, Table, Tag, Tooltip, Typography } from 'antd'
import { CheckCircleFilled, CloseCircleFilled, GlobalOutlined, MobileOutlined, SendOutlined, ThunderboltOutlined } from '@ant-design/icons'
import { post } from '../api'
import { navigate } from '../App'
import { JobStatusTag, useJobs } from '../components/Jobs'
import type { NodeView, Overview } from '../types'
import { fromNow, HealthBadge, MeshTag, RoleTag, usePoll } from '../util'
import { EventsCard, MetricsCard } from '../components/Activity'

export default function Dashboard() {
  const { data, loading, reload } = usePoll<Overview>('/api/overview', 10000)
  const { track, version } = useJobs()
  const { message } = App.useApp()
  useEffect(() => {
    reload()
  }, [version, reload])

  if (loading && !data) return <Skeleton active paragraph={{ rows: 8 }} />
  if (!data) return <Empty />

  const byId = new Map(data.nodes.map((n) => [n.id, n]))
  const chain = data.chain.map((id) => byId.get(id)).filter(Boolean) as NodeView[]
  const remote = data.nodes.filter((n) => !n.local)
  const outOfSync = data.nodes.filter((n) => n.out_of_sync)
  const step = !data.cloudflare ? 0 : remote.length === 0 ? 1 : chain.length < 2 ? 2 : !data.services.wdtt_enabled && !data.services.xui_enabled ? 3 : 4

  const run = async (path: string) => {
    try {
      const r = await post<{ job_id: number }>(path)
      track(r.job_id, () => reload())
    } catch (e: any) {
      message.error(e.message)
    }
  }

  return (
    <Space orientation="vertical" size="middle" style={{ width: '100%' }}>
      {step < 4 && (
        <Card title="Первоначальная настройка">
          <Steps
            current={step}
            responsive
            items={[
              { title: 'Cloudflare', content: 'Аккаунт Zero Trust и токен', onClick: () => navigate('/cloudflare') },
              { title: 'Серверы', content: 'Добавьте выходной сервер', onClick: () => navigate('/servers') },
              { title: 'Цепочка', content: 'Порядок серверов', onClick: () => navigate('/chain') },
              { title: 'Сервисы', content: 'WDTT и/или 3x-ui', onClick: () => navigate('/services') },
            ]}
          />
        </Card>
      )}
      {data.plan_error && <Alert type="warning" showIcon title="Конфигурацию нельзя применить" description={data.plan_error} />}
      {outOfSync.length > 0 && !data.plan_error && (
        <Alert
          type="info"
          showIcon
          title={`Есть неприменённые изменения: ${outOfSync.map((n) => n.name).join(', ')}`}
          action={
            <Button size="small" type="primary" onClick={() => run('/api/apply')}>
              Применить
            </Button>
          }
        />
      )}

      <Row gutter={[16, 16]}>
        <Col xs={12} md={6}>
          <Card>
            <Statistic title="Серверов" value={data.nodes.length} suffix={<Typography.Text type="secondary" style={{ fontSize: 14 }}>· {data.nodes.filter((n) => !n.last_error && n.last_seen).length} в сети</Typography.Text>} />
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card>
            <Statistic title="Узлов в цепочке" value={chain.length} />
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card>
            <Statistic title="Выход в Интернет" value={data.probe?.ok ? data.probe.exit_ip : '—'} styles={{ content: { fontSize: 20 } }} />
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card>
            <Statistic title="Задержка TCP / UDP" value={data.probe?.ok ? `${data.probe.tcp_ms} / ${data.probe.udp_ms}` : '—'} suffix={data.probe?.ok ? 'мс' : ''} styles={{ content: { fontSize: 20 } }} />
          </Card>
        </Col>
      </Row>

      <Card
        title="Цепочка"
        extra={
          <Space>
            <Tooltip title="Проверить TCP и UDP через всю цепочку">
              <Button icon={<ThunderboltOutlined />} onClick={() => run('/api/probe')} disabled={chain.length < 2}>
                <span className="hide-sm">Проверить</span>
              </Button>
            </Tooltip>
            <Tooltip title="Применить конфигурацию ко всем серверам">
              <Button type="primary" icon={<SendOutlined />} onClick={() => run('/api/apply')} disabled={!!data.plan_error}>
                <span className="hide-sm">Применить</span>
              </Button>
            </Tooltip>
          </Space>
        }
      >
        {chain.length < 2 ? (
          <Empty description="Цепочка не настроена" image={Empty.PRESENTED_IMAGE_SIMPLE}>
            <Button type="primary" onClick={() => navigate('/chain')}>
              Настроить цепочку
            </Button>
          </Empty>
        ) : (
          <ChainFlow chain={chain} data={data} />
        )}
        {data.probe && (
          <Alert
            style={{ marginTop: 16 }}
            type={data.probe.ok && data.probe.match ? 'success' : 'error'}
            showIcon
            title={
              data.probe.ok && data.probe.match
                ? `Цепочка работает: трафик выходит в Интернет с ${data.probe.exit_ip} (${data.probe.exit_node}), Cloudflare ${data.probe.colo}`
                : `Проверка не прошла: ${data.probe.error || `выход с ${data.probe.exit_ip}, ожидался ${data.probe.expected_ip}`}`
            }
            description={`Последняя проверка ${fromNow(data.probe.at)} · TCP ${data.probe.tcp_ms} мс · UDP ${data.probe.udp_ok ? data.probe.udp_ms + ' мс' : 'нет'}`}
          />
        )}
      </Card>

      <Row gutter={[16, 16]}>
        <Col xs={24} lg={12}>
          <Card title="Серверы" extra={<Button type="link" onClick={() => navigate('/servers')}>Все серверы</Button>}>
            <Table
              size="small"
              rowKey="id"
              pagination={false}
              dataSource={data.nodes}
              scroll={{ x: true }}
              columns={[
                { title: 'Сервер', render: (_, n: NodeView) => <Space>{n.name}{n.local && <Tag>панель</Tag>}</Space> },
                { title: 'Роль', render: (_, n: NodeView) => <RoleTag role={n.role} /> },
                { title: 'Mesh', render: (_, n: NodeView) => <MeshTag n={n} /> },
                { title: 'Состояние', render: (_, n: NodeView) => <HealthBadge n={n} /> },
              ]}
            />
          </Card>
        </Col>
        <Col xs={24} lg={12}>
          <Card title="Последние задачи" extra={<Button type="link" onClick={() => navigate('/jobs')}>Все задачи</Button>}>
            <RecentJobs data={data} />
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]}>
        <Col xs={24} xl={16}>
          <MetricsCard nodes={data.nodes} />
        </Col>
        <Col xs={24} xl={8}>
          <EventsCard />
        </Col>
      </Row>
    </Space>
  )
}

function RecentJobs({ data }: { data: Overview }) {
  const { open } = useJobs()
  return (
    <Table
      size="small"
      rowKey="id"
      pagination={false}
      dataSource={data.jobs}
      locale={{ emptyText: 'Задач ещё не было' }}
      onRow={(j) => ({ onClick: () => open(j.id), style: { cursor: 'pointer' } })}
      columns={[
        { title: 'Задача', dataIndex: 'title', ellipsis: true },
        { title: 'Статус', width: 130, render: (_, j) => <JobStatusTag status={j.status} /> },
        { title: 'Когда', width: 120, render: (_, j) => fromNow(j.created_at) },
      ]}
    />
  )
}

function Arrow({ label }: { label?: string }) {
  return (
    <div className="chain-arrow">
      <div className="line" />
      {label && <span>{label}</span>}
    </div>
  )
}

function ChainFlow({ chain, data }: { chain: NodeView[]; data: Overview }) {
  const sources = [data.services.wdtt_enabled && 'WDTT', data.services.xui_enabled && '3x-ui'].filter(Boolean) as string[]
  return (
    <div className="chain-flow">
      <div className="chain-step">
        <Card className="chain-node endpoint" size="small">
          <Flex vertical gap={6}>
            <Space>
              <MobileOutlined />
              <Typography.Text strong>Клиенты</Typography.Text>
            </Space>
            {sources.length ? sources.map((s) => <Tag key={s} color="blue">{s}</Tag>) : <Typography.Text type="secondary">Сервисы не включены</Typography.Text>}
          </Flex>
        </Card>
      </div>
      {chain.map((n, i) => (
        <ChainPart key={n.id} n={n} first={i === 0} />
      ))}
      <Arrow label="выход" />
      <div className="chain-step" style={{ flex: '0 1 160px', minWidth: 140 }}>
        <Card className="chain-node endpoint" size="small">
          <Flex vertical gap={6}>
            <Space>
              <GlobalOutlined />
              <Typography.Text strong>Интернет</Typography.Text>
            </Space>
            <Typography.Text className="mono" type="secondary">
              {data.probe?.ok ? data.probe.exit_ip : chain[chain.length - 1]?.status?.public_ipv4}
            </Typography.Text>
          </Flex>
        </Card>
      </div>
    </div>
  )
}

function ChainPart({ n, first }: { n: NodeView; first: boolean }) {
  const meshOk = n.status?.mesh_status === 'Connected'
  const hopOk = n.status?.xray_active === 'active'
  return (
    <>
      <Arrow label={first ? '' : 'Mesh'} />
      <div className="chain-step">
        <Card className="chain-node" size="small" hoverable onClick={() => navigate('/servers')}>
          <Flex justify="space-between" align="center" style={{ marginBottom: 6 }}>
            <Typography.Text strong ellipsis style={{ maxWidth: 130 }}>
              {n.name}
            </Typography.Text>
            <RoleTag role={n.role} />
          </Flex>
          <div className="kv">
            <span>Mesh</span>
            <span className="mono">{n.mesh_ip || '—'}</span>
          </div>
          <div className="kv">
            <span>Mesh · звено</span>
            <span>
              <Tooltip title={`Mesh: ${n.status?.mesh_status || '—'}`}>{meshOk ? <CheckCircleFilled style={{ color: '#52c41a' }} /> : <CloseCircleFilled style={{ color: '#ff4d4f' }} />}</Tooltip>{' '}
              <Tooltip title={`Звено цепочки (Xray): ${n.status?.xray_active || '—'}`}>{hopOk ? <CheckCircleFilled style={{ color: '#52c41a' }} /> : <CloseCircleFilled style={{ color: '#ff4d4f' }} />}</Tooltip>
            </span>
          </div>
          <div className="kv">
            <span>Состояние</span>
            <span>{n.last_error ? <Badge status="error" text="нет связи" /> : n.out_of_sync ? <Badge status="warning" text="не применено" /> : <Badge status="success" text="ок" />}</span>
          </div>
        </Card>
      </div>
    </>
  )
}

