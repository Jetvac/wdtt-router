import { useEffect, useMemo, useState } from 'react'
import { Alert, App, Button, Card, Col, Empty, Row, Space, Steps, Tag, Typography } from 'antd'
import { RowItem, Rows } from '../components/Rows'
import { ArrowDownOutlined, ArrowUpOutlined, CloseOutlined, PlusOutlined, SaveOutlined } from '@ant-design/icons'
import { post, put } from '../api'
import { navigate } from '../App'
import { useJobs } from '../components/Jobs'
import type { NodeView, Overview } from '../types'
import { HealthBadge, MeshTag, usePoll } from '../util'

export default function Chain() {
  const { data, reload } = usePoll<Overview>('/api/overview')
  const [order, setOrder] = useState<number[]>([])
  const [busy, setBusy] = useState(false)
  const { track } = useJobs()
  const { message } = App.useApp()

  useEffect(() => {
    if (!data) return
    const entry = data.nodes.find((n) => n.local)
    const saved = data.chain.slice(1)
    setOrder(entry ? [entry.id, ...saved] : saved)
  }, [data])

  const byId = useMemo(() => new Map((data?.nodes || []).map((n) => [n.id, n])), [data])
  if (!data) return <Card loading />
  const entry = data.nodes.find((n) => n.local)!
  const hops = order.slice(1).map((id) => byId.get(id)!).filter(Boolean)
  const available = data.nodes.filter((n) => !n.local && !order.includes(n.id))
  const savedKey = JSON.stringify(data.chain.length ? data.chain : [entry.id])
  const dirty = JSON.stringify(order) !== savedKey
  const entryReady = !!entry.cf_node_id

  const move = (i: number, d: number) => {
    const h = order.slice(1)
    const j = i + d
    if (j < 0 || j >= h.length) return
    ;[h[i], h[j]] = [h[j], h[i]]
    setOrder([order[0], ...h])
  }

  const save = async (apply: boolean) => {
    setBusy(true)
    try {
      await put('/api/chain', { chain: hops.length ? order : [] })
      message.success('Цепочка сохранена')
      if (apply) {
        const r = await post<{ job_id: number }>('/api/apply')
        track(r.job_id, () => reload())
      }
      reload()
    } catch (e: any) {
      message.error(e.message)
    } finally {
      setBusy(false)
    }
  }

  const roleOf = (i: number) => (i === hops.length - 1 ? <Tag color="green">выход</Tag> : <Tag color="purple">промежуточный</Tag>)

  return (
    <Space orientation="vertical" size="middle" style={{ width: '100%' }}>
      <Alert
        type="info"
        showIcon
        title="Как устроена цепочка"
        description={
          <>
            Трафик клиентов шифруется на сервере панели отдельно для каждого звена («луковица», VLESS Encryption с постквантовым обменом ключей) и идёт по Cloudflare Mesh.
            Каждый сервер знает только Mesh-адрес следующего звена и не видит содержимого — расшифровать его может только выходной сервер. Публичные адреса серверов друг другу неизвестны.
          </>
        }
      />
      {!entryReady && (
        <Alert
          type="warning"
          showIcon
          title="Сервер панели не подключён к Mesh"
          action={<Button size="small" onClick={() => navigate('/servers')}>К серверам</Button>}
        />
      )}
      <Row gutter={[16, 16]}>
        <Col xs={24} lg={14}>
          <Card
            title="Порядок серверов"
            extra={
              <Space>
                <Button icon={<SaveOutlined />} disabled={!dirty} loading={busy} onClick={() => save(false)}>
                  Сохранить
                </Button>
                <Button type="primary" disabled={!entryReady} loading={busy} onClick={() => save(true)}>
                  Сохранить и применить
                </Button>
              </Space>
            }
          >
            <Steps
              orientation="vertical"
              size="small"
              current={-1}
              items={[
                {
                  title: (
                    <Space>
                      {entry.name}
                      <Tag color="blue">вход · панель</Tag>
                    </Space>
                  ),
                  content: <MeshTag n={entry} />,
                  status: 'finish',
                },
                ...hops.map((n, i) => ({
                  title: (
                    <Space wrap>
                      {n.name}
                      {roleOf(i)}
                      <Button size="small" type="text" icon={<ArrowUpOutlined />} disabled={i === 0} onClick={() => move(i, -1)} aria-label="Выше" />
                      <Button size="small" type="text" icon={<ArrowDownOutlined />} disabled={i === hops.length - 1} onClick={() => move(i, 1)} aria-label="Ниже" />
                      <Button size="small" type="text" danger icon={<CloseOutlined />} onClick={() => setOrder(order.filter((x) => x !== n.id))} aria-label="Убрать" />
                    </Space>
                  ),
                  content: (
                    <Space>
                      <MeshTag n={n} />
                      <HealthBadge n={n} />
                    </Space>
                  ),
                  status: 'process' as const,
                })),
                { title: 'Интернет', status: 'wait' as const, content: hops.length ? `выход через ${hops[hops.length - 1].name}` : 'добавьте хотя бы один сервер' },
              ]}
            />
            {dirty && <Typography.Text type="warning">Есть несохранённые изменения</Typography.Text>}
          </Card>
        </Col>
        <Col xs={24} lg={10}>
          <Card title="Доступные серверы" extra={<Button type="link" onClick={() => navigate('/servers')}>Добавить сервер</Button>}>
            {available.length === 0 ? (
              <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="Все серверы уже в цепочке" />
            ) : (
              <Rows>
                {available.map((n: NodeView) => {
                  const ready = !!n.cf_node_id && !!n.mesh_ip
                  return (
                    <RowItem
                      key={n.id}
                      title={n.name}
                      description={ready ? <MeshTag n={n} /> : 'не подключён к Mesh'}
                      extra={
                        <Button icon={<PlusOutlined />} disabled={!ready} onClick={() => setOrder([...order, n.id])}>
                          В цепочку
                        </Button>
                      }
                    />
                  )
                })}
              </Rows>
            )}
          </Card>
        </Col>
      </Row>
    </Space>
  )
}
