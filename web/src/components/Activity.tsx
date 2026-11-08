import { useEffect, useState } from 'react'
import { Card, Col, Empty, List, Row, Segmented, Tag, theme, Typography } from 'antd'
import { get } from '../api'
import { LineChart } from './Charts'
import type { NodeView } from '../types'
import { fromNow } from '../util'

interface Point {
  t: number
  load: number
  mem: number
  rx: number
  tx: number
  sessions: number
}

interface Metrics {
  hours: number
  bucket: number
  ping: { t: number; ms: number }[]
  nodes: Record<string, Point[]>
}

/** Load, memory and traffic of every server, WDTT sessions and the chain
 * latency over the last day or week. */
export function MetricsCard({ nodes }: { nodes: NodeView[] }) {
  const [hours, setHours] = useState(24)
  const [m, setM] = useState<Metrics | null>(null)
  const { token } = theme.useToken()
  useEffect(() => {
    const load = () => get<Metrics>(`/api/metrics?hours=${hours}`).then(setM).catch(() => {})
    load()
    const t = setInterval(load, 60000)
    return () => clearInterval(t)
  }, [hours])
  const entry = nodes.find((n) => n.local)
  const wdtt = entry && m ? (m.nodes[String(entry.id)] || []).filter((p) => p.sessions >= 0) : []
  return (
    <Card
      title="Нагрузка и трафик"
      loading={!m}
      extra={<Segmented size="small" value={hours} onChange={(v) => setHours(v as number)} options={[{ value: 24, label: '24 ч' }, { value: 168, label: '7 дней' }]} />}
    >
      {m && (
        <Row gutter={[24, 24]}>
          {nodes.map((n) => {
            const pts = m.nodes[String(n.id)] || []
            return (
              <Col xs={24} xl={12} key={n.id}>
                <Typography.Text strong>{n.name}</Typography.Text>
                <Row gutter={[16, 8]} style={{ marginTop: 6 }}>
                  <Col xs={24} md={12}>
                    <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                      Трафик, Мбит/с
                    </Typography.Text>
                    <LineChart
                      bucket={m.bucket}
                      unit=""
                      lines={[
                        { name: 'входящий', color: token.colorPrimary, points: pts.map((p) => [p.t, p.rx]) },
                        { name: 'исходящий', color: token.colorSuccess, points: pts.map((p) => [p.t, p.tx]) },
                      ]}
                    />
                  </Col>
                  <Col xs={24} md={12}>
                    <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                      Нагрузка и память
                    </Typography.Text>
                    <LineChart bucket={m.bucket} digits={0} unit="%" max={100} lines={[{ name: 'память', color: token.colorWarning, points: pts.map((p) => [p.t, p.mem]) }]} />
                    <LineChart bucket={m.bucket} height={60} digits={2} lines={[{ name: 'load', color: token.colorTextSecondary, points: pts.map((p) => [p.t, p.load]) }]} />
                  </Col>
                </Row>
              </Col>
            )
          })}
          <Col xs={24} md={12}>
            <Typography.Text strong>Сессии WDTT</Typography.Text>
            <LineChart bucket={m.bucket} digits={0} lines={[{ name: 'сессий', color: token.colorPrimary, points: wdtt.map((p) => [p.t, p.sessions]) }]} />
          </Col>
          <Col xs={24} md={12}>
            <Typography.Text strong>Задержка цепочки (TCP)</Typography.Text>
            <LineChart bucket={300} digits={0} unit=" мс" lines={[{ name: 'TCP', color: token.colorInfo, points: m.ping.map((p) => [p.t, p.ms]) }]} />
          </Col>
        </Row>
      )}
    </Card>
  )
}

interface Event {
  id: number
  at: string
  kind: string
  text: string
}

const KIND: Record<string, [string, string]> = {
  server: ['Серверы', 'blue'],
  chain: ['Цепочка', 'purple'],
  wdtt: ['WDTT', 'cyan'],
  security: ['Безопасность', 'orange'],
  jobs: ['Задачи', 'red'],
  update: ['Обновления', 'green'],
  test: ['Проверка', 'default'],
}

/** Recent events: what the Telegram bot would send. */
export function EventsCard() {
  const [events, setEvents] = useState<Event[] | null>(null)
  useEffect(() => {
    const load = () => get<Event[]>('/api/events').then(setEvents).catch(() => {})
    load()
    const t = setInterval(load, 30000)
    return () => clearInterval(t)
  }, [])
  return (
    <Card title="События" loading={!events}>
      {events && events.length === 0 ? (
        <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="Пока ничего не происходило" />
      ) : (
        <List
          size="small"
          dataSource={(events || []).slice(0, 12)}
          renderItem={(e) => (
            <List.Item>
              <div style={{ width: '100%' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
                  <Tag color={KIND[e.kind]?.[1]}>{KIND[e.kind]?.[0] || e.kind}</Tag>
                  <Typography.Text type="secondary" style={{ fontSize: 12, whiteSpace: 'nowrap' }}>
                    {fromNow(e.at)}
                  </Typography.Text>
                </div>
                <div style={{ marginTop: 4 }}>{e.text}</div>
              </div>
            </List.Item>
          )}
        />
      )}
    </Card>
  )
}
