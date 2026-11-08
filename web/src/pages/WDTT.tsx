import { useEffect } from 'react'
import { Alert, Card, Col, Row, Space, Statistic } from 'antd'
import { useJobs } from '../components/Jobs'
import { useWDTTKeys, WDTTKeysCard } from '../components/WDTTKeys'
import { fmtBytes, usePoll } from '../util'
import { WDTTCard, type ServicesData } from './Services'

/** WDTT: the server's settings, what is going on right now, access keys. */
export default function WDTT() {
  const { data, reload } = usePoll<ServicesData>('/api/services', 15000)
  const { version } = useJobs()
  useEffect(() => {
    reload()
  }, [version, reload])
  const keys = useWDTTKeys(!!data?.settings.wdtt_enabled)
  if (!data) return <Card loading />
  const rt = keys.data?.runtime
  const list = keys.data?.keys || []
  const online = list.filter((k) => k.sessions > 0).length
  const down = list.reduce((a, k) => a + (k.down_bytes || 0), 0)
  const up = list.reduce((a, k) => a + (k.up_bytes || 0), 0)
  const reloadAll = () => {
    reload()
    keys.reload()
  }
  return (
    <Space orientation="vertical" size="middle" style={{ width: '100%' }}>
      {!data.settings.wdtt_enabled && (
        <Alert type="info" showIcon title="WDTT выключен" description="Включите его переключателем в карточке ниже: сервер встроен в панель и запускается за несколько секунд." />
      )}
      {data.settings.wdtt_enabled && (
        <Row gutter={[16, 16]}>
          <Col xs={12} md={6}>
            <Card>
              <Statistic title="Сессий сейчас" value={rt?.sessions ?? 0} />
            </Card>
          </Col>
          <Col xs={12} md={6}>
            <Card>
              <Statistic title="Ключей в сети" value={online} suffix={`/ ${list.length}`} />
            </Card>
          </Col>
          <Col xs={12} md={6}>
            <Card>
              <Statistic title="Устройств" value={rt?.devices ?? 0} />
            </Card>
          </Col>
          <Col xs={12} md={6}>
            <Card>
              <Statistic title="Трафик ключей" value={`↓${fmtBytes(down)} ↑${fmtBytes(up)}`} styles={{ content: { fontSize: 18 } }} />
            </Card>
          </Col>
        </Row>
      )}
      <Row gutter={[16, 16]}>
        <Col xs={24} xl={data.settings.wdtt_enabled ? 10 : 24}>
          <WDTTCard data={data} keys={keys.data} reload={reloadAll} />
        </Col>
        {data.settings.wdtt_enabled && (
          <Col xs={24} xl={14}>
            <WDTTKeysCard data={keys.data} reload={keys.reload} />
          </Col>
        )}
      </Row>
    </Space>
  )
}
