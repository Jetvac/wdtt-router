import { useEffect, useState } from 'react'
import { Alert, Card, Col, Row, Space, Statistic, Tabs } from 'antd'
import { useJobs } from '../components/Jobs'
import { KindTag, useWDTTKeys, WDTTDevicesCard, WDTTKeysCard, wdttKinds } from '../components/WDTTKeys'
import type { WDTTKeysData, WDTTKind } from '../types'
import { fmtBytes, usePoll } from '../util'
import { WDTTCard, type ServicesData } from './Services'

const tabKey = 'wdtt.tab'

/** WDTT: two servers (standard client, TurnVK client), their keys, and every device. */
export default function WDTT() {
  const { data, reload } = usePoll<ServicesData>('/api/services', 15000)
  const { version } = useJobs()
  useEffect(() => {
    reload()
  }, [version, reload])
  const [tab, setTab] = useState<string>(() => {
    try {
      return localStorage.getItem(tabKey) || 'standard'
    } catch {
      return 'standard'
    }
  })
  const choose = (t: string) => {
    setTab(t)
    try {
      localStorage.setItem(tabKey, t)
    } catch {
      /* not essential */
    }
  }
  const anyOn = !!data?.settings.wdtt_enabled || !!data?.settings.turnvk?.enabled
  const keys = useWDTTKeys(anyOn)
  if (!data) return <Card loading />
  const reloadAll = () => {
    reload()
    keys.reload()
  }
  const enabled: Record<WDTTKind, boolean> = { standard: data.settings.wdtt_enabled, turnvk: !!data.settings.turnvk?.enabled }
  const server = (kind: WDTTKind) => (
    <ServerTab kind={kind} enabled={enabled[kind]} data={data} keys={keys.data} reload={reloadAll} reloadKeys={keys.reload} />
  )
  const online = (keys.data?.devices || []).filter((d) => d.sessions > 0).length
  return (
    <Tabs
      activeKey={tab}
      onChange={choose}
      items={[
        { key: 'standard', label: <Space size={6}>{wdttKinds.standard.title}<KindTag kind="standard" /></Space>, children: server('standard') },
        { key: 'turnvk', label: <Space size={6}>{wdttKinds.turnvk.title}<KindTag kind="turnvk" /></Space>, children: server('turnvk') },
        {
          key: 'devices',
          label: `Устройства${keys.data ? ` · ${keys.data.devices?.length ?? 0}${online ? `, в сети ${online}` : ''}` : ''}`,
          children: anyOn ? <WDTTDevicesCard data={keys.data} reload={keys.reload} /> : <Alert type="info" showIcon title="Оба сервера WDTT выключены" />,
        },
      ]}
    />
  )
}

function ServerTab({ kind, enabled, data, keys, reload, reloadKeys }: { kind: WDTTKind; enabled: boolean; data: ServicesData; keys: WDTTKeysData | null; reload: () => void; reloadKeys: () => void }) {
  const rt = keys?.servers?.[kind]?.runtime
  const list = (keys?.keys || []).filter((k) => (k.kind || 'standard') === kind)
  const devices = (keys?.devices || []).filter((d) => d.kind === kind)
  const online = devices.filter((d) => d.sessions > 0).length
  const down = list.reduce((a, k) => a + (k.down_bytes || 0), 0)
  const up = list.reduce((a, k) => a + (k.up_bytes || 0), 0)
  return (
    <Space orientation="vertical" size="middle" style={{ width: '100%' }}>
      {!enabled && (
        <Alert
          type="info"
          showIcon
          title={`Сервер для ${wdttKinds[kind].app} выключен`}
          description={
            kind === 'turnvk'
              ? 'Включите его переключателем в карточке ниже. Он работает рядом с сервером для стандартного клиента, на своём порту, и не мешает ему.'
              : 'Включите его переключателем в карточке ниже: сервер встроен в панель и запускается за несколько секунд.'
          }
        />
      )}
      {enabled && (
        <Row gutter={[16, 16]}>
          <Col xs={12} md={6}>
            <Card>
              <Statistic title="Сессий сейчас" value={rt?.sessions ?? 0} />
            </Card>
          </Col>
          <Col xs={12} md={6}>
            <Card>
              <Statistic title="Устройств в сети" value={online} suffix={`/ ${devices.length}`} />
            </Card>
          </Col>
          <Col xs={12} md={6}>
            <Card>
              <Statistic title="Ключей" value={list.length} />
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
        <Col xs={24} xl={enabled ? 10 : 24}>
          <WDTTCard data={data} kind={kind} keys={keys} reload={reload} />
        </Col>
        {enabled && (
          <Col xs={24} xl={14}>
            <WDTTKeysCard data={keys} kind={kind} reload={reloadKeys} />
          </Col>
        )}
      </Row>
    </Space>
  )
}
