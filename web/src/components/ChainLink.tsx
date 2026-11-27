import { useState } from 'react'
import { Alert, App, Badge, Card, Descriptions, Segmented, Space, Table, Typography } from 'antd'
import { put } from '../api'
import type { LinkMode, LinkStatus, LinkView, Probe } from '../types'
import { fmtBytes } from '../util'
import dayjs from 'dayjs'

const modeText: Record<LinkMode, string> = {
  off: 'Весь трафик клиентов идёт через Xray, как раньше. «Проверка» поднимает туннель рядом с Xray и меряет его, не трогая трафик клиентов.',
  check: 'Туннель поднят и проверяется. Трафик клиентов идёт через Xray.',
  udp: 'UDP и ICMP клиентов (DNS, QUIC, звонки, игры) идут через туннель, TCP — через Xray. Если туннель не отвечает 3 с, UDP сам возвращается на Xray.',
}

const unix = (t?: number) => (t ? dayjs.unix(t) : null)
const ms = (v?: number) => (v ? `${Math.round(v)} мс` : '—')
const mbps = (v?: number) => (v ? `${v.toFixed(1)} Мбит/с` : '—')
/** A packet count; "—" when that end has not reported one (older version). */
const count = (v?: number) => (v === undefined ? '—' : v.toLocaleString('ru-RU'))

function handshake(age?: number) {
  if (age === undefined || age < 0) return 'ещё не было'
  return `${age} с назад`
}

/** The chain tunnel (docs/chain-link.md): mode, state, and the last check
 * side by side with Xray. */
export function ChainLinkCard({ link, probe, onJob }: { link: LinkView; probe: Probe | null; onJob: (jobId: number) => void }) {
  const { message, modal } = App.useApp()
  const [busy, setBusy] = useState(false)
  const e: LinkStatus | undefined = link.entry
  const x: LinkStatus | undefined = link.exit
  const missing = link.missing || []

  const apply = async (mode: LinkMode) => {
    setBusy(true)
    try {
      const r = await put<{ job_id: number }>('/api/chain/link', { mode })
      message.success(mode === 'off' ? 'Туннель выключается' : mode === 'check' ? 'Туннель поднимается для проверки' : 'UDP клиентов переходит на туннель')
      onJob(r.job_id)
    } catch (err: any) {
      message.error(err.message)
    } finally {
      setBusy(false)
    }
  }

  const change = (mode: LinkMode) => {
    if (mode === 'udp') {
      modal.confirm({
        title: 'Пустить UDP клиентов через туннель?',
        content: 'Идущие сейчас звонки и QUIC-соединения один раз переподключатся. TCP это не затрагивает. Вернуть всё на Xray можно в любой момент.',
        okText: 'Включить',
        cancelText: 'Отмена',
        onOk: () => apply(mode),
      })
      return
    }
    if (mode === 'off' && link.mode !== 'off') {
      modal.confirm({
        title: 'Выключить туннель?',
        content: link.mode === 'udp' ? 'UDP клиентов сразу вернётся на Xray, туннель остановится на всех серверах.' : 'Туннель остановится на всех серверах.',
        okText: 'Выключить',
        cancelText: 'Отмена',
        onOk: () => apply(mode),
      })
      return
    }
    apply(mode)
  }

  const switchAt = unix(e?.switch_at)
  const held = unix(e?.held_until)
  const l = probe?.link

  return (
    <Card title="Туннель цепочки">
      <Space orientation="vertical" size="middle" style={{ width: '100%' }}>
        <Segmented<LinkMode>
          value={link.mode}
          disabled={busy || (missing.length > 0 && link.mode === 'off')}
          onChange={change}
          options={[
            { label: 'Xray', value: 'off' },
            { label: 'Проверка', value: 'check' },
            { label: 'UDP через туннель', value: 'udp', disabled: !link.ready && link.mode !== 'udp' },
          ]}
        />
        <Typography.Text type="secondary">{modeText[link.mode]}</Typography.Text>
        {missing.length > 0 && (
          <Alert type="warning" showIcon title={`Туннель появится после обновления серверов: ${missing.join(', ')}`} description="Обновите панель и нажмите «Применить»: серверы получат новую версию." />
        )}
        {link.mode === 'check' && !link.ready && link.why && <Alert type="info" showIcon title={`Включить UDP через туннель можно, когда пройдёт проверка: ${link.why}`} />}
        {held && held.isAfter(dayjs()) && <Alert type="warning" showIcon title={`Туннель часто пропадал: UDP остаётся на Xray до ${held.format('HH:mm')}`} />}
        {link.mode !== 'off' && e && (
          <Descriptions size="small" column={{ xs: 1, md: 2 }} bordered>
            <Descriptions.Item label="Состояние">
              {e.healthy ? <Badge status="success" text="исправен" /> : <Badge status="error" text={e.problem || 'неисправен'} />}
            </Descriptions.Item>
            <Descriptions.Item label="UDP клиентов">
              {e.routing ? <Badge status="processing" text="через туннель" /> : <Badge status="default" text="через Xray" />}
              {switchAt && (
                <Typography.Text type="secondary">
                  {' '}
                  · {switchAt.fromNow()}
                  {e.switch_to === 'xray' && e.switch_why ? `: ${e.switch_why}` : ''}
                </Typography.Text>
              )}
            </Descriptions.Item>
            <Descriptions.Item label="Круг по туннелю">
              {e.rtt_p50_ms ? `${ms(e.rtt_p50_ms)}, 95 % — ${ms(e.rtt_p95_ms)}` : '—'} · потери {((e.loss || 0) * 100).toFixed(1)} %
            </Descriptions.Item>
            <Descriptions.Item label="DNS через туннель">
              {e.dns_error ? <Typography.Text type="danger">{e.dns_error}</Typography.Text> : ms(e.dns_ms)}
              {e.dns_at ? <Typography.Text type="secondary"> · {dayjs.unix(e.dns_at).fromNow()}</Typography.Text> : null}
            </Descriptions.Item>
            <Descriptions.Item label="Размер пакетов">
              MTU Mesh {e.mesh_mtu || '—'} · датаграмма {e.datagram || '—'} · проверено {e.confirmed || '—'}
            </Descriptions.Item>
            <Descriptions.Item label="Рукопожатие">
              вход {handshake(e.handshake_age)} · выход {handshake(link.exit?.handshake_age)}
            </Descriptions.Item>
            <Descriptions.Item label="Трафик туннеля">
              ↓ {fmtBytes(e.rx_bytes)} · ↑ {fmtBytes(e.tx_bytes)}
              {e.split ? ` · крупных пакетов частями ${e.split}` : ''}
              {e.expired ? ` · не собрано ${e.expired}` : ''}
            </Descriptions.Item>
            <Descriptions.Item label="Пакеты через туннель">
              туда: ушло со входа {count(e.tun_out)} · вышло на выходе {count(x?.tun_in)}
              <br />
              обратно: ушло с выхода {count(x?.tun_out)} · пришло на вход {count(e.tun_in)}
            </Descriptions.Item>
            {x?.public_iface && (
              <Descriptions.Item label="Выход в Интернет">
                через {x.public_iface}
                {x.forward && <Typography.Text type="secondary"> · {x.forward}</Typography.Text>}
              </Descriptions.Item>
            )}
            {(e.path_problem || x?.path_problem) && (
              <Descriptions.Item label="Путь пакетов">
                {x?.path_problem && <Typography.Text type="danger">выход: {x.path_problem}</Typography.Text>}
                {x?.path_problem && e.path_problem && <br />}
                {e.path_problem && <Typography.Text type="danger">вход: {e.path_problem}</Typography.Text>}
              </Descriptions.Item>
            )}
            {e.route_error && (
              <Descriptions.Item label="Ошибка маршрута">
                <Typography.Text type="danger">{e.route_error}</Typography.Text>
              </Descriptions.Item>
            )}
          </Descriptions>
        )}
        {link.mode !== 'off' && !e && <Alert type="error" showIcon title="Служба туннеля на входе не отвечает" />}
        {probe && l && (
          <>
            <Typography.Text strong>Последняя проверка: Xray и туннель</Typography.Text>
            <Table
              size="small"
              pagination={false}
              rowKey="what"
              dataSource={[
                { what: 'DNS-запрос', xray: probe.udp_ok ? ms(probe.udp_ms) : '—', link: l.ok ? ms(l.dns_ms) : '—' },
                { what: 'Новый запрос HTTPS', xray: probe.ok ? ms(probe.tcp_ms) : '—', link: l.ok ? ms(l.tcp_ms) : '—' },
                { what: 'Скорость загрузки', xray: mbps(probe.speed_mbps), link: mbps(l.speed_mbps) },
              ]}
              columns={[
                { title: '', dataIndex: 'what' },
                { title: 'Xray', dataIndex: 'xray' },
                { title: 'Туннель', dataIndex: 'link' },
              ]}
            />
            {!l.ok && l.error && <Typography.Text type="danger">{l.error}</Typography.Text>}
            {l.ok && probe.link_match === false && <Typography.Text type="danger">Туннель выходит с {l.exit_ip}, ожидался {probe.expected_ip}</Typography.Text>}
            <Typography.Text type="secondary">Скорость меряется, когда проверку запускают кнопкой «Проверить».</Typography.Text>
          </>
        )}
      </Space>
    </Card>
  )
}
