import { useEffect, useState } from 'react'
import { Alert, App, Button, Card, Col, Descriptions, Form, Input, Radio, Row, Select, Space, Typography } from 'antd'
import { post, put } from '../api'
import { useJobs } from '../components/Jobs'
import { usePoll } from '../util'
import TelegramBot from '../components/TelegramBot'
import BackupCard, { DiagnosticsCard } from '../components/BackupCard'
import { UpdateCard } from '../components/Update'
import type { Overview } from '../types'

interface SettingsData {
  panel_port: number
  panel_allow: string[]
  your_ip: string
  cert_fingerprint: string
  version: string
  xray_version: string
  mesh_only: boolean
  via_mesh: boolean
  via_tunnel: boolean
  mesh_url: string
}

export default function Settings() {
  const { data, reload } = usePoll<SettingsData>('/api/settings')
  const { data: ov } = usePoll<Overview>('/api/overview', 30000)
  const [allow, setAllow] = useState<string[]>([])
  const [mode, setMode] = useState<'any' | 'list' | 'mesh'>('any')
  const [busy, setBusy] = useState(false)
  const [pwForm] = Form.useForm()
  const { message } = App.useApp()
  const { track } = useJobs()
  useEffect(() => {
    if (data) {
      setAllow(data.panel_allow)
      setMode(data.mesh_only ? 'mesh' : data.panel_allow.length ? 'list' : 'any')
    }
  }, [data])
  if (!data) return <Card loading />

  const saveAllow = async () => {
    setBusy(true)
    try {
      const r = await put<{ job_id: number }>('/api/settings/panel', { panel_allow: mode === 'list' ? allow : [], mesh_only: mode === 'mesh' })
      track(r.job_id, () => reload())
    } catch (e: any) {
      message.error(e.message)
    } finally {
      setBusy(false)
    }
  }
  const changePassword = async () => {
    const v = await pwForm.validateFields()
    try {
      await post('/api/account/password', { old: v.old, new: v.new })
      message.success('Пароль изменён. Остальные сессии завершены.')
      pwForm.resetFields()
    } catch (e: any) {
      message.error(e.message)
    }
  }

  // Through Mesh or the app's SSH tunnel access survives Mesh-only mode.
  const safe = data.via_mesh || data.via_tunnel
  return (
    <Row gutter={[16, 16]}>
      <Col xs={24} lg={12}>
        <Space orientation="vertical" size="middle" style={{ width: '100%' }}>
          <Card title="Доступ к веб-панели">
            <Radio.Group value={mode} onChange={(e) => setMode(e.target.value)} style={{ display: 'grid', gap: 8, marginBottom: 12 }}>
              <Radio value="any">Из любого адреса</Radio>
              <Radio value="list">Только с указанных адресов</Radio>
              <Radio value="mesh">Только из приложения или через Mesh — порт закрыт для Интернета</Radio>
            </Radio.Group>
            {!data.via_tunnel && (
              <Alert
                style={{ marginBottom: 12 }}
                type="info"
                showIcon
                title="Приложение для Windows"
                description={
                  <>
                    Открывает панель через SSH: без пароля, без предупреждений о сертификате и без открытого порта — режим «только из приложения» закрывает его для
                    Интернета. Значок в трее показывает состояние серверов и присылает уведомления.{' '}
                    <Typography.Link href="https://github.com/Jetvac/wdtt-router/releases/latest/download/wdtt-router-windows-amd64.exe">Скачать</Typography.Link>
                  </>
                }
              />
            )}
            <Typography.Paragraph type="secondary">
              Порт панели {data.panel_port}. Ваш текущий адрес: <Typography.Text code>{data.your_ip}</Typography.Text>
              {data.via_tunnel ? ' (приложение, через SSH)' : data.via_mesh ? ' (через Mesh)' : ''}
            </Typography.Paragraph>
            {mode === 'mesh' && (
              <Alert
                style={{ marginBottom: 12 }}
                type={safe ? 'info' : 'warning'}
                showIcon
                title={data.via_tunnel ? 'Вы в приложении для Windows — режим можно включить' : data.via_mesh ? 'Вы подключены через Mesh — режим можно включить' : 'Откройте панель в приложении или через Mesh'}
                description={
                  <>
                    Порт панели закроется для Интернета. Открыть панель можно будет в приложении WDTT Router для Windows (оно подключается по SSH) или с устройств, где запущен Cloudflare WARP с вашей командой, по адресу{' '}
                    <Typography.Text code copyable>{data.mesh_url || 'сервер ещё не в Mesh'}</Typography.Text>.
                    {!safe && ' Включить режим можно только из такой сессии, чтобы не потерять доступ.'}
                  </>
                }
              />
            )}
            {mode === 'list' && (
              <Select mode="tags" style={{ width: '100%' }} value={allow} onChange={setAllow} tokenSeparators={[',', ' ']} placeholder="Например, 203.0.113.5 или 198.51.100.0/24" />
            )}
            {mode === 'list' && allow.length > 0 && !data.via_tunnel && !allow.includes(data.your_ip) && (
              <Alert style={{ marginTop: 12 }} type="warning" showIcon title="Ваш текущий адрес не входит в список" description="Панель не даст сохранить такой список, чтобы вы не потеряли доступ (если адрес не входит в одну из подсетей)." />
            )}
            <Button style={{ marginTop: 12 }} type="primary" loading={busy} disabled={mode === 'mesh' && !safe} onClick={saveAllow}>
              Сохранить и применить
            </Button>
          </Card>
          <UpdateCard />
          <BackupCard />
          <DiagnosticsCard />
          <Card title="О панели">
            <Descriptions column={1} size="small" bordered>
              <Descriptions.Item label="Версия">{data.version}</Descriptions.Item>
              <Descriptions.Item label="Xray">{data.xray_version}</Descriptions.Item>
              <Descriptions.Item label="Отпечаток сертификата">
                <Typography.Text className="mono" style={{ fontSize: 11 }} copyable>
                  {data.cert_fingerprint}
                </Typography.Text>
              </Descriptions.Item>
            </Descriptions>
            <Typography.Paragraph type="secondary" style={{ marginTop: 12, marginBottom: 0 }}>
              Сверьте отпечаток с выводом <Typography.Text code>wdtt-router fingerprint</Typography.Text> на сервере, прежде чем доверять сертификату в браузере.
            </Typography.Paragraph>
          </Card>
        </Space>
      </Col>
      <Col xs={24} lg={12}>
        <Space orientation="vertical" size="middle" style={{ width: '100%' }}>
        <TelegramBot nodes={ov?.nodes || []} />
        <Card title="Смена пароля">
          <Form form={pwForm} layout="vertical" style={{ maxWidth: 400 }}>
            <Form.Item name="old" label="Текущий пароль" rules={[{ required: true, message: 'Введите текущий пароль' }]}>
              <Input.Password autoComplete="current-password" />
            </Form.Item>
            <Form.Item name="new" label="Новый пароль" rules={[{ required: true, min: 16, message: 'Не короче 16 символов' }]}>
              <Input.Password autoComplete="new-password" />
            </Form.Item>
            <Form.Item
              name="repeat"
              label="Повторите пароль"
              dependencies={['new']}
              rules={[{ required: true, message: 'Повторите пароль' }, ({ getFieldValue }) => ({ validator: (_, v) => (v === getFieldValue('new') ? Promise.resolve() : Promise.reject(new Error('Пароли не совпадают'))) })]}
            >
              <Input.Password autoComplete="new-password" />
            </Form.Item>
            <Button type="primary" onClick={changePassword}>
              Сменить пароль
            </Button>
          </Form>
        </Card>
        </Space>
      </Col>
    </Row>
  )
}
