import { useEffect, useState } from 'react'
import { Alert, App, Button, Card, Col, Descriptions, Form, Input, Row, Select, Space, Typography } from 'antd'
import { post, put } from '../api'
import { useJobs } from '../components/Jobs'
import { usePoll } from '../util'

interface SettingsData {
  panel_port: number
  panel_allow: string[]
  your_ip: string
  cert_fingerprint: string
  version: string
  xray_version: string
}

export default function Settings() {
  const { data, reload } = usePoll<SettingsData>('/api/settings')
  const [allow, setAllow] = useState<string[]>([])
  const [busy, setBusy] = useState(false)
  const [pwForm] = Form.useForm()
  const { message } = App.useApp()
  const { track } = useJobs()
  useEffect(() => {
    if (data) setAllow(data.panel_allow)
  }, [data])
  if (!data) return <Card loading />

  const saveAllow = async () => {
    setBusy(true)
    try {
      const r = await put<{ job_id: number }>('/api/settings/panel', { panel_allow: allow })
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

  return (
    <Row gutter={[16, 16]}>
      <Col xs={24} lg={12}>
        <Space orientation="vertical" size="middle" style={{ width: '100%' }}>
          <Card title="Доступ к веб-панели">
            <Typography.Paragraph type="secondary">
              Укажите адреса или подсети, с которых можно открыть панель (порт {data.panel_port}). Пусто — доступ отовсюду. Ваш текущий адрес: <Typography.Text code>{data.your_ip}</Typography.Text>
            </Typography.Paragraph>
            <Select mode="tags" style={{ width: '100%' }} value={allow} onChange={setAllow} tokenSeparators={[',', ' ']} placeholder="Например, 203.0.113.5 или 198.51.100.0/24" />
            {allow.length > 0 && !allow.includes(data.your_ip) && (
              <Alert style={{ marginTop: 12 }} type="warning" showIcon title="Ваш текущий адрес не входит в список" description="Панель не даст сохранить такой список, чтобы вы не потеряли доступ (если адрес не входит в одну из подсетей)." />
            )}
            <Button style={{ marginTop: 12 }} type="primary" loading={busy} onClick={saveAllow}>
              Сохранить и применить
            </Button>
          </Card>
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
      </Col>
    </Row>
  )
}
