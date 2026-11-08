import { useEffect, useState } from 'react'
import { Alert, App, Button, Card, Col, Form, Input, Row, Skeleton, Space, Table, Tag, Typography } from 'antd'
import { RowItem, Rows } from '../components/Rows'
import { CheckCircleFilled, CloseCircleFilled, ReloadOutlined } from '@ant-design/icons'
import { get, post, put } from '../api'
import type { Check } from '../types'
import { fmtTime, usePoll } from '../util'

interface CF {
  account_id: string
  team: string
  configured: boolean
  error?: string
  connectors?: { id: string; name: string; status: string; created_at: string; owned: boolean }[]
}

const fixLabel: Record<string, string> = {
  enable_settings: 'Включить',
  create_profile: 'Создать профиль',
  disable_profile: 'Отключить профиль',
}

export default function Cloudflare() {
  const { data, reload, loading } = usePoll<CF>('/api/cloudflare')
  const [checks, setChecks] = useState<Check[] | null>(null)
  const [checking, setChecking] = useState(false)
  const [saving, setSaving] = useState(false)
  const [form] = Form.useForm()
  const { message, modal } = App.useApp()

  useEffect(() => {
    if (data) form.setFieldsValue({ account_id: data.account_id, team: data.team })
  }, [data, form])

  const preflight = async () => {
    setChecking(true)
    try {
      const r = await get<{ checks: Check[] }>('/api/cloudflare/preflight')
      setChecks(r.checks)
    } catch (e: any) {
      message.error(e.message)
    } finally {
      setChecking(false)
    }
  }
  useEffect(() => {
    if (data?.configured && checks === null) preflight()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data?.configured])

  const save = async () => {
    const v = await form.validateFields()
    setSaving(true)
    try {
      await put('/api/cloudflare', v)
      message.success('Доступ к Cloudflare проверен и сохранён')
      form.setFieldValue('token', '')
      reload()
      preflight()
    } catch (e: any) {
      message.error(e.message)
    } finally {
      setSaving(false)
    }
  }

  const fix = (c: Check) =>
    modal.confirm({
      title: c.title,
      content:
        c.fix === 'disable_profile'
          ? 'Профиль будет отключён (не удалён) — его можно включить обратно в панели Cloudflare. Он направляет весь трафик узлов через Cloudflare, что ломает схему цепочки.'
          : c.fix === 'create_profile'
            ? 'Будет создан профиль устройств, через который в Cloudflare идёт только диапазон Mesh (100.96.0.0/12).'
            : 'Будут включены уникальные IP устройств и TCP/UDP-прокси Gateway.',
      okText: fixLabel[c.fix || ''] || 'Исправить',
      cancelText: 'Отмена',
      onOk: async () => {
        try {
          await post('/api/cloudflare/fix', { fix: c.fix, arg: c.fix_arg || '' })
          message.success('Готово')
          preflight()
        } catch (e: any) {
          message.error(e.message)
        }
      },
    })

  return (
    <Row gutter={[16, 16]}>
      <Col xs={24} lg={10}>
        <Card title="Аккаунт Cloudflare Zero Trust">
          <Typography.Paragraph type="secondary">
            Используйте отдельный аккаунт для цепочки. Токен API: права <b>Cloudflare One Connectors Write</b> и <b>Zero Trust Write</b>. Токен хранится в зашифрованном виде.
          </Typography.Paragraph>
          <Form form={form} layout="vertical" requiredMark="optional">
            <Form.Item name="account_id" label="Account ID" rules={[{ required: true, pattern: /^[a-fA-F0-9]{32}$/, message: '32 шестнадцатеричных символа' }]}>
              <Input className="mono" />
            </Form.Item>
            <Form.Item name="team" label="Команда (Team)" rules={[{ required: true, message: 'Например, myteam.cloudflareaccess.com' }]}>
              <Input placeholder="myteam.cloudflareaccess.com" />
            </Form.Item>
            <Form.Item name="token" label="API-токен" extra={data?.configured ? 'Оставьте пустым, чтобы не менять сохранённый токен' : undefined} rules={[{ required: !data?.configured, message: 'Введите токен' }]}>
              <Input.Password autoComplete="off" />
            </Form.Item>
            <Button type="primary" onClick={save} loading={saving}>
              Проверить и сохранить
            </Button>
          </Form>
        </Card>
      </Col>
      <Col xs={24} lg={14}>
        <Space orientation="vertical" size="middle" style={{ width: '100%' }}>
          <Card title="Проверка аккаунта" extra={<Button icon={<ReloadOutlined />} loading={checking} disabled={!data?.configured} onClick={preflight}>Проверить</Button>}>
            {!data?.configured ? (
              <Alert type="info" showIcon title="Сохраните доступ к аккаунту, чтобы проверить его готовность к Mesh." />
            ) : (
              checks === null ? (
                <Skeleton active />
              ) : (
                <Rows>
                  {checks.map((c) => (
                    <RowItem
                      key={c.key}
                      avatar={c.ok ? <CheckCircleFilled style={{ color: '#52c41a', fontSize: 18 }} /> : <CloseCircleFilled style={{ color: '#ff4d4f', fontSize: 18 }} />}
                      title={c.title}
                      description={c.detail}
                      extra={
                        c.fix && !c.ok ? (
                          <Button type="primary" size="small" onClick={() => fix(c)}>
                            {fixLabel[c.fix] || 'Исправить'}
                          </Button>
                        ) : undefined
                      }
                    />
                  ))}
                </Rows>
              )
            )}
          </Card>
          <Card title="Mesh-узлы в аккаунте" extra={<Button icon={<ReloadOutlined />} onClick={reload} loading={loading}>Обновить</Button>}>
            {data?.error && <Alert type="error" showIcon title={data.error} style={{ marginBottom: 12 }} />}
            <Table
              size="small"
              rowKey="id"
              pagination={false}
              dataSource={data?.connectors || []}
              locale={{ emptyText: 'Узлов нет' }}
              columns={[
                { title: 'Имя', dataIndex: 'name' },
                { title: 'Статус', dataIndex: 'status', render: (s: string) => <Tag color={s === 'healthy' ? 'success' : s === 'inactive' ? 'default' : 'warning'}>{s}</Tag> },
                { title: 'Владелец', dataIndex: 'owned', render: (o: boolean) => (o ? <Tag color="blue">панель</Tag> : <Tag>сторонний</Tag>) },
                { title: 'Создан', dataIndex: 'created_at', render: (t: string) => fmtTime(t) },
              ]}
            />
          </Card>
        </Space>
      </Col>
    </Row>
  )
}
