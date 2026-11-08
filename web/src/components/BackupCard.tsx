import { useState } from 'react'
import { App, Button, Card, Form, Input, Typography } from 'antd'
import { DownloadOutlined } from '@ant-design/icons'
import { download } from '../api'

/** Encrypted backup of the panel state, downloaded to the browser. */
export default function BackupCard() {
  const [form] = Form.useForm()
  const [busy, setBusy] = useState(false)
  const { message } = App.useApp()
  const save = async () => {
    const v = await form.validateFields()
    setBusy(true)
    try {
      await download('/api/backup', { passphrase: v.passphrase }, 'wdtt-router-backup.wbk')
      message.success('Копия скачана. Храните её отдельно от пароля.')
      form.resetFields()
    } catch (e: any) {
      message.error(e.message)
    } finally {
      setBusy(false)
    }
  }
  return (
    <Card title="Резервная копия">
      <Typography.Paragraph type="secondary">
        Всё состояние панели в одном файле: серверы, цепочка, ключи и пароли, ключи доступа и устройства WDTT. Файл зашифрован паролем, который вы зададите, — без него копию не открыть, и восстановить пароль нельзя.
      </Typography.Paragraph>
      <Form form={form} layout="vertical" style={{ maxWidth: 400 }}>
        <Form.Item name="passphrase" label="Пароль копии" rules={[{ required: true, min: 12, message: 'Не короче 12 символов' }]}>
          <Input.Password autoComplete="new-password" />
        </Form.Item>
        <Form.Item
          name="repeat"
          label="Повторите пароль"
          dependencies={['passphrase']}
          rules={[{ required: true, message: 'Повторите пароль' }, ({ getFieldValue }) => ({ validator: (_, v) => (v === getFieldValue('passphrase') ? Promise.resolve() : Promise.reject(new Error('Пароли не совпадают'))) })]}
        >
          <Input.Password autoComplete="new-password" />
        </Form.Item>
        <Button type="primary" icon={<DownloadOutlined />} loading={busy} onClick={save}>
          Скачать копию
        </Button>
      </Form>
      <Typography.Paragraph type="secondary" style={{ marginTop: 16, marginBottom: 0 }}>
        Восстановление — на этом или новом сервере после установки панели: <Typography.Text code>sudo wdtt-router restore файл.wbk</Typography.Text>, затем «Применить ко всем серверам». На новом сервере добавьте <Typography.Text code>--public-host АДРЕС</Typography.Text>. После замены SSH-ключа панели скачайте новую копию: в старых — прежний ключ, который на серверах уже удалён.
      </Typography.Paragraph>
    </Card>
  )
}

/** Logs and state of every server in one ZIP, secrets masked. */
export function DiagnosticsCard() {
  const [busy, setBusy] = useState(false)
  const { message } = App.useApp()
  const run = async () => {
    setBusy(true)
    try {
      await download('/api/diagnostics', {}, 'wdtt-router-diagnostics.zip')
    } catch (e: any) {
      message.error(e.message)
    } finally {
      setBusy(false)
    }
  }
  return (
    <Card title="Диагностика">
      <Typography.Paragraph type="secondary">
        Журналы служб за последний час, состояние служб, правила firewall, маршруты и Mesh со всех серверов — в одном архиве. Пароли, ключи и токены в нём скрыты, файлы настроек не включаются.
      </Typography.Paragraph>
      <Button icon={<DownloadOutlined />} loading={busy} onClick={run}>
        Скачать диагностику
      </Button>
    </Card>
  )
}
