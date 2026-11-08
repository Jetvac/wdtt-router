import { Card, Table, Tag } from 'antd'
import { fmtTime, usePoll } from '../util'

interface Row {
  id: number
  username: string
  action: string
  detail: string
  remote: string
  at: string
}

const names: Record<string, string> = {
  login: 'Вход',
  'login.failed': 'Неудачный вход',
  'password.change': 'Смена пароля',
  'node.add': 'Добавление сервера',
  'node.update': 'Изменение сервера',
  'node.enroll': 'Подключение к Mesh',
  'node.leave': 'Отключение от Mesh',
  'node.apply': 'Применение настроек',
  'node.remove': 'Удаление сервера',
  'chain.update': 'Изменение цепочки',
  'apply.all': 'Применение конфигурации',
  'wdtt.update': 'Настройки WDTT',
  'xui.update': 'Настройки 3x-ui',
  'xui.reset': 'Сброс доступа 3x-ui',
  'secret.view': 'Просмотр секрета',
  'cloudflare.update': 'Доступ Cloudflare',
  'cloudflare.fix': 'Исправление Cloudflare',
  'panel.allow': 'Доступ к панели',
}

export default function Audit() {
  const { data, loading } = usePoll<Row[]>('/api/audit', 15000)
  return (
    <Card title="Журнал действий">
      <Table
        rowKey="id"
        size="small"
        loading={loading && !data}
        dataSource={data || []}
        scroll={{ x: 800 }}
        pagination={{ pageSize: 25, showSizeChanger: false }}
        columns={[
          { title: 'Время', dataIndex: 'at', width: 170, render: fmtTime },
          { title: 'Пользователь', dataIndex: 'username', width: 130 },
          { title: 'Действие', dataIndex: 'action', render: (a: string) => <Tag color={a === 'login.failed' ? 'error' : a === 'secret.view' ? 'warning' : 'default'}>{names[a] || a}</Tag> },
          { title: 'Подробности', dataIndex: 'detail', ellipsis: true },
          { title: 'Адрес', dataIndex: 'remote', width: 150, render: (r: string) => <span className="mono">{r}</span> },
        ]}
      />
    </Card>
  )
}
