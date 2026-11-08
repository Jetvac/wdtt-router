import { useEffect } from 'react'
import { Card, Table, Typography } from 'antd'
import { JobStatusTag, useJobs } from '../components/Jobs'
import type { Job } from '../types'
import { fmtTime, usePoll } from '../util'

export default function JobsPage() {
  const { data, loading, reload } = usePoll<Job[]>('/api/jobs?limit=200', 4000)
  const { open, version } = useJobs()
  useEffect(() => {
    reload()
  }, [version, reload])
  return (
    <Card title="Задачи">
      <Typography.Paragraph type="secondary">
        Все изменения на серверах выполняются по очереди, по одной задаче. Повторные одинаковые запросы объединяются, поэтому многократное нажатие кнопок безопасно.
      </Typography.Paragraph>
      <Table
        rowKey="id"
        loading={loading && !data}
        dataSource={data || []}
        scroll={{ x: 800 }}
        onRow={(j) => ({ onClick: () => open(j.id), style: { cursor: 'pointer' } })}
        pagination={{ pageSize: 20, showSizeChanger: false }}
        columns={[
          { title: '№', dataIndex: 'id', width: 70 },
          { title: 'Задача', dataIndex: 'title' },
          { title: 'Статус', width: 140, render: (_, j) => <JobStatusTag status={j.status} /> },
          { title: 'Ошибка', dataIndex: 'error', ellipsis: true, render: (e: string) => <Typography.Text type="danger">{e}</Typography.Text> },
          { title: 'Пользователь', dataIndex: 'created_by', width: 120 },
          { title: 'Создана', dataIndex: 'created_at', width: 170, render: fmtTime },
        ]}
      />
    </Card>
  )
}
