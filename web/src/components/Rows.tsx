import type { ReactNode } from 'react'
import { Flex, Typography, theme } from 'antd'

/** A list of rows with dividers, in the style of the antd List. */
export function Rows({ children, bordered }: { children: ReactNode; bordered?: boolean }) {
  const { token } = theme.useToken()
  return (
    <div
      className="rows"
      style={{
        border: bordered ? `1px solid ${token.colorBorderSecondary}` : undefined,
        borderRadius: bordered ? token.borderRadiusLG : undefined,
        ['--row-border' as string]: token.colorSplit,
      }}
    >
      {children}
    </div>
  )
}

export function RowItem({ avatar, title, description, extra, compact }: { avatar?: ReactNode; title?: ReactNode; description?: ReactNode; extra?: ReactNode; compact?: boolean }) {
  return (
    <Flex className={compact ? 'row-item compact' : 'row-item'} align="center" justify="space-between" gap={16}>
      <Flex gap={12} align="flex-start" style={{ minWidth: 0, flex: 1 }}>
        {avatar && <div style={{ paddingTop: 2 }}>{avatar}</div>}
        <div style={{ minWidth: 0 }}>
          {title && <div className="row-title">{title}</div>}
          {description && <Typography.Text type="secondary">{description}</Typography.Text>}
        </div>
      </Flex>
      {extra && <div style={{ flexShrink: 0 }}>{extra}</div>}
    </Flex>
  )
}
