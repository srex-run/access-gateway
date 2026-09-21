import { Tag } from '@arco-design/web-react'

interface StatusTagProps { label: string; tone?: 'neutral' | 'success' | 'warning' | 'danger' | 'info' }
const colors = { neutral: 'gray', success: 'green', warning: 'orange', danger: 'red', info: 'blue' }
export function StatusTag({ label, tone = 'neutral' }: StatusTagProps) {
  return <Tag color={colors[tone]}>{label}</Tag>
}
