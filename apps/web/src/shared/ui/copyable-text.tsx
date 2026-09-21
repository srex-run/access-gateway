import { Message, Tooltip } from '@arco-design/web-react'
import { IconCopy } from '@arco-design/web-react/icon'
import { Link } from 'react-router-dom'
import { shortID } from '@/shared/lib/format'
import { IconButton } from './icon-button'

interface CopyableTextProps { value?: string | null; abbreviated?: boolean; to?: string }
export function CopyableText({ value, abbreviated = false, to }: CopyableTextProps) {
  if (!value) return <span className="muted">-</span>
  const copy = async () => {
    try { await navigator.clipboard.writeText(value); Message.success('已复制') }
    catch { Message.error('复制失败') }
  }
  const text = <code>{abbreviated ? shortID(value) : value}</code>
  return <span className="copyable"><Tooltip content={value}>{to ? <Link className="table-link" to={to}>{text}</Link> : text}</Tooltip><IconButton label="复制" icon={<IconCopy />} onClick={() => void copy()} /></span>
}
