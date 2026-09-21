import { Popover, Tag, Tooltip } from '@arco-design/web-react'

export function CompactTags({ values, title = '全部标签', limit = 1 }: { values: string[]; title?: string; limit?: number }) {
  if (!values.length) return <span className="muted">-</span>
  const visible = values.slice(0, limit)
  return <span className="compact-tags">
    {visible.map(value => <Tooltip key={value} content={<span className="break-text">{value}</span>}><Tag><span className="compact-tag-value">{value}</span></Tag></Tooltip>)}
    {values.length > visible.length && <Popover trigger="click" title={title} content={<div className="tag-popover">{values.map(value => <Tag key={value}>{value}</Tag>)}</div>}>
      <button type="button" className="tag-overflow" aria-label={`查看${title}，共 ${values.length} 项`}>+{values.length - visible.length}</button>
    </Popover>}
  </span>
}
