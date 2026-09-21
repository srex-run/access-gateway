import { Button, Empty, Popover, Select, Space, Table, Tooltip } from '@arco-design/web-react'
import { IconLeft, IconRight } from '@arco-design/web-react/icon'
import type { TableColumnProps, TableProps } from '@arco-design/web-react'
import type { ReactNode } from 'react'
import { ErrorNotice } from './page'
import { PAGE_SIZE_OPTIONS } from '@/shared/lib/pagination'

export interface OffsetPaginationProps {
  page: number
  pageSize: number
  hasNext: boolean
  count: number
  total?: number
  loading?: boolean
  onChange: (page: number, size: number) => void
}

export function OffsetPagination({ page, pageSize, hasNext, count, total, loading, onChange }: OffsetPaginationProps) {
  return <div className="pagination">
    <span className="muted">{total === undefined ? `第 ${page} 页，本页 ${count} 条` : `共 ${total} 条，第 ${page} 页`}</span>
    <Space>
      <Select aria-label="每页条数" className="page-size" value={pageSize} disabled={loading} onChange={(value: number) => onChange(1, value)} options={PAGE_SIZE_OPTIONS.map(value => ({ value, label: `${value} 条 / 页` }))} />
      <Button aria-label="上一页" icon={<IconLeft />} disabled={loading || page <= 1} onClick={() => onChange(page - 1, pageSize)} />
      <Button aria-label="下一页" icon={<IconRight />} disabled={loading || !hasNext} onClick={() => onChange(page + 1, pageSize)} />
    </Space>
  </div>
}

export type DataColumn<T> = TableColumnProps<T> & { width: number; children?: never }

interface DataTableProps<T extends object> extends Pick<TableProps<T>, 'expandedRowRender' | 'expandProps' | 'defaultExpandedRowKeys'> {
  columns: DataColumn<T>[]
  data?: T[]
  rowKey?: string | ((row: T) => string)
  loading?: boolean
  error?: unknown
  onRetry?: () => void
  empty?: ReactNode
  pagination?: OffsetPaginationProps
}

export function DataTable<T extends object>({ columns, data = [], rowKey = 'id', loading, error, onRetry, empty = '暂无记录', pagination, expandedRowRender, expandProps, defaultExpandedRowKeys }: DataTableProps<T>) {
  const normalized = columns.map(column => ({ ...column, ellipsis: true, render: (value: unknown, row: T, index: number) => {
    const content = column.render ? column.render(value, row, index) : value
    return typeof content === 'string' || typeof content === 'number' ? <TableText>{String(content)}</TableText> : content as ReactNode
  } }))
  return <div className="data-table">
    <ErrorNotice error={error} retry={onRetry} />
    <Table<T> rowKey={rowKey} columns={normalized} data={data} loading={loading} pagination={false} size="small" border={false} tableLayoutFixed expandedRowRender={expandedRowRender} expandProps={expandProps} defaultExpandedRowKeys={defaultExpandedRowKeys} scroll={{ x: columns.reduce((sum, column) => sum + column.width, 0) + (expandedRowRender ? expandProps?.width ?? 40 : 0) }} noDataElement={<Empty description={error ? '数据加载失败' : empty} />} />
    {pagination && <OffsetPagination {...pagination} loading={loading || !!error} />}
  </div>
}

export function TableText({ children }: { children?: string | null }) {
  return children ? <Tooltip content={<span className="break-text">{children}</span>}><span className="table-ellipsis">{children}</span></Tooltip> : <span className="muted">-</span>
}

export function TableDetail({ title, summary, children }: { title: string; summary: string; children: ReactNode }) {
  return <Popover trigger="click" className="table-detail-popover" style={{ maxWidth: 'calc(100vw - 32px)' }} title={title} content={<div className="table-detail-content">{children}</div>}>
    <button type="button" className="table-detail-trigger" aria-label={`查看${title}`}><span className="table-ellipsis">{summary}</span></button>
  </Popover>
}
