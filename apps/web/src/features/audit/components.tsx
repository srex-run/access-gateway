import { Button, Form, Input, Popover, Select } from '@arco-design/web-react'
import { IconFilter, IconRefresh, IconSearch } from '@arco-design/web-react/icon'
import { useState } from 'react'
import { Navigate, useSearchParams } from 'react-router-dom'
import { useIdentity } from '@/features/auth'
import { SessionList } from '@/features/sessions'
import { formatTime } from '@/shared/lib/format'
import { CopyableText } from '@/shared/ui/copyable-text'
import { DataTable, TableDetail, TableText } from '@/shared/ui/data-table'
import type { DataColumn } from '@/shared/ui/data-table'
import { IconButton } from '@/shared/ui/icon-button'
import { HelpPopover } from '@/shared/ui/help-popover'
import { StatusTag } from '@/shared/ui/status-tag'
import { RouteTabs, TabToolbar } from '@/shared/ui/route-tabs'
import { useAudit } from './hooks'
import type { AuditFilters } from './hooks'
import type { AuditEvent } from './types'
import { auditActions, auditCategories } from './types'

function ResultTag({ value }: { value: string | undefined }) {
  const labels: Record<string, string> = { approved: '已通过', pending: '待审批', cancelled: '已取消', queued: '已排队', success: '成功', failed: '失败', unknown: '结果未知', sent: '已发送', partial: '部分完成', failure: '失败', rejected: '已拒绝', skipped: '未执行' }
  return <StatusTag label={labels[value ?? ''] ?? value ?? '-'} tone={['success', 'approved'].includes(value ?? '') || /^http_[23]/.test(value ?? '') ? 'success' : ['failure', 'failed', 'denied', 'error', 'rejected'].includes(value ?? '') || /^http_[45]/.test(value ?? '') ? 'danger' : value === 'unknown' ? 'warning' : 'neutral'} />
}

interface AuditFiltersProps { value: AuditFilters; onSubmit: (value: AuditFilters) => void; refresh: () => void; loading: boolean }
function AuditFilterForm({ value, onSubmit, refresh, loading }: AuditFiltersProps) {
  const [open, setOpen] = useState(false)
  const count = Object.values(value).filter(item => item.trim()).length
  const apply = (filters: AuditFilters) => { onSubmit(filters); setOpen(false) }
  return <TabToolbar title="操作日志"><div className="table-actions">
    <Popover trigger="click" position="bottom" title="审计筛选" popupVisible={open} onVisibleChange={setOpen} content={open && <Form<AuditFilters> className="audit-filter-panel" layout="vertical" key={JSON.stringify(value)} initialValues={{ ...value, result: value.result || undefined, category: value.category || undefined, action: value.action || undefined }} onSubmit={apply}>
      <Form.Item label="操作人 ID" field="actor_id"><Input aria-label="操作人 ID" placeholder="全部用户" allowClear /></Form.Item>
      <Form.Item label="业务分类" field="category"><Select aria-label="业务分类" placeholder="全部分类" allowClear options={auditCategories} /></Form.Item>
      <Form.Item label="操作类型" field="action"><Select aria-label="操作类型" placeholder="全部操作" allowClear options={auditActions} /></Form.Item>
      <Form.Item label="事件编码" field="event_type"><Input aria-label="事件编码" placeholder="事件编码" allowClear /></Form.Item>
      <Form.Item label="会话 ID" field="session_id"><Input aria-label="会话 ID" placeholder="会话 ID" allowClear /></Form.Item>
      <Form.Item label="执行结果" field="result"><Select aria-label="执行结果" placeholder="全部结果" allowClear allowCreate options={['success', 'failure', 'failed', 'denied', 'rejected', 'unknown', 'sent', 'partial', 'skipped', 'queued']} /></Form.Item>
      <div className="audit-filter-panel-actions"><Button onClick={() => apply({ actor_id: '', event_type: '', session_id: '', result: '', category: '', action: '' })}>重置</Button><Button type="primary" icon={<IconSearch />} htmlType="submit">查询</Button></div>
    </Form>}>
      <Button type={count ? 'primary' : 'secondary'} icon={<IconFilter />} aria-label={count ? `筛选审计，已应用 ${count} 项条件` : '筛选审计'} aria-expanded={open}>筛选{count > 0 && ` (${count})`}</Button>
    </Popover>
    <HelpPopover title="操作日志">记录用户发起的新增、修改、删除及审批等状态变更，按业务分类查询。登录、只读查询和系统运行事件不列入此表；资产命令在“会话记录”的会话详情中查看。</HelpPopover><IconButton label="刷新审计" icon={<IconRefresh />} loading={loading} onClick={refresh} />
  </div></TabToolbar>
}

function AuditList() {
  const state = useAudit()
  const columns: DataColumn<AuditEvent>[] = [
    { title: '操作人', width: 160, fixed: 'left', render: (_, value) => <CopyableText value={value.actor_id} abbreviated /> },
    { title: '用户名', width: 180, render: (_, value) => <TableText>{value.actor_username || value.actor_name || '-'}</TableText> },
    { title: '时间', width: 170, render: (_, value) => formatTime(value.created_at) },
    { title: '业务分类', width: 110, render: (_, value) => auditCategories.find(item => item.value === value.category)?.label || '-' },
    { title: '操作', width: 170, render: (_, value) => <TableDetail title="操作详情" summary={value.label || value.event_type}><p>{auditActions.find(item => item.value === value.action)?.label || '-'}</p><code>{value.event_type}</code><p>记录编号：<CopyableText value={value.id} /></p></TableDetail> },
    { title: '关联对象', width: 180, render: (_, value) => <CopyableText value={value.session_id || value.request_id || value.asset_id || value.subject_user_id} abbreviated to={value.session_id ? `/sessions/${value.session_id}` : undefined} /> },
    { title: '来源 IP', dataIndex: 'source_ip', width: 140 },
    { title: '说明', dataIndex: 'reason', width: 220 },
    { title: '结果', width: 100, fixed: 'right', render: (_, value) => <ResultTag value={value.result} /> },
  ]
  return <><AuditFilterForm value={state.filter} onSubmit={state.apply} refresh={state.refresh} loading={state.query.isFetching} /><DataTable columns={columns} data={state.data} loading={state.query.isPending} error={state.query.error} onRetry={state.refresh} pagination={{ ...state.pagination, count: state.data.length, hasNext: (state.query.data?.length ?? 0) > state.pagination.pageSize, onChange: state.pagination.change }} /></>
}

export function AuditWorkspace() {
  const identity = useIdentity()
  const [params] = useSearchParams()
  const canReadAll = identity.data?.permissions.includes('audit:read') ?? false
  if (['operations', 'unmatched'].includes(params.get('view') ?? '')) {
    const next = new URLSearchParams(params)
    next.set('view', 'sessions')
    const sessionID = next.get('session_id')
    if (sessionID && !next.has('search')) next.set('search', sessionID)
    next.delete('session_id')
    return <Navigate replace to={`/audit?${next}`} />
  }
  return <div className="audit-workspace"><RouteTabs param="view" items={[
    ...(canReadAll ? [{ key: 'access', title: '操作日志', content: <AuditList /> }] : []),
    { key: 'sessions', title: '会话记录', content: <SessionList /> },
  ]} /></div>
}
