import { Alert, Button, Popconfirm, Space } from '@arco-design/web-react'
import type { DataColumn } from '@/shared/ui/data-table'
import { IconPlus, IconRefresh } from '@arco-design/web-react/icon'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { usePagination } from '@/shared/hooks/use-pagination'
import { formatDuration, formatTime } from '@/shared/lib/format'
import { DataTable } from '@/shared/ui/data-table'
import { TabToolbar } from '@/shared/ui/route-tabs'
import { CopyableText } from '@/shared/ui/copyable-text'
import { DetailList, ErrorNotice, QueryState } from '@/shared/ui/page'
import { IconButton } from '@/shared/ui/icon-button'
import { StatusTag } from '@/shared/ui/status-tag'
import { requestQuery, requestsQuery } from './api'
import { useCancelRequest } from './hooks'
import { requestApprovalLabel, requestDurationStartLabel, requestRequiresApproval } from './model'
import type { AccessRequest, RequestStatus } from './types'
import { WorkflowProgress } from '@/features/governance'

const requestLabels: Record<RequestStatus, string> = { pending_approval: '待审批', approved: '已批准', rejected: '已拒绝', cancelled: '已取消', approval_expired: '审批超时' }
export function RequestStatusTag({ status }: { status: RequestStatus }) {
  return <StatusTag label={requestLabels[status] ?? status} tone={status === 'approved' ? 'success' : status === 'pending_approval' ? 'warning' : status === 'rejected' ? 'danger' : 'neutral'} />
}

export function RequestList() {
  const pagination = usePagination('requests')
  const query = useQuery(requestsQuery(pagination.page, pagination.pageSize))
  const data = (query.data ?? []).slice(0, pagination.pageSize)
  const columns: DataColumn<AccessRequest>[] = [
    { title: '申请编号', width: 180, render: (_, value) => <CopyableText value={value.id} abbreviated to={`/requests/${value.id}`} /> },
    { title: '资产 ID', width: 170, render: (_, value) => <CopyableText value={value.asset_id} abbreviated /> },
    { title: '目标端口', dataIndex: 'target_port', width: 100 },
    { title: '目标账号', dataIndex: 'target_account', width: 140 },
    { title: '申请原因', dataIndex: 'reason', width: 240, ellipsis: true },
    { title: '状态', width: 150, render: (_, value) => <Space><RequestStatusTag status={value.status} />{value.emergency && <StatusTag label="紧急" tone="danger" />}</Space> },
    { title: '审批方式', width: 160, render: (_, value) => requestApprovalLabel(value.approval_mode) },
    { title: '访问时长', width: 120, render: (_, value) => formatDuration(value.ttl_seconds) },
    { title: '提交时间', width: 180, render: (_, value) => formatTime(value.created_at) },
  ]
  return <>
    <TabToolbar title="我的申请"><IconButton label="刷新申请" icon={<IconRefresh />} loading={query.isFetching} onClick={() => void query.refetch()} /><Link to="/requests/create"><Button type="primary" icon={<IconPlus />}>新建申请</Button></Link></TabToolbar>
    <DataTable columns={columns} data={data} loading={query.isPending} error={query.error} onRetry={() => void query.refetch()} pagination={{ ...pagination, count: data.length, hasNext: (query.data?.length ?? 0) > pagination.pageSize, onChange: pagination.change }} />
  </>
}

interface RequestDetailsProps { id: string }
export function RequestDetails({ id }: RequestDetailsProps) {
  const query = useQuery(requestQuery(id))
  const cancel = useCancelRequest()
  const value = query.data
  return <QueryState loading={query.isPending} error={query.error} retry={() => void query.refetch()}>
    {value && <>
      <div className="detail-actions"><Space><RequestStatusTag status={value.status} />{value.emergency && <StatusTag label="紧急" tone="danger" />}</Space><Space>
        {value.status === 'approved' && <Link to={`/sessions/by-request/${value.id}`}><Button type="primary">查看会话</Button></Link>}
        {['approved', 'pending_approval'].includes(value.status) && <Popconfirm title="取消这条申请？关联会话将被回收。" onOk={() => cancel.mutateAsync(value.id).then(() => undefined)}><Button status="danger" loading={cancel.isPending}>取消申请</Button></Popconfirm>}
      </Space></div>
      <ErrorNotice error={cancel.error} />
      {value.status === 'pending_approval' && <Alert type={value.emergency ? 'warning' : 'info'} content={value.emergency ? '紧急申请已在审批待办中优先展示，等待指定审批人处理。' : '申请正在等待指定审批人处理。'} />}
      <DetailList items={[
        { label: '申请 ID', value: <CopyableText value={value.id} /> }, { label: '资产 ID', value: <CopyableText value={value.asset_id} /> },
        { label: '目标端口', value: value.target_port }, { label: '目标账号', value: value.target_account },
        { label: '来源 IP', value: value.source_ip },
        { label: '审批方式', value: requestApprovalLabel(value.approval_mode) },
        { label: '会话有效期', value: `${formatDuration(value.ttl_seconds)}（${requestDurationStartLabel(value.approval_mode)}开始计时）` },
        ...(value.ticket_no?.trim() ? [{ label: '关联工单', value: value.ticket_no }] : []),
        { label: '申请原因', value: value.reason }, { label: '提交时间', value: formatTime(value.created_at) },
      ]} />
      {requestRequiresApproval(value.approval_mode) && <WorkflowProgress requestID={value.id} />}
    </>}
  </QueryState>
}
