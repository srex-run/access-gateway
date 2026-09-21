import { Alert, Button, Form, Input, Message, Modal, Space } from '@arco-design/web-react'
import type { DataColumn } from '@/shared/ui/data-table'
import { IconCheck, IconClose, IconRefresh } from '@arco-design/web-react/icon'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { requestQuery, requestKeys } from '@/features/requests'
import { workflowQuery, WorkflowProgress } from '@/features/governance'
import { request, resourcePath } from '@/shared/api/client'
import { usePagination } from '@/shared/hooks/use-pagination'
import { formatDuration, formatTime } from '@/shared/lib/format'
import { DataTable } from '@/shared/ui/data-table'
import { CopyableText } from '@/shared/ui/copyable-text'
import { TabToolbar } from '@/shared/ui/route-tabs'
import { DetailList, ErrorNotice, QueryState } from '@/shared/ui/page'
import { IconButton } from '@/shared/ui/icon-button'
import { StatusTag } from '@/shared/ui/status-tag'

interface Approval { id: string; request_id: string; approver_id: string; approval_level: number; step_name: string; required_approvals: number; created_at: string; emergency: boolean }
interface Decision { approval: Approval; action: 'approve' | 'reject' }
const approvalKeys = ['approvals'] as const

function useApprovals() {
  const pagination = usePagination('pending')
  const [decision, setDecision] = useState<Decision | null>(null)
  const query = useQuery({ queryKey: [...approvalKeys, pagination.page, pagination.pageSize], queryFn: ({ signal }) => request<Approval[]>('/approvals/pending', { signal, query: { limit: pagination.pageSize + 1, offset: pagination.offset } }) })
  return { pagination, decision, setDecision, query, data: (query.data ?? []).slice(0, pagination.pageSize) }
}

function useDecision(decision: Decision, onClose: () => void) {
  const client = useQueryClient()
  const [form] = Form.useForm<{ comment: string }>()
  const detail = useQuery(requestQuery(decision.approval.request_id))
  const workflow = useQuery(workflowQuery(decision.approval.request_id))
  const mutation = useMutation({
    mutationFn: ({ comment }: { comment: string }) => request(resourcePath('approvals', decision.approval.id, `/${decision.action}`), { method: 'POST', body: { comment: comment?.trim() || null } }),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: ['notifications'] })
      await client.invalidateQueries({ queryKey: approvalKeys })
      await client.invalidateQueries({ queryKey: requestKeys.all })
      await client.invalidateQueries({ queryKey: ['sessions'] })
      await client.invalidateQueries({ queryKey: ['workflow-progress', decision.approval.request_id] })
      Message.success(decision.action === 'approve' ? '已记录通过意见' : '已拒绝申请')
      onClose()
    },
    onError: async () => {
      await client.invalidateQueries({ queryKey: approvalKeys })
      await client.invalidateQueries({ queryKey: ['workflow-progress', decision.approval.request_id] })
    },
  })
  return { form, detail, workflow, mutation }
}

function DecisionDialog({ decision, onClose }: { decision: Decision; onClose: () => void }) {
  const { form, detail, workflow, mutation } = useDecision(decision, onClose)
  const value = detail.data
  const canDecide = !!value && !detail.error && !workflow.error && value.status === 'pending_approval' && workflow.data?.can_decide && workflow.data.approval_id === decision.approval.id
  return <Modal visible title={decision.action === 'approve' ? '批准访问申请' : '拒绝访问申请'} className="decision-modal" onCancel={onClose} maskClosable={!mutation.isPending} closable={!mutation.isPending} escToExit={!mutation.isPending} onOk={() => { if (canDecide) form.submit() }} okText={decision.action === 'approve' ? '确认批准' : '确认拒绝'} confirmLoading={mutation.isPending} okButtonProps={{ disabled: !canDecide, status: decision.action === 'reject' ? 'danger' : undefined }} cancelButtonProps={{ disabled: mutation.isPending }}>
    <QueryState loading={detail.isPending} error={detail.error} retry={() => void detail.refetch()}>{value && <>
      {value.emergency && <Alert type="warning" content="紧急访问，请优先处理。申请原因中包含故障情况和影响范围。" />}
      <DetailList items={[
      { label: '申请人', value: value.applicant_id }, { label: '资产', value: value.asset_id }, { label: '端口 / 账号', value: `${value.target_port} / ${value.target_account ?? '-'}` },
      { label: '来源 IP', value: value.source_ip }, { label: '会话有效期', value: `审批通过后 ${formatDuration(value.ttl_seconds)}` }, { label: '申请原因', value: value.reason },
    ]} /></>}</QueryState>
    <WorkflowProgress requestID={decision.approval.request_id} />
    {workflow.data?.decision_reason && <Alert type="warning" content={workflow.data.decision_reason} />}
    <Form form={form} layout="vertical" onSubmit={values => { if (canDecide) mutation.mutate(values) }} disabled={mutation.isPending || !canDecide}><Form.Item label="审批意见" field="comment" rules={[{ required: decision.action === 'reject', match: /\S/, message: '请填写拒绝原因' }]}><Input.TextArea maxLength={4000} autoSize={{ minRows: 3, maxRows: 6 }} /></Form.Item></Form>
    <ErrorNotice error={mutation.error} />
  </Modal>
}

export function ApprovalList() {
  const state = useApprovals()
  const columns: DataColumn<Approval>[] = [
    { title: '优先级', width: 90, render: (_, value) => value.emergency ? <StatusTag label="紧急" tone="danger" /> : '普通' },
    { title: '申请编号', width: 180, render: (_, value) => <CopyableText value={value.request_id} abbreviated to={`/requests/${value.request_id}`} /> },
    { title: '审批级别', width: 140, render: (_, value) => `第 ${value.approval_level} 级` },
    { title: '当前节点', width: 180, render: (_, value) => value.step_name || '审批' },
    { title: '通过条件', width: 130, render: (_, value) => `需 ${value.required_approvals || 1} 人通过` },
    { title: '待办创建时间', width: 200, render: (_, value) => formatTime(value.created_at) },
    { title: '操作', width: 180, fixed: 'right', render: (_, value) => <Space><Button type="text" icon={<IconCheck />} onClick={() => state.setDecision({ approval: value, action: 'approve' })}>批准</Button><Button type="text" status="danger" icon={<IconClose />} onClick={() => state.setDecision({ approval: value, action: 'reject' })}>拒绝</Button></Space> },
  ]
  return <><TabToolbar title="待我审批"><IconButton label="刷新审批" icon={<IconRefresh />} loading={state.query.isFetching} onClick={() => void state.query.refetch()} /></TabToolbar>
    <DataTable columns={columns} data={state.data} loading={state.query.isPending} error={state.query.error} onRetry={() => void state.query.refetch()} empty="暂无待处理的审批" pagination={{ ...state.pagination, count: state.data.length, hasNext: (state.query.data?.length ?? 0) > state.pagination.pageSize, onChange: state.pagination.change }} />
    {state.decision && <DecisionDialog decision={state.decision} onClose={() => state.setDecision(null)} />}
  </>
}
