import { Form, Space, Tag } from '@arco-design/web-react'
import { IconRefresh } from '@arco-design/web-react/icon'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { PermissionGate } from '@/features/auth'
import { useAdminForm } from '@/features/admin/hooks'
import { request, resourcePath } from '@/shared/api/client'
import { DataTable } from '@/shared/ui/data-table'
import { LabelTags } from '@/shared/ui/labels'
import { formatTime } from '@/shared/lib/format'
import { ErrorNotice, QueryState, SectionTitle } from '@/shared/ui/page'
import { ResourceForm } from '@/shared/ui/resource-form'
import { IconButton } from '@/shared/ui/icon-button'
import { HelpPopover } from '@/shared/ui/help-popover'
import { workflowQuery } from './api'
import { approvalSourceLabel } from './workflow-step-model'
import { AssetLabelEditor, assetLabelKeyAliases } from './asset-label-editor'
import type { AssetLabels, WorkflowStage } from './types'

const stageLabels: Record<WorkflowStage['status'], string> = { pending: '待审批', approved: '已通过', rejected: '已拒绝', waiting: '等待前序节点', expired: '已过期', cancelled: '已取消', skipped: '已结束' }

export function WorkflowProgress({ requestID, assetID }: { requestID?: string; assetID?: string }) {
  const query = useQuery(workflowQuery(requestID, assetID))
  const v = !requestID && (query.isFetching || query.isError) ? undefined : query.data
  return <section className="workflow-progress"><div className="table-toolbar"><strong>{v?.snapshot?.name ?? '审批流程'}</strong><IconButton label="刷新流程" icon={<IconRefresh />} onClick={() => void query.refetch()} loading={query.isFetching} /></div><ErrorNotice error={query.error} retry={() => void query.refetch()} />
    {v && <><Space wrap><Tag>{requestID ? `流程版本 ${v.snapshot?.revision ?? '历史配置'}` : '提交时将重新校验'}</Tag><HelpPopover title="审批流程版本">{requestID ? '此申请使用提交时保存的流程版本。修改资产关联流程或审批节点只影响新申请；如需使用新流程，请取消后重新申请。' : '按资产当前关联的流程预览审批人，提交时重新校验。节点名称可自定义，实际审批规则以审批人来源为准。'}</HelpPopover><span>截止：{formatTime(v.expires_at)}</span>{v.current_level > 0 && v.status === 'pending_approval' && <Tag color="orange">当前第 {v.current_level} 级</Tag>}</Space>
    <ol className="workflow-stages">{v.stages.map(stage => <li key={stage.level}><Space wrap><strong>{stage.level}. {stage.name || '审批'}</strong><span>{stage.approved} / {stage.required} 人通过</span><span className="muted">{stage.candidates} 位候选人</span></Space><Tag color={stage.status === 'approved' ? 'green' : stage.status === 'pending' ? 'orange' : stage.status === 'rejected' ? 'red' : 'gray'}>{stageLabels[stage.status]}</Tag></li>)}</ol>
    <DataTable data={v.approvals} loading={query.isPending} columns={[
      { title: '节点', width: 180, render: (_, a) => `${a.level}. ${a.step_name || '审批'}` },
      { title: '审批人来源', width: 180, render: (_, a) => approvalSourceLabel(v.snapshot?.steps.find(step => step.level === a.level)) },
      { title: '审批人', dataIndex: 'name', width: 160 },
      { title: '决定', width: 130, render: (_, a) => a.decision === 'approved' ? '已通过' : a.decision === 'rejected' ? '已拒绝' : v.status !== 'pending_approval' || a.level < v.current_level || v.current_level === 0 ? '已结束' : a.level === v.current_level ? '待处理' : '等待前序节点' },
      { title: '意见', width: 240, render: (_, a) => a.comment || '—' }, { title: '处理时间', width: 180, render: (_, a) => formatTime(a.decided_at) },
    ]} /></>}
  </section>
}

function AssetLabelForm({ initial }: { initial: AssetLabels }) {
  const client = useQueryClient()
  const state = useAdminForm(async (value: AssetLabels) => {
    const updated = await request<AssetLabels>(resourcePath('admin/assets', initial.asset_id, '/labels'), { method: 'PATCH', body: { labels: value.labels, revision: initial.revision }, validationMessages: true })
    await client.invalidateQueries({ queryKey: ['asset-labels', initial.asset_id] })
    await client.invalidateQueries({ queryKey: ['workflow-progress'] })
    return updated
  })
  return <ResourceForm form={state.form} initialValues={initial} onSubmit={value => state.mutation.mutate(value)} onChange={state.change} submitting={state.mutation.isPending} dirty={state.dirty} error={state.mutation.error}>
    <Form.Item field="labels" noStyle><AssetLabelEditor /></Form.Item>
  </ResourceForm>
}

export function AssetGovernance({ id }: { id: string }) {
  const query = useQuery({ queryKey: ['asset-labels', id], queryFn: ({ signal }) => request<AssetLabels>(resourcePath('assets', id, '/labels'), { signal }) })
  return <section aria-label="资源标签"><SectionTitle>资源标签 <HelpPopover title="资源标签"><p>标签用于描述资产，例如 env:prod、team:database。审批流程由资产直接关联。</p><p>添加 owner 标签时选择负责人，流程中的“资源负责人”节点由该用户审批。负责人需具备审批权限，申请人不能自批。未设置 owner 时，可使用负责人匹配规则。</p><PermissionGate permission="workflow:manage"><Link to="/admin/workflows?tab=owners">管理资源负责人规则</Link></PermissionGate></HelpPopover></SectionTitle>
    <QueryState loading={query.isPending} error={query.error} retry={() => void query.refetch()}>{query.data && <PermissionGate permission="workflow:manage" fallback={<LabelTags value={query.data.labels} keyAliases={assetLabelKeyAliases} />}><AssetLabelForm key={query.data.revision} initial={query.data} /></PermissionGate>}</QueryState>
  </section>
}
