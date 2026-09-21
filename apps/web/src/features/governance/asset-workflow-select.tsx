import { Alert, Button, Modal, Select } from '@arco-design/web-react'
import { IconEye } from '@arco-design/web-react/icon'
import { queryOptions, useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { PermissionGate } from '@/features/auth'
import { request } from '@/shared/api/client'
import { TableText } from '@/shared/ui/data-table'
import { HelpPopover } from '@/shared/ui/help-popover'
import { IconButton } from '@/shared/ui/icon-button'
import { ErrorNotice } from '@/shared/ui/page'
import { WorkflowDiagram } from './workflow-diagram'
import type { Workflow } from './types'
import './asset-workflow-select.css'

const assetWorkflowsQuery = queryOptions({ queryKey: ['governance', 'asset-workflows'], queryFn: ({ signal }) => request<Workflow[]>('/admin/asset-workflows', { signal }) })

export function AssetWorkflowSelect({ value = '', onChange, id, disabled, assetID, readOnly }: { value?: string; onChange?: (value: string) => void; id?: string; disabled?: boolean; assetID?: string; readOnly?: boolean }) {
  const [previewVisible, setPreviewVisible] = useState(false)
  const query = useQuery(assetWorkflowsQuery)
  const selected = query.data?.find(flow => flow.id === value)
  const options = (query.data ?? []).map(flow => ({ value: flow.id, label: `${flow.name}${flow.enabled ? '' : '（已停用）'}`, disabled: !flow.enabled }))
  if (value && !selected) options.push({ value, label: '当前关联流程（暂不可用）', disabled: true })
  return <div className={readOnly ? 'asset-workflow-summary' : undefined}>
    <div className="asset-workflow-control">
      {readOnly ? <TableText>{value ? selected?.name ?? (query.isPending ? '正在读取关联流程' : '关联流程不可用') : '待配置审批流程'}</TableText> : <Select id={id} aria-label="审批流程" placeholder="选择审批流程" value={value || undefined} onChange={selectedID => onChange?.(selectedID ?? '')} allowClear showSearch loading={query.isPending} disabled={disabled || query.isPending || !!query.error}
        options={options} />}
      {readOnly && selected && <IconButton label="查看审批流程" icon={<IconEye />} onClick={() => setPreviewVisible(true)} />}
      <HelpPopover title="审批流程">
        <p>访问申请按资产关联的审批流程流转，审批人由流程节点决定。尚未关联流程时可保存资产配置，普通访问申请需配置流程后才能提交。</p>
        {selected?.steps.some(step => step.kind === 'owners') && <p>此流程需要资源负责人。在{assetID ? <Link to={`/admin/assets/${assetID}`}>资源标签</Link> : '资产保存后的资源标签'}中添加 owner 并选择负责人；也可在“审批流程 → 资源负责人”设置匹配规则。</p>}
      </HelpPopover>
    </div>
    <ErrorNotice error={query.error} retry={() => void query.refetch()} />
    {value && query.data && (!selected || !selected.enabled) && <Alert type="warning" content="当前关联的流程不可用，新申请将无法提交，请选择启用的审批流程。" />}
    {!readOnly && <div className="table-actions">
      {selected && <Button type="text" size="small" htmlType="button" onClick={() => setPreviewVisible(true)}>查看审批流程</Button>}
      <PermissionGate permission="workflow:manage"><Link to="/admin/workflows">管理审批流程</Link></PermissionGate>
    </div>}
    {selected && <Modal title="审批流程预览" visible={previewVisible} onCancel={() => setPreviewVisible(false)} footer={null} unmountOnExit style={{ width: 720, maxWidth: 'calc(100vw - 32px)' }}>
      <div style={{ maxHeight: '70vh', overflowY: 'auto' }}><WorkflowDiagram steps={selected.steps} title={selected.name} /></div>
    </Modal>}
  </div>
}
