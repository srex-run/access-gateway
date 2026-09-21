import { Button, Form, Input, Popover, Select, Tooltip } from '@arco-design/web-react'
import { IconSearch } from '@arco-design/web-react/icon'
import { useState } from 'react'
import type { ResourceStatus } from '@/features/catalog'
import { ResourceForm } from '@/shared/ui/resource-form'
import { IconButton } from '@/shared/ui/icon-button'
import { updateStatus } from './api'
import { statusOptions, uuidRules } from './fields'
import { useAdminForm } from './hooks'

export function ResourceStatusForm({ type, id, backTo }: { type: 'assets'; id: string; backTo: string }) {
  const state = useAdminForm((value: { status: ResourceStatus }) => updateStatus(type, id, value.status))
  return <ResourceForm form={state.form} onSubmit={value => state.mutation.mutate(value)} onChange={state.change} dirty={state.dirty} submitting={state.mutation.isPending} saved={state.mutation.isSuccess} error={state.mutation.error} backTo={backTo}>
    <Form.Item label="资源状态" field="status" rules={[{ required: true }]}><Select options={statusOptions} /></Form.Item>
    <p className="muted">停用或维护会触发关联会话的访问权限回收。</p>
  </ResourceForm>
}

interface ResourceLookupProps { label: string; initial?: string; onLookup: (id: string) => void; actionLabel?: string; layout?: 'inline' | 'vertical' }
export function ResourceLookup({ label, initial, onLookup, actionLabel = '查询', layout = 'inline' }: ResourceLookupProps) {
  return <Form<{ id: string }> layout={layout} className="resource-lookup" initialValues={{ id: initial }} onSubmit={value => onLookup(value.id.trim())}>
    <Form.Item label={label} field="id" rules={uuidRules}><Input aria-label={label} placeholder={label} /></Form.Item><Form.Item>{layout === 'inline' ? <IconButton label={actionLabel} htmlType="submit" icon={<IconSearch />} /> : <Button htmlType="submit" icon={<IconSearch />}>{actionLabel}</Button>}</Form.Item>
  </Form>
}

export function ResourceLookupAction(props: ResourceLookupProps) {
  const [visible, setVisible] = useState(false)
  return <Popover trigger="click" position="bottom" popupVisible={visible} onVisibleChange={setVisible} content={visible && <ResourceLookup {...props} layout="vertical" onLookup={id => { setVisible(false); props.onLookup(id) }} />}>
    <Tooltip content={`按 ${props.label} 管理`}><Button aria-label={`按 ${props.label} 管理`} icon={<IconSearch />} /></Tooltip>
  </Popover>
}
