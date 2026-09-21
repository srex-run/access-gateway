import { Button, Form, Input, InputNumber, Select, Switch, Tooltip } from '@arco-design/web-react'
import { IconArrowDown, IconArrowUp, IconDelete, IconPlus } from '@arco-design/web-react/icon'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useParams } from 'react-router-dom'
import { request } from '@/shared/api/client'
import { LabelEditor } from '@/shared/ui/labels'
import { EmptyResult, QueryState } from '@/shared/ui/page'
import { ResourceForm } from '@/shared/ui/resource-form'
import { HelpPopover } from '@/shared/ui/help-popover'
import { useAdminForm } from '@/features/admin/hooks'
import { bindingsQuery, ownersQuery, rolesQuery, workflowsQuery } from './api'
import { LabelBindingPreview } from './preview'
import { PermissionTree } from './permission-tree'
import { WorkflowDiagram } from './workflow-diagram'
import { changeApprovalSource, isPlatformAdminStep, type ApprovalSource } from './workflow-step-model'
import type { PermissionItem } from './permission-tree-model'
import type { LabelBindingDraft, Ownership, RoleBinding, RoleDefinition, Step, Workflow } from './types'

function useSave<T extends object>(path: string) {
  const client = useQueryClient()
  return useAdminForm(async (body: T) => {
    const result = await request<T>(path, { method: 'POST', body, validationMessages: true })
    await client.invalidateQueries({ queryKey: ['governance'] })
    await client.invalidateQueries({ queryKey: ['identity'] })
    await client.invalidateQueries({ queryKey: ['managed-user'] })
    await client.invalidateQueries({ queryKey: ['workflow-progress'] })
    await client.invalidateQueries({ queryKey: ['approvals'] })
    await client.invalidateQueries({ queryKey: ['label-preview'] })
    return result
  })
}

function RoleEditor({ editing }: { editing?: RoleDefinition }) {
  const state = useSave<RoleDefinition>('/admin/roles')
  const isAdmin = editing?.built_in && editing.name === 'admin'
  const catalog = useQuery({ queryKey: ['governance', 'permissions'], queryFn: ({ signal }) => request<PermissionItem[]>('/admin/permissions', { signal }) })
  return <QueryState loading={catalog.isPending} error={catalog.error} retry={() => void catalog.refetch()}><ResourceForm form={state.form} initialValues={editing ?? { revision: 0, enabled: true, labels: {}, permissions: [] }} onSubmit={value => state.mutation.mutate({ ...value, revision: editing?.revision ?? 0, built_in: editing?.built_in ?? false })} onChange={state.change} submitting={state.mutation.isPending} dirty={state.dirty} saved={state.mutation.isSuccess} error={state.mutation.error} backTo="/admin/roles">
    <Form.Item label="角色名称" field="name" rules={[{ required: true, match: /^[a-z][a-z0-9_-]{1,62}$/, message: '请输入 2–63 位小写字母、数字、下划线或连字符' }]}><Input disabled={!!editing} /></Form.Item>
    <Form.Item label="描述" field="description"><Input.TextArea maxLength={512} /></Form.Item>
    <Form.Item label={<span>权限 <HelpPopover title="角色权限"><p>权限树与左侧菜单保持两级结构，勾选菜单即可选择对应权限，勾选分组可批量选择。半选表示已有角色仅获授其中部分权限。</p><p>同一权限可能用于多个菜单，相关节点会同步勾选；最终权限为默认用户权限与所有已授予角色权限的合集。保存后按新的权限生效。</p><p>自定义角色也可勾选强制回收；勾选全部菜单可创建拥有全部权限的管理员角色。修改普通用户角色会影响所有账户的默认权限，内置平台管理员必须保留授权管理权限。</p></HelpPopover></span>} field="permissions" rules={[{ required: true, type: 'array', minLength: 1, message: '请至少选择一项权限' }]}><PermissionTree items={catalog.data ?? []} disabled={state.mutation.isPending} lockedPermissions={isAdmin ? ['role:manage'] : undefined} /></Form.Item>
    <Form.Item label={<>角色标签<HelpPopover title="角色标签">可添加或修改自定义标签；系统托管标签用于现有授权和审批规则，不能更改。</HelpPopover></>} field="labels"><LabelEditor /></Form.Item>
    <Form.Item label={<>启用<HelpPopover title="角色启用">内置管理员和普通用户角色保持启用；审计员和自定义角色可停用，停用后不再授予权限。</HelpPopover></>} field="enabled" triggerPropName="checked"><Switch disabled={editing?.built_in && editing.name !== 'auditor'} /></Form.Item>
  </ResourceForm></QueryState>
}

export function RoleDefinitionForm() {
  const { name } = useParams()
  const query = useQuery(rolesQuery)
  const editing = query.data?.find(role => role.name === name)
  return <QueryState loading={!!name && query.isPending} error={query.error} retry={() => void query.refetch()}>{name && !editing ? <EmptyResult title="角色不存在" /> : <RoleEditor key={name ?? 'new'} editing={editing} />}</QueryState>
}

function BindingEditor({ ownership, editing }: { ownership: boolean; editing?: RoleBinding | Ownership }) {
  const state = useSave<LabelBindingDraft>(ownership ? '/admin/ownerships' : '/admin/role-bindings')
  return <ResourceForm form={state.form} initialValues={editing ?? { enabled: true, revision: 0 }} onSubmit={value => state.mutation.mutate({ ...value, id: editing?.id ?? '', revision: editing?.revision ?? 0 })} onChange={state.change} submitting={state.mutation.isPending} dirty={state.dirty} saved={state.mutation.isSuccess} error={state.mutation.error} backTo={ownership ? '/admin/workflows?tab=owners' : '/admin/roles?tab=bindings'}>
    <Form.Item label="规则名称" field="name" rules={[{ required: true }]}><Input maxLength={128} /></Form.Item>
    {ownership && <Form.Item label="资源标签条件" field="asset_selector" rules={[{ required: true }]}><Input maxLength={1024} placeholder="team=database,env=production" /></Form.Item>}
    <Form.Item label={ownership ? '负责人用户标签条件' : '用户标签条件'} field="user_selector" rules={[{ required: true }]}><Input maxLength={1024} placeholder="team=database,duty=owner" /></Form.Item>
    {!ownership && <Form.Item label="角色标签条件" field="role_selector" rules={[{ required: true }]}><Input maxLength={1024} placeholder="access-gateway.io/role=sre" /></Form.Item>}
    <Form.Item label="启用" field="enabled" triggerPropName="checked"><Switch /></Form.Item>
    <LabelBindingPreview form={state.form} ownership={ownership} />
  </ResourceForm>
}

export function BindingForm({ ownership = false }: { ownership?: boolean }) {
  const { id } = useParams()
  const roles = useQuery({ ...bindingsQuery, enabled: !ownership })
  const owners = useQuery({ ...ownersQuery, enabled: ownership })
  const query = ownership ? owners : roles
  const editing = query.data?.find(value => value.id === id)
  return <QueryState loading={!!id && query.isPending} error={query.error} retry={() => void query.refetch()}>{id && !editing ? <EmptyResult title="规则不存在" /> : <BindingEditor key={id ?? 'new'} ownership={ownership} editing={editing} />}</QueryState>
}

const newStep = (): Step => ({ name: '', kind: 'owners', mode: 'any', selector: '' })
function StepEditor({ value = [], onChange }: { value?: Step[]; onChange?: (value: Step[]) => void }) {
  const change = (index: number, patch: Partial<Step>) => onChange?.(value.map((s, i) => i === index ? { ...s, ...patch } : s))
  const move = (index: number, direction: number) => { const next = [...value]; const from = next[index]; const to = next[index + direction]; if (!from || !to) return; next[index] = to; next[index + direction] = from; onChange?.(next) }
  return <div className="workflow-steps">{value.map((step, index) => <section className="workflow-step" key={index}>
    <div className="table-toolbar"><strong>第 {index + 1} 级</strong><div className="table-actions">
      <Tooltip content="上移"><Button aria-label={`上移第 ${index + 1} 级`} icon={<IconArrowUp />} disabled={index === 0} onClick={() => move(index, -1)} /></Tooltip>
      <Tooltip content="下移"><Button aria-label={`下移第 ${index + 1} 级`} icon={<IconArrowDown />} disabled={index === value.length - 1} onClick={() => move(index, 1)} /></Tooltip>
      <Tooltip content="删除节点"><Button aria-label={`删除第 ${index + 1} 级`} icon={<IconDelete />} disabled={value.length <= 1} onClick={() => onChange?.(value.filter((_, i) => i !== index))} /></Tooltip>
    </div></div>
    <div className="form-grid"><label htmlFor={`flow-step-${index}-name`}>节点名称<Input id={`flow-step-${index}-name`} aria-label={`第 ${index + 1} 级名称`} maxLength={128} value={step.name} onChange={name => change(index, { name })} /></label>
    <label htmlFor={`flow-step-${index}-mode`}><span>审批方式<HelpPopover title="审批方式">或签：一人通过即可。会签：全部审批人均需通过。</HelpPopover></span><Select id={`flow-step-${index}-mode`} aria-label={`第 ${index + 1} 级审批方式`} value={step.mode} options={[{ value: 'any', label: '或签' }, { value: 'all', label: '会签' }]} onChange={mode => change(index, { mode })} /></label>
    <label htmlFor={`flow-step-${index}-kind`}><span>审批人来源<HelpPopover title="审批人来源"><p>“资源负责人”使用资产 owner 标签指定的用户；未设置 owner 时使用负责人匹配规则。负责人需具备审批权限。</p><p>选择“平台管理”后，由拥有平台管理员（admin）角色且具备审批权限的用户审批，无需填写标签条件。申请人不能审批自己的申请。</p></HelpPopover></span><Select id={`flow-step-${index}-kind`} aria-label={`第 ${index + 1} 级审批人来源`} value={isPlatformAdminStep(step) ? 'platform_admin' : step.kind} options={[{ value: 'owners', label: '资源负责人' }, { value: 'platform_admin', label: '平台管理' }, { value: 'user_selector', label: '匹配用户标签' }, { value: 'role_selector', label: '匹配角色标签' }]} onChange={(source: ApprovalSource) => change(index, changeApprovalSource(step, source))} /></label>
    {step.kind !== 'owners' && !isPlatformAdminStep(step) && <label htmlFor={`flow-step-${index}-selector`}>标签条件<Input id={`flow-step-${index}-selector`} aria-label={`第 ${index + 1} 级标签条件`} value={step.selector} maxLength={1024} onChange={selector => change(index, { selector })} /></label>}</div>
  </section>)}<Button icon={<IconPlus />} disabled={value.length >= 10} onClick={() => onChange?.([...value, newStep()])}>添加审批节点</Button></div>
}

function WorkflowEditor({ editing }: { editing?: Workflow }) {
  const state = useSave<Workflow>('/admin/workflows')
  const initial = editing ?? { enabled: true, labels: {}, timeout_seconds: 86400, steps: [{ name: '资源负责人', kind: 'owners', mode: 'any', selector: '' }, { name: '平台运维', kind: 'role_selector', mode: 'any', selector: 'access-gateway.io/approval=platform' }] }
  const steps = Form.useWatch('steps', state.form) as Step[] | undefined
  return <ResourceForm form={state.form} initialValues={initial as Partial<Workflow>} onSubmit={value => state.mutation.mutate({ ...value, id: editing?.id ?? '', revision: editing?.revision ?? 0, asset_selector: editing?.asset_selector ?? '', built_in: false })} onChange={state.change} submitting={state.mutation.isPending} dirty={state.dirty} saved={state.mutation.isSuccess} error={state.mutation.error} backTo="/admin/workflows">
    <Form.Item label="流程名称" field="name" rules={[{ required: true }]}><Input maxLength={128} /></Form.Item>
    <Form.Item label="描述" field="description"><Input.TextArea maxLength={512} /></Form.Item>
    <Form.Item label="审批期限（秒）" field="timeout_seconds" rules={[{ required: true }]}><InputNumber min={60} max={604800} precision={0} step={3600} /></Form.Item>
    <Form.Item label="流程标签" field="labels"><LabelEditor /></Form.Item>
    <Form.Item label="审批节点" field="steps"><StepEditor /></Form.Item>
    <Form.Item label="启用" field="enabled" triggerPropName="checked"><Switch /></Form.Item>
    <WorkflowDiagram steps={steps ?? initial.steps as Step[]} onStepSelect={index => {
      const input = document.getElementById(`flow-step-${index}-name`)
      input?.scrollIntoView({ block: 'center', behavior: 'smooth' })
      input?.focus({ preventScroll: true })
    }} />
  </ResourceForm>
}

export function WorkflowForm() {
  const { id } = useParams()
  const query = useQuery(workflowsQuery)
  const editing = query.data?.find(value => value.id === id)
  return <QueryState loading={!!id && query.isPending} error={query.error} retry={() => void query.refetch()}>{id && !editing ? <EmptyResult title="流程不存在" /> : <WorkflowEditor key={id ?? 'new'} editing={editing} />}</QueryState>
}
