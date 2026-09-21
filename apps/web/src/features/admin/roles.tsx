import { Button, Form, Input, Message, Popconfirm, Select, Tag, Tooltip } from '@arco-design/web-react'
import { IconDelete, IconPlus, IconRefresh } from '@arco-design/web-react/icon'
import type { DataColumn } from '@/shared/ui/data-table'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useSearchParams } from 'react-router-dom'
import { useIdentity } from '@/features/auth'
import { request, resourcePath } from '@/shared/api/client'
import { formatTime } from '@/shared/lib/format'
import { queryPath } from '@/shared/lib/navigation'
import { useTableView } from '@/shared/hooks/use-table-view'
import { DataTable } from '@/shared/ui/data-table'
import { TabToolbar } from '@/shared/ui/route-tabs'
import { CopyableText } from '@/shared/ui/copyable-text'
import { ErrorNotice } from '@/shared/ui/page'
import { ResourceForm } from '@/shared/ui/resource-form'
import { uuidPattern, uuidRules } from './fields'
import { useAdminForm } from './hooks'
import { ResourceLookup } from './resource-actions'
import type { RoleAssignment } from './types'

const roleOptions = [{ value: 'sre', label: '运维工程师' }, { value: 'auditor', label: '审计员' }, { value: 'catalog_admin', label: '目录管理员' }, { value: 'security_admin', label: '安全管理员' }, { value: 'admin', label: '管理员' }]

function useRoles() {
  const [params, setParams] = useSearchParams()
  const rawID = params.get('user') ?? ''
  const client = useQueryClient()
  const identity = useIdentity()
  const id = uuidPattern.test(rawID) ? rawID : identity.data?.user_id ?? ''
  const queryKey = ['roles', id]
  const query = useQuery({ queryKey, queryFn: ({ signal }) => request<RoleAssignment[]>('/admin/role-assignments', { signal, query: { user_id: id } }), enabled: !!id })
  const revoke = useMutation({ mutationFn: (assignment: string) => request(resourcePath('admin/role-assignments', assignment), { method: 'DELETE' }), onSuccess: async () => {
    await client.invalidateQueries({ queryKey: ['roles'] })
    await client.invalidateQueries({ queryKey: ['managed-user'] })
    await client.invalidateQueries({ queryKey: ['identity'] })
    await client.invalidateQueries({ queryKey: ['workflow-progress'] })
    Message.success('角色已撤销')
  } })
  return { id, params, setParams, identity, query, revoke }
}

export function RoleWorkspace() {
  const state = useRoles()
  const view = useTableView('roles', state.query.data, value => value.role)
  const columns: DataColumn<RoleAssignment>[] = [
    { title: '角色', width: 180, render: (_, value) => roleOptions.find(option => option.value === value.role)?.label ?? value.role },
    { title: '用户 ID', width: 220, render: (_, value) => <CopyableText value={value.user_id} abbreviated /> },
    { title: '授予时间', width: 180, render: (_, value) => formatTime(value.created_at) },
    { title: '状态', width: 100, render: (_, value) => <Tag color={value.revoked_at ? 'gray' : 'green'}>{value.revoked_at ? '已撤销' : '有效'}</Tag> },
    { title: '操作', width: 72, fixed: 'right', render: (_, value) => !value.revoked_at && !(value.role === 'admin' && value.user_id === state.identity.data?.user_id) && <Popconfirm title="撤销这个角色？" onOk={() => state.revoke.mutateAsync(value.id).then(() => undefined)}><Tooltip content="撤销角色"><Button type="text" size="small" status="danger" icon={<IconDelete />} aria-label={`撤销 ${roleOptions.find(option => option.value === value.role)?.label ?? value.role}`} loading={state.revoke.isPending} /></Tooltip></Popconfirm> },
  ]
  return <><TabToolbar title="直接角色授权">
    <ResourceLookup key={state.id} label="用户 ID" initial={state.id} onLookup={value => state.setParams(previous => {
      const next = new URLSearchParams(previous)
      next.set('user', value)
      next.set('roles_page', '1')
      return next
    })} />
    <div className="table-actions">
      <Tooltip content="刷新角色"><Button icon={<IconRefresh />} aria-label="刷新角色" loading={state.query.isFetching} disabled={!state.id} onClick={() => void state.query.refetch()} /></Tooltip>
      <Link to={queryPath('/admin/roles/create', state.params, { user: state.id })}><Button type="primary" icon={<IconPlus />}>授予角色</Button></Link>
    </div>
  </TabToolbar>
    <ErrorNotice error={state.revoke.error} />
    <DataTable columns={columns} data={view.data} pagination={view.pagination} loading={!!state.id && state.query.isPending} error={state.query.error} onRetry={() => void state.query.refetch()} empty="暂无角色授权" />
  </>
}

export function RoleGrantForm() {
  const [params] = useSearchParams()
  const rawID = params.get('user') ?? ''
  const definitions = useQuery({ queryKey: ['governance', 'roles'], queryFn: ({ signal }) => request<{ name: string; description: string; enabled: boolean }[]>('/admin/roles', { signal }) })
  const client = useQueryClient()
  const state = useAdminForm(async (body: { user_id: string; role: string }) => {
    const value = await request<RoleAssignment>('/admin/role-assignments', { method: 'POST', body })
    await client.invalidateQueries({ queryKey: ['roles'] })
    await client.invalidateQueries({ queryKey: ['managed-user'] })
    await client.invalidateQueries({ queryKey: ['identity'] })
    await client.invalidateQueries({ queryKey: ['workflow-progress'] })
    return value
  })
  const backTo = queryPath('/admin/role-assignments', params, state.mutation.data ? { user: state.mutation.data.user_id, roles_page: '1' } : {})
  return <ResourceForm form={state.form} initialValues={{ user_id: uuidPattern.test(rawID) ? rawID : undefined }} onSubmit={value => state.mutation.mutate(value)} onChange={state.change} dirty={state.dirty} submitting={state.mutation.isPending} saved={state.mutation.isSuccess} backTo={backTo} error={state.mutation.error} submitText="授予角色">
    <Form.Item label="用户 ID" field="user_id" rules={uuidRules}><Input /></Form.Item><Form.Item label="角色" field="role" rules={[{ required: true }]}><Select options={definitions.data?.filter(role => role.enabled).map(role => ({ value: role.name, label: `${role.name} · ${role.description}` })) ?? roleOptions} /></Form.Item>
  </ResourceForm>
}
