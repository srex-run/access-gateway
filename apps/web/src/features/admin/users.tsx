import { Button, Form, Input, Select, Space, Tag } from '@arco-design/web-react'
import type { DataColumn } from '@/shared/ui/data-table'
import { IconEdit, IconPlus, IconRefresh } from '@arco-design/web-react/icon'
import { queryOptions, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { PermissionGate, useIdentity, UserMFAStatus } from '@/features/auth'
import type { Permission } from '@/features/auth'
import type { RoleGrant } from '@/features/governance'
import { request } from '@/shared/api/client'
import { usePagination } from '@/shared/hooks/use-pagination'
import { formatTime } from '@/shared/lib/format'
import { CopyableText } from '@/shared/ui/copyable-text'
import { DataTable, TableDetail } from '@/shared/ui/data-table'
import { IconButton } from '@/shared/ui/icon-button'
import { TabToolbar } from '@/shared/ui/route-tabs'
import { DetailList, ErrorNotice } from '@/shared/ui/page'
import { HelpPopover } from '@/shared/ui/help-popover'
import { ResourceForm } from '@/shared/ui/resource-form'
import { useAdminForm } from './hooks'
import { LabelEditor, LabelTags } from '@/shared/ui/labels'
import type { Labels } from '@/shared/ui/labels'
import { QueryState } from '@/shared/ui/page'

interface User { id: string; nickname: string; username: string; email: string; department: string; labels: Labels; revision: number; status: string; feishu_bound: boolean; created_at: string; roles?: { name: string }[]; role_grants?: RoleGrant[]; permissions?: Permission[]; can_edit?: boolean; can_label?: boolean }
const usersQuery = (search: string, active = false, limit = 51, offset = 0) => queryOptions({ queryKey: ['users', search, active, limit, offset], queryFn: ({ signal }) => request<User[]>('/admin/users', { signal, query: { search, active, limit, offset } }) })

export function UserField({ label = '审批人' }: { label?: string }) {
  const [search, setSearch] = useState('')
  const query = useQuery(usersQuery(search, true, 50))
  return <><ErrorNotice error={query.error} retry={() => void query.refetch()} />
    <Form.Item label={<>{label}<HelpPopover title={label}>按昵称或用户名搜索启用的账户。申请人不能审批自己的申请；飞书审批需要审批人绑定飞书账号。</HelpPopover></>} field="user_id" rules={[{ required: true, message: `请选择${label}` }]}>
      <Select aria-label={label} showSearch filterOption={false} onSearch={setSearch} loading={query.isFetching} placeholder="搜索昵称或用户名" options={(query.data ?? []).map(value => ({ value: value.id, label: `${value.nickname}${value.username ? ` (${value.username})` : ''}` }))} />
    </Form.Item>
  </>
}

export function UserWorkspace() {
  const [search, setSearch] = useState('')
  const pagination = usePagination()
  const query = useQuery(usersQuery(search, false, pagination.pageSize + 1, pagination.offset))
  const columns: DataColumn<User>[] = [
    { title: '用户名', dataIndex: 'username', width: 160 },
    { title: '昵称', dataIndex: 'nickname', width: 160 },
    { title: '账户 ID', width: 180, render: (_, value) => <CopyableText value={value.id} abbreviated /> },
    { title: '邮箱', width: 210, render: (_, value) => value.email || '—' },
    { title: '标签', width: 240, render: (_, value) => <LabelTags value={value.labels} /> },
    { title: '状态', width: 90, render: (_, value) => <Tag color={value.status === 'active' ? 'green' : 'gray'}>{value.status === 'active' ? '启用' : '停用'}</Tag> },
    { title: '飞书', width: 100, render: (_, value) => value.feishu_bound ? '已绑定' : '未绑定' },
    { title: '创建时间', width: 170, render: (_, value) => formatTime(value.created_at) },
    { title: '操作', width: 200, fixed: 'right', render: (_, value) => <Space><Link to={`/admin/users/${value.id}`}>用户详情</Link><PermissionGate permission="user:manage"><Link to={`/admin/users/${value.id}`}><IconButton label={`编辑用户 ${value.nickname}`} icon={<IconEdit />} /></Link></PermissionGate><PermissionGate permission="role:manage"><Link to={`/admin/role-assignments?user=${value.id}`}>角色授权</Link></PermissionGate></Space> },
  ]
  const values = (query.data ?? []).slice(0, pagination.pageSize)
  return <><TabToolbar title="用户账户">
    <Input.Search className="filter-search" aria-label="搜索账户" placeholder="搜索昵称、用户名或邮箱" allowClear value={search} onChange={value => { setSearch(value); pagination.change(1) }} />
    <div className="table-actions"><IconButton label="刷新账户" icon={<IconRefresh />} loading={query.isFetching} onClick={() => void query.refetch()} /><PermissionGate permission="user:manage"><Link to="/admin/users/create"><Button type="primary" icon={<IconPlus />}>添加账户</Button></Link></PermissionGate></div>
  </TabToolbar><DataTable columns={columns} data={values} loading={query.isPending} error={query.error} onRetry={() => void query.refetch()} pagination={{ ...pagination, count: values.length, hasNext: (query.data?.length ?? 0) > pagination.pageSize, onChange: pagination.change }} empty="暂无账户" /></>
}

interface LocalUserInput { nickname: string; username: string; password: string }
function ProfileEditor({ user }: { user: User }) {
  const identity = useIdentity()
  const client = useQueryClient()
  const state = useAdminForm(async (body: User) => {
    const value = await request<User>(`/admin/users/${user.id}`, { method: 'PATCH', body: { nickname: body.nickname, email: body.email, department: body.department, status: body.status, labels: body.labels, revision: user.revision }, validationMessages: true })
    await client.invalidateQueries({ queryKey: ['users'] })
    await client.invalidateQueries({ queryKey: ['managed-user', user.id] })
    await client.invalidateQueries({ queryKey: ['identity'] })
    await client.invalidateQueries({ queryKey: ['workflow-progress'] })
    await client.invalidateQueries({ queryKey: ['label-preview'] })
    return value
  })
  return <ResourceForm form={state.form} initialValues={user} onSubmit={value => state.mutation.mutate(value)} onChange={state.change} submitting={state.mutation.isPending} dirty={state.dirty} saved={state.mutation.isSuccess} error={state.mutation.error} backTo="/admin/users">
    <Form.Item label="昵称" field="nickname"><Input maxLength={128} placeholder="默认使用用户名" /></Form.Item>
    <Form.Item label="邮箱" field="email"><Input maxLength={254} /></Form.Item>
    <Form.Item label="部门" field="department"><Input maxLength={128} /></Form.Item>
    <Form.Item label="状态" field="status"><Select disabled={user.id === identity.data?.user_id} options={[{ value: 'active', label: '启用' }, { value: 'inactive', label: '停用（退出登录并回收访问会话）' }]} /></Form.Item>
    <Form.Item label={<>用户标签<HelpPopover title="授权标签">标签用于匹配角色绑定及负责人规则，修改需要授权管理权限。示例：team=database、duty=owner。</HelpPopover></>} field="labels"><LabelEditor disabled={!user.can_label} /></Form.Item>
  </ResourceForm>
}

function UserAuthorization({ user }: { user: User }) {
  return <section className="user-authorization"><div className="table-toolbar"><strong>有效权限</strong><Tag color={user.status === 'active' ? 'green' : 'gray'}>{user.status === 'active' ? '账户启用' : '账户停用'}</Tag></div>
    <Space wrap>{user.permissions?.length ? user.permissions.map(permission => <Tag key={permission}>{permission}</Tag>) : <span className="muted">无有效权限</span>}</Space>
    <div className="table-toolbar"><strong>角色授权来源</strong><PermissionGate permission="role:manage"><Link to={`/admin/role-assignments?user=${user.id}`}>管理直接授权</Link></PermissionGate></div>
    <DataTable data={user.role_grants ?? []} rowKey={value => value.role.name} columns={[
      { title: '角色', width: 140, render: (_, value) => <strong>{value.role.name}</strong> },
      { title: '角色标签', width: 200, render: (_, value) => <LabelTags value={value.role.labels} /> },
      { title: '来源', width: 320, render: (_, value) => <TableDetail title="角色授权来源" summary={value.sources.map(source => source.name).join('、')}><div className="grant-sources">{value.sources.map((source, index) => <div key={`${source.kind}-${source.id ?? index}`}><strong>{source.name}</strong>{source.revision !== undefined && <span className="muted"> · v{source.revision}</span>}{source.user_selector && <div><code className="break-text">{source.user_selector} → {source.role_selector}</code></div>}</div>)}</div></TableDetail> },
    ]} empty={user.status === 'active' ? '无有效角色' : '账户已停用'} />
  </section>
}

export function UserEditForm() {
  const { id } = useParams()
  const identity = useIdentity()
  const query = useQuery({ queryKey: ['managed-user', id], queryFn: ({ signal }) => request<User>(`/admin/users/${id}`, { signal }), enabled: !!id })
  const user = query.data
  return <QueryState loading={query.isPending} error={query.error} retry={() => void query.refetch()}>{user && <>
    <DetailList items={[{ label: '用户 ID', value: <CopyableText value={user.id} /> }, { label: '用户名', value: user.username || '—' }, { label: '飞书账户', value: user.feishu_bound ? '已绑定' : '未绑定' }]} />
    {user.can_edit ? <ProfileEditor key={user.revision} user={user} /> : <DetailList items={[{ label: '昵称', value: user.nickname }, { label: '邮箱', value: user.email || '—' }, { label: '部门', value: user.department || '—' }, { label: '用户标签', value: <LabelTags value={user.labels} /> }]} />}
    <UserAuthorization user={user} />
    <UserMFAStatus userID={user.id} canReset={user.id !== identity.data?.user_id && (identity.data?.permissions.includes('role:manage') ?? false)} />
  </>}</QueryState>
}

export function UserCreateForm() {
  const client = useQueryClient()
  const state = useAdminForm(async (body: LocalUserInput) => {
    const value = await request<User>('/admin/users', { method: 'POST', body, validationMessages: true })
    await client.invalidateQueries({ queryKey: ['users'] })
    return value
  }, '账户已创建')
  return <ResourceForm form={state.form} onSubmit={value => state.mutation.mutate(value)} onChange={state.change} dirty={state.dirty} submitting={state.mutation.isPending} saved={state.mutation.isSuccess} error={state.mutation.error} backTo="/admin/users">
    <Form.Item label="用户名" field="username" rules={[{ required: true, match: /^[a-zA-Z0-9][a-zA-Z0-9._-]{2,63}$/, message: '请输入 3–64 位字母、数字、点、下划线或连字符' }]}><Input autoComplete="off" maxLength={64} /></Form.Item>
    <Form.Item label="昵称" field="nickname"><Input maxLength={128} placeholder="默认使用用户名" /></Form.Item>
    <Form.Item label={<>初始密码<HelpPopover title="初始密码">密码长度为 12–72 字节。新账户使用普通用户角色的默认权限，初始可申请访问并管理自己的会话。</HelpPopover></>} field="password" rules={[{ required: true, minLength: 12, maxLength: 72, message: '请输入 12–72 位密码' }]}><Input.Password aria-label="初始密码" autoComplete="new-password" /></Form.Item>
  </ResourceForm>
}
