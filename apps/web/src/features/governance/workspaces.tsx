import { Button, Input, Tag } from '@arco-design/web-react'
import { IconEdit, IconPlus, IconRefresh, IconSearch, IconUserGroup } from '@arco-design/web-react/icon'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import type { ReactNode } from 'react'
import { PermissionGate } from '@/features/auth'
import { useTableView } from '@/shared/hooks/use-table-view'
import { CompactTags } from '@/shared/ui/compact-tags'
import { DataTable, TableText } from '@/shared/ui/data-table'
import { IconButton } from '@/shared/ui/icon-button'
import { LabelTags } from '@/shared/ui/labels'
import { HelpPopover } from '@/shared/ui/help-popover'
import { RouteTabs, TabToolbar } from '@/shared/ui/route-tabs'
import { bindingsQuery, ownersQuery, rolesQuery, workflowsQuery } from './api'

function Toolbar({ title, path, label, refresh, loading, search, onSearch, help, actions }: { title: string; path: string; label: string; refresh: () => void; loading: boolean; search: string; onSearch: (value: string) => void; help?: ReactNode; actions?: ReactNode }) {
  return <TabToolbar title={title}><Input className="filter-search" prefix={<IconSearch />} aria-label={`搜索${title}`} placeholder={`搜索${title}`} allowClear value={search} onChange={onSearch} /><div className="table-actions">{help}{actions}<IconButton label={`刷新${title}`} icon={<IconRefresh />} loading={loading} onClick={refresh} /><Link to={path}><Button type="primary" icon={<IconPlus />}>{label}</Button></Link></div></TabToolbar>
}

function Roles() {
  const query = useQuery(rolesQuery)
  const view = useTableView('definitions', query.data, value => `${value.name} ${value.description} ${value.permissions.join(' ')} ${JSON.stringify(value.labels)}`)
  return <><Toolbar title="角色" path="/admin/role-definitions/create" label="新建角色" search={view.search} onSearch={view.setSearch} loading={query.isFetching} refresh={() => void query.refetch()} actions={<Link to="/admin/role-assignments"><IconButton label="用户直接角色授权" icon={<IconUserGroup />} /></Link>} /><DataTable data={view.data} pagination={view.pagination} rowKey="name" loading={query.isPending} error={query.error} onRetry={() => void query.refetch()} columns={[
    { title: '角色', width: 200, render: (_, value) => <div className="table-cell-inline"><TableText>{value.name}</TableText>{value.built_in && <Tag>内置</Tag>}</div> },
    { title: '描述', dataIndex: 'description', width: 240 }, { title: '角色标签', width: 240, render: (_, value) => <LabelTags value={value.labels} /> },
    { title: '权限', width: 240, render: (_, value) => <CompactTags values={value.permissions} title="角色权限" /> },
    { title: '状态', width: 90, render: (_, value) => <Tag color={value.enabled ? 'green' : 'gray'}>{value.enabled ? '启用' : '停用'}</Tag> },
    { title: '操作', width: 72, fixed: 'right', render: (_, value) => <Link to={`/admin/role-definitions/${encodeURIComponent(value.name)}/edit`}><IconButton label={`编辑角色 ${value.name}`} icon={<IconEdit />} /></Link> },
  ]} /></>
}

function Bindings() {
  const query = useQuery(bindingsQuery)
  const view = useTableView('role_bindings', query.data, value => `${value.name} ${value.user_selector} ${value.role_selector}`)
  return <><Toolbar title="授权绑定" path="/admin/role-bindings/create" label="新建绑定" search={view.search} onSearch={view.setSearch} loading={query.isFetching} refresh={() => void query.refetch()} help={<HelpPopover title="标签授权绑定">绑定规则将匹配的用户授予匹配的角色。标签本身不会赋予权限；修改用户标签、角色标签和绑定规则都需要授权管理权限。</HelpPopover>} /><DataTable data={view.data} pagination={view.pagination} loading={query.isPending} error={query.error} onRetry={() => void query.refetch()} columns={[
    { title: '名称', dataIndex: 'name', width: 220 }, { title: '用户标签条件', dataIndex: 'user_selector', width: 300 }, { title: '角色标签条件', dataIndex: 'role_selector', width: 300 },
    { title: '状态', width: 90, render: (_, v) => <Tag color={v.enabled ? 'green' : 'gray'}>{v.enabled ? '启用' : '停用'}</Tag> }, { title: '操作', width: 72, fixed: 'right', render: (_, v) => <Link to={`/admin/role-bindings/${v.id}/edit`}><IconButton label="编辑授权绑定" icon={<IconEdit />} /></Link> },
  ]} /></>
}

export function RoleCenter() {
  return <RouteTabs items={[{ key: 'roles', title: '角色与权限', content: <Roles /> }, { key: 'bindings', title: '标签授权绑定', content: <Bindings /> }]} />
}

function Workflows() {
  const query = useQuery(workflowsQuery)
  const view = useTableView('workflows', query.data, value => `${value.name} ${value.steps.map(step => step.name).join(' ')}`)
  return <><Toolbar title="审批流程" path="/admin/workflows/create" label="新建流程" search={view.search} onSearch={view.setSearch} loading={query.isFetching} refresh={() => void query.refetch()} help={<HelpPopover title="审批流程">创建流程时可在表单下方实时预览审批节点和顺序。保存后，在资产创建或编辑页选择审批流程，通过“查看审批流程”查看节点。审批人由所选流程的节点决定。包含资源负责人节点时，可用资产 owner 标签指定负责人；未设置 owner 时使用负责人匹配规则。</HelpPopover>} /><DataTable data={view.data} pagination={view.pagination} loading={query.isPending} error={query.error} onRetry={() => void query.refetch()} columns={[
    { title: '流程名称', width: 240, render: (_, v) => <TableText>{v.name}</TableText> },
    { title: '审批节点', width: 340, render: (_, v) => <TableText>{v.steps.map(s => s.name).join(' → ')}</TableText> },
    { title: <span className="table-cell-inline">审批方式<HelpPopover title="审批方式">或签：一人通过即可。会签：全部审批人均需通过。各方式与审批节点按顺序对应。</HelpPopover></span>, width: 180, render: (_, v) => <TableText>{v.steps.map(s => s.mode === 'all' ? '会签' : '或签').join(' → ')}</TableText> },
    { title: '期限', width: 110, render: (_, v) => `${v.timeout_seconds / 3600} 小时` }, { title: '状态', width: 90, render: (_, v) => <Tag color={v.enabled ? 'green' : 'gray'}>{v.enabled ? '启用' : '停用'}</Tag> },
    { title: '操作', width: 72, fixed: 'right', render: (_, v) => <Link to={`/admin/workflows/${v.id}/edit`}><IconButton label="编辑审批流程" icon={<IconEdit />} /></Link> },
  ]} /></>
}

function Owners() {
  const query = useQuery(ownersQuery)
  const view = useTableView('owners', query.data, value => `${value.name} ${value.asset_selector} ${value.user_selector}`)
  return <><Toolbar title="负责人规则" path="/admin/ownerships/create" label="新建负责人规则" search={view.search} onSearch={view.setSearch} loading={query.isFetching} refresh={() => void query.refetch()} /><DataTable data={view.data} pagination={view.pagination} loading={query.isPending} error={query.error} onRetry={() => void query.refetch()} columns={[
    { title: '名称', dataIndex: 'name', width: 220 }, { title: '资源标签条件', dataIndex: 'asset_selector', width: 300 }, { title: '负责人用户标签条件', dataIndex: 'user_selector', width: 300 },
    { title: '状态', width: 90, render: (_, v) => <Tag color={v.enabled ? 'green' : 'gray'}>{v.enabled ? '启用' : '停用'}</Tag> }, { title: '操作', width: 72, fixed: 'right', render: (_, v) => <Link to={`/admin/ownerships/${v.id}/edit`}><IconButton label="编辑负责人规则" icon={<IconEdit />} /></Link> },
  ]} /></>
}

export function WorkflowCenter() {
  return <PermissionGate permission="workflow:manage"><RouteTabs items={[{ key: 'workflows', title: '审批流程', content: <Workflows /> }, { key: 'owners', title: '资源负责人', content: <Owners /> }]} /></PermissionGate>
}
