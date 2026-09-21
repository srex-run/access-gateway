import { Link, Navigate, useParams, useSearchParams } from 'react-router-dom'
import { CloudAccountForm, CloudSyncForm, ResourceStatusForm, AssetCreateForm, AssetEditForm, AssetSettings, AssetWorkspace, ForceCloseForm, PortCreateForm, RoleGrantForm, RoleWorkspace, UserWorkspace, UserCreateForm, UserEditForm } from '@/features/admin'
import { ResourceFormPage } from '@/shared/ui/resource-form-page'
import { queryPath } from '@/shared/lib/navigation'
import { EmptyResult, PageBody, PageHeader } from '@/shared/ui/page'
import { InvitationsWorkspace } from '@/features/invitations'
import { RouteTabs } from '@/shared/ui/route-tabs'

export function AssetsPage() {
  return <><PageHeader title="资产管理" breadcrumb="平台管理" /><PageBody><AssetWorkspace /></PageBody></>
}
export function UsersPage() {
  return <><PageHeader title="账户管理" breadcrumb="平台管理" /><PageBody><RouteTabs items={[{ key: 'users', title: '用户账户', content: <UserWorkspace /> }, { key: 'invitations', title: '邮箱邀请', content: <InvitationsWorkspace /> }]} /></PageBody></>
}
export function UserEditPage() { return <><PageHeader title="用户详情" breadcrumb={<Link to="/admin/users">用户中心</Link>} /><PageBody><UserEditForm /></PageBody></> }
export function UserCreatePage() {
  return <ResourceFormPage title="添加账户" breadcrumb={<Link to="/admin/users">账户管理</Link>}><UserCreateForm /></ResourceFormPage>
}
export function LegacyAssetsPage() {
  const [params] = useSearchParams()
  const tab = params.get('tab')
  return <Navigate replace to={queryPath('/admin/assets', params, { tab: tab === 'sync' || tab === 'cloud' ? tab : 'assets', region: null })} />
}
export function RolePage() {
  return <><PageHeader title="角色授权" breadcrumb="安全管理" /><PageBody><RoleWorkspace /></PageBody></>
}
export function ForceClosePage() {
  return <ResourceFormPage title="强制回收" breadcrumb="安全管理"><ForceCloseForm /></ResourceFormPage>
}
export function AssetCreatePage() {
  const [params] = useSearchParams()
  return <ResourceFormPage title="添加资产" breadcrumb={<Link to={queryPath('/admin/assets', params, { tab: 'assets', region: null })}>资产管理</Link>}><AssetCreateForm /></ResourceFormPage>
}
export function AssetEditPage() {
  const { id } = useParams()
  const [params] = useSearchParams()
  return <ResourceFormPage title="编辑资产" breadcrumb={<Link to={queryPath('/admin/assets', params, { tab: 'assets', region: null })}>资产管理</Link>}>{id ? <AssetEditForm key={id} id={id} /> : <EmptyResult title="资产不存在" />}</ResourceFormPage>
}
export function AssetSettingsPage() {
  const { id } = useParams()
  const [params] = useSearchParams()
  return <><PageHeader title="资产配置" breadcrumb={<Link to={queryPath('/admin/assets', params, { tab: 'assets', region: null })}>资产管理</Link>} /><PageBody>{id ? <AssetSettings key={id} id={id} /> : <EmptyResult title="资产不存在" />}</PageBody></>
}

export function PortCreatePage() {
  const { id } = useParams()
  const [params] = useSearchParams()
  return <ResourceFormPage title="添加端口" breadcrumb={<Link to={queryPath(`/admin/assets/${id}`, params, { tab: null })}>资产配置</Link>}>{id ? <PortCreateForm key={id} id={id} /> : <EmptyResult title="资产不存在" />}</ResourceFormPage>
}


export function RoleGrantPage() {
  const [params] = useSearchParams()
  return <ResourceFormPage title="授予角色" breadcrumb={<Link to={queryPath('/admin/roles', params)}>角色授权</Link>}><RoleGrantForm /></ResourceFormPage>
}

export function CloudAccountPage() {
  const { id } = useParams()
  const [params] = useSearchParams()
  return <ResourceFormPage title={id ? '编辑云账号' : '添加云账号'} breadcrumb={<Link to={queryPath('/admin/assets', params, { tab: 'cloud', region: null })}>云账号</Link>}><CloudAccountForm id={id} /></ResourceFormPage>
}

export function CloudSyncPage() {
  const [params] = useSearchParams()
  return <ResourceFormPage title="同步云资产" breadcrumb={<Link to={queryPath('/admin/assets', params, { tab: 'sync', account: null, job: null, region: null })}>云同步</Link>}><CloudSyncForm /></ResourceFormPage>
}

export function ResourceStatusPage({ type }: { type: 'assets' }) {
  const { id } = useParams()
  const [params] = useSearchParams()
  const backTo = queryPath(`/admin/assets/${id}`, params)
  return <ResourceFormPage title="修改状态" breadcrumb={<Link to={backTo}>资产配置</Link>}>{id ? <ResourceStatusForm type={type} id={id} backTo={backTo} /> : <EmptyResult title="资源不存在" />}</ResourceFormPage>
}
