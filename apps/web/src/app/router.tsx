import { Suspense, lazy } from 'react'
import type { ReactNode } from 'react'
import { createBrowserRouter, Link, Navigate, Outlet, useLocation, useParams } from 'react-router-dom'
import { Button } from '@arco-design/web-react'
import { PermissionGate } from '@/features/auth'
import type { Permission } from '@/features/auth'
import { EmptyResult, QueryState } from '@/shared/ui/page'
import { navigationPermission } from '@/shared/config/navigation'
import { ConsoleLayout } from './layout'

const CatalogPage = lazy(() => import('@/pages/catalog'))
const LoginPage = lazy(() => import('@/pages/login'))
const MFAPage = lazy(() => import('@/pages/mfa'))
const InvitePage = lazy(() => import('@/pages/invite'))
const InvitationCreatePage = lazy(() => import('@/pages/invitations'))
const AccountPage = lazy(() => import('@/pages/account'))
const SettingsPage = lazy(() => import('@/pages/settings'))
const ApprovalsPage = lazy(() => import('@/pages/approvals'))
const AuditPage = lazy(() => import('@/pages/audit'))
const RequestsPage = lazy(() => import('@/pages/requests').then(module => ({ default: module.RequestsPage })))
const RequestCreatePage = lazy(() => import('@/pages/requests').then(module => ({ default: module.RequestCreatePage })))
const RequestDetailPage = lazy(() => import('@/pages/requests').then(module => ({ default: module.RequestDetailPage })))
const SessionsPage = lazy(() => import('@/pages/sessions').then(module => ({ default: module.SessionsPage })))
const SessionDetailPage = lazy(() => import('@/pages/sessions').then(module => ({ default: module.SessionDetailPage })))
const AssetsPage = lazy(() => import('@/pages/admin').then(module => ({ default: module.AssetsPage })))
const UsersPage = lazy(() => import('@/pages/admin').then(module => ({ default: module.UsersPage })))
const UserCreatePage = lazy(() => import('@/pages/admin').then(module => ({ default: module.UserCreatePage })))
const LegacyAssetsPage = lazy(() => import('@/pages/admin').then(module => ({ default: module.LegacyAssetsPage })))
const AssetCreatePage = lazy(() => import('@/pages/admin').then(module => ({ default: module.AssetCreatePage })))
const AssetEditPage = lazy(() => import('@/pages/admin').then(module => ({ default: module.AssetEditPage })))
const AssetSettingsPage = lazy(() => import('@/pages/admin').then(module => ({ default: module.AssetSettingsPage })))
const PortCreatePage = lazy(() => import('@/pages/admin').then(module => ({ default: module.PortCreatePage })))
const RolePage = lazy(() => import('@/pages/admin').then(module => ({ default: module.RolePage })))
const RoleGrantPage = lazy(() => import('@/pages/admin').then(module => ({ default: module.RoleGrantPage })))
const ForceClosePage = lazy(() => import('@/pages/admin').then(module => ({ default: module.ForceClosePage })))

const RolesPage = lazy(() => import('@/pages/governance').then(module => ({ default: module.RolesPage })))
const RoleDefinitionPage = lazy(() => import('@/pages/governance').then(module => ({ default: module.RoleDefinitionPage })))
const RoleBindingPage = lazy(() => import('@/pages/governance').then(module => ({ default: module.RoleBindingPage })))
const WorkflowsPage = lazy(() => import('@/pages/governance').then(module => ({ default: module.WorkflowsPage })))
const WorkflowEditPage = lazy(() => import('@/pages/governance').then(module => ({ default: module.WorkflowEditPage })))
const OwnershipPage = lazy(() => import('@/pages/governance').then(module => ({ default: module.OwnershipPage })))
const UserEditPage = lazy(() => import('@/pages/admin').then(module => ({ default: module.UserEditPage })))

const CloudAccountPage = lazy(() => import('@/pages/admin').then(module => ({ default: module.CloudAccountPage })))
const CloudSyncPage = lazy(() => import('@/pages/admin').then(module => ({ default: module.CloudSyncPage })))
const ResourceStatusPage = lazy(() => import('@/pages/admin').then(module => ({ default: module.ResourceStatusPage })))

function LegacyAssetGatewayRedirect() {
  const { id } = useParams()
  return <Navigate replace to={`/admin/assets/${id}`} />
}

function LegacyCreateRedirect() {
  const location = useLocation()
  return <Navigate replace to={`${location.pathname.replace(/\/new$/, '/create')}${location.search}`} />
}

function guard(permission: Permission | Permission[], children: ReactNode) {
  return <PermissionGate permission={permission} fallback={<EmptyResult title="无权访问此页面" status="403" />}>{children}</PermissionGate>
}

function guardMenu(path: string, children: ReactNode) {
  return guard(navigationPermission(path), children)
}

export const router = createBrowserRouter([{
  element: <Suspense fallback={<QueryState loading error={null}>{null}</QueryState>}><Outlet /></Suspense>,
  errorElement: <EmptyResult title="页面加载失败" status="error"><Button onClick={() => window.location.reload()}>重新加载</Button></EmptyResult>,
  children: [
    { path: '/login', element: <LoginPage /> },
    { path: '/mfa', element: <MFAPage /> },
    { path: '/invite', element: <InvitePage /> },
    { element: <ConsoleLayout />, children: [
      { index: true, element: <Navigate to="/catalog" replace /> },
      { path: 'account', element: <AccountPage /> },
      { path: 'catalog', element: guardMenu('/catalog', <CatalogPage />) },
      { path: 'requests', element: guard('request:manage', <RequestsPage />) },
      { path: 'requests/create', element: guard('request:manage', <RequestCreatePage />) },
      { path: 'requests/:id', element: guard('request:manage', <RequestDetailPage />) },
      { path: 'approvals', element: guardMenu('/approvals', <ApprovalsPage />) },
      { path: 'sessions', element: guard(['session:manage', 'approval:manage', 'audit:read'], <SessionsPage />) },
      { path: 'sessions/by-request/:id', element: guard(['session:manage', 'approval:manage', 'audit:read'], <SessionDetailPage byRequest />) },
      { path: 'sessions/:id', element: guard(['session:manage', 'approval:manage', 'audit:read'], <SessionDetailPage />) },
      { path: 'audit', element: guardMenu('/audit', <AuditPage />) },
      { path: 'admin/regions', element: guard('catalog:manage', <LegacyAssetsPage />) },
      { path: 'admin/regions/create', element: guard('catalog:manage', <LegacyAssetsPage />) },
      { path: 'admin/cloud-accounts/create', element: guard('role:manage', <CloudAccountPage />) },
      { path: 'admin/cloud-accounts/:id/edit', element: guard('role:manage', <CloudAccountPage />) },
      { path: 'admin/cloud-sync/create', element: guard('catalog:manage', <CloudSyncPage />) },
      { path: 'admin/assets/:id/status/edit', element: guard('catalog:manage', <ResourceStatusPage type="assets" />) },
      { path: 'admin/assets', element: guardMenu('/admin/assets', <AssetsPage />) },
      { path: 'admin/gateways/*', element: <Navigate replace to="/admin/assets" /> },
      { path: 'admin/assets/:id/gateways/*', element: <LegacyAssetGatewayRedirect /> },
      { path: 'admin/users', element: guardMenu('/admin/users', <UsersPage />) },
      { path: 'admin/users/create', element: guard('user:manage', <UserCreatePage />) },
      { path: 'admin/users/invite', element: guard('user:manage', <InvitationCreatePage />) },
      { path: 'admin/assets/create', element: guard('catalog:manage', <AssetCreatePage />) },
      { path: 'admin/assets/:id/edit', element: guard('catalog:manage', <AssetEditPage />) },
      { path: 'admin/assets/:id', element: guard('catalog:manage', <AssetSettingsPage />) },
      { path: 'admin/assets/:id/ports/create', element: guard('catalog:manage', <PortCreatePage />) },
      { path: 'admin/roles', element: guardMenu('/admin/roles', <RolesPage />) },
      { path: 'admin/role-assignments', element: guard('role:manage', <RolePage />) },
      { path: 'admin/roles/create', element: guard('role:manage', <RoleGrantPage />) },
      { path: 'admin/users/:id', element: guard('user:read', <UserEditPage />) },
      { path: 'admin/role-definitions/create', element: guard('role:manage', <RoleDefinitionPage />) },
      { path: 'admin/role-definitions/:name/edit', element: guard('role:manage', <RoleDefinitionPage />) },
      { path: 'admin/role-bindings/create', element: guard('role:manage', <RoleBindingPage />) },
      { path: 'admin/role-bindings/:id/edit', element: guard('role:manage', <RoleBindingPage />) },
      { path: 'admin/workflows', element: guardMenu('/admin/workflows', <WorkflowsPage />) },
      { path: 'admin/workflows/create', element: guard('workflow:manage', <WorkflowEditPage />) },
      { path: 'admin/workflows/:id/edit', element: guard('workflow:manage', <WorkflowEditPage />) },
      { path: 'admin/ownerships/create', element: guard('workflow:manage', <OwnershipPage />) },
      { path: 'admin/ownerships/:id/edit', element: guard('workflow:manage', <OwnershipPage />) },
      { path: 'admin/settings', element: guardMenu('/admin/settings', <SettingsPage />) },
      { path: 'admin/force-close', element: guardMenu('/admin/force-close', <ForceClosePage />) },
      { path: 'requests/new', element: <LegacyCreateRedirect /> },
      { path: 'admin/regions/new', element: <LegacyCreateRedirect /> },
      { path: 'admin/users/new', element: <LegacyCreateRedirect /> },
      { path: 'admin/assets/new', element: <LegacyCreateRedirect /> },
      { path: 'admin/assets/:id/ports/new', element: <LegacyCreateRedirect /> },
      { path: 'admin/roles/new', element: <LegacyCreateRedirect /> },
      { path: 'admin/role-definitions/new', element: <LegacyCreateRedirect /> },
      { path: 'admin/role-bindings/new', element: <LegacyCreateRedirect /> },
      { path: 'admin/workflows/new', element: <LegacyCreateRedirect /> },
      { path: 'admin/ownerships/new', element: <LegacyCreateRedirect /> },
      { path: '*', element: <EmptyResult title="页面不存在"><Link to="/catalog"><Button>返回资产目录</Button></Link></EmptyResult> },
    ] },
  ],
}])
