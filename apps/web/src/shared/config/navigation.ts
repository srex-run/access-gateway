import type { Permission } from '../lib/permissions'

export interface NavigationItem {
  path: string
  label: string
  icon: 'apps' | 'approval' | 'audit' | 'security' | 'users' | 'settings'
  group: string
  permission: Permission | Permission[]
  permissions: Permission[]
  aliases?: string[]
}

// Sidebar order, page access and the role permission tree share this definition.
// Some permissions enable actions in several menus; each occurrence grants the same key.
export const navigationItems: NavigationItem[] = [
  { path: '/catalog', label: '资产目录', icon: 'apps', group: '访问管理', permission: 'directory:read', permissions: ['directory:read'] },
  { path: '/approvals', label: '访问审批', icon: 'approval', group: '访问管理', permission: ['approval:manage', 'session:manage', 'request:manage', 'audit:read'], permissions: ['request:manage', 'approval:manage', 'session:manage', 'audit:read'], aliases: ['/requests', '/sessions'] },
  { path: '/audit', label: '审计日志', icon: 'audit', group: '安全管理', permission: ['session:manage', 'audit:read'], permissions: ['session:manage', 'audit:read'] },
  { path: '/admin/force-close', label: '强制回收', icon: 'security', group: '安全管理', permission: 'session:override', permissions: ['session:override'] },
  { path: '/admin/roles', label: '角色与权限', icon: 'users', group: '安全管理', permission: 'role:manage', permissions: ['role:manage'] },
  { path: '/admin/assets', label: '资产管理', icon: 'apps', group: '平台管理', permission: 'catalog:manage', permissions: ['catalog:manage'], aliases: ['/admin/cloud-accounts', '/admin/cloud-sync'] },
  { path: '/admin/users', label: '用户中心', icon: 'users', group: '平台管理', permission: 'user:read', permissions: ['user:read', 'user:manage'] },
  { path: '/admin/workflows', label: '审批流程', icon: 'approval', group: '平台管理', permission: 'workflow:manage', permissions: ['workflow:manage'] },
  { path: '/admin/settings', label: '系统设置', icon: 'settings', group: '平台管理', permission: 'role:manage', permissions: ['role:manage'] },
]

export function navigationPermission(path: string) {
  const item = navigationItems.find(item => item.path === path)
  if (!item) throw new Error(`Unknown navigation path: ${path}`)
  return item.permission
}
