import { Button, Drawer, Menu, Space } from '@arco-design/web-react'
import { IconExport, IconMenuFold, IconMenuUnfold, IconMoon, IconSun, IconUser } from '@arco-design/web-react/icon'
import { useEffect, useState } from 'react'
import { Link, Navigate, Outlet, useLocation, useNavigate } from 'react-router-dom'
import { useIdentity, useLogout } from '@/features/auth'
import { NotificationBell } from '@/features/notifications'
import { RealtimeUpdates } from '@/features/realtime'
import { ApiError } from '@/shared/api/client'
import { hasPermission } from '@/shared/lib/permissions'
import { IconButton } from '@/shared/ui/icon-button'
import { ErrorNotice, QueryState } from '@/shared/ui/page'
import { navigation } from './navigation'
import { usePreferences } from './store'

function Navigation({ onNavigate, collapsed = false }: { onNavigate?: () => void; collapsed?: boolean }) {
  const identity = useIdentity()
  const location = useLocation()
  const navigate = useNavigate()
  const items = navigation.filter(item => hasPermission(identity.data?.permissions ?? [], item.permission))
  const selected = items.find(item => [item.path, ...(item.aliases ?? [])].some(path => location.pathname.startsWith(path)))?.path ?? ''
  return <Menu selectedKeys={[selected]} collapse={collapsed} onClickMenuItem={path => { void navigate(path); onNavigate?.() }}>
    {[...new Set(items.map(item => item.group))].map(group => <Menu.ItemGroup title={collapsed ? undefined : group} key={group}>{items.filter(item => item.group === group).map(item => <Menu.Item key={item.path}>{item.icon}{item.label}</Menu.Item>)}</Menu.ItemGroup>)}
  </Menu>
}

export function ConsoleLayout() {
  const navigate = useNavigate()
  const identity = useIdentity()
  const logout = useLogout()
  const { collapsed, theme, toggleSidebar, toggleTheme } = usePreferences()
  const [mobileOpen, setMobileOpen] = useState(false)
  useEffect(() => { document.body.setAttribute('arco-theme', theme) }, [theme])
  if (identity.error instanceof ApiError && identity.error.status === 401) return <Navigate to="/login" replace />
  return <QueryState loading={identity.isPending} error={identity.error} retry={() => void identity.refetch()}>
    <div className={`console${collapsed ? ' console--collapsed' : ''}`}>
      <aside className="sidebar"><Link to="/catalog" className="brand"><img src="/favicon.svg" alt="" width={30} height={30} />{!collapsed && <span>Access Gateway</span>}</Link><Navigation collapsed={collapsed} /><div className="sidebar-footer"><IconButton label={collapsed ? '展开导航' : '收起导航'} icon={collapsed ? <IconMenuUnfold /> : <IconMenuFold />} onClick={toggleSidebar} />{!collapsed && <span>访问控制台</span>}</div></aside>
      <div className="workspace"><header className="topbar"><div className="topbar-left"><span className="mobile-menu"><IconButton label="打开导航" icon={<IconMenuUnfold />} onClick={() => setMobileOpen(true)} /></span><span>工作台</span></div>
        <Space><IconButton label={theme === 'light' ? '切换深色主题' : '切换浅色主题'} icon={theme === 'light' ? <IconMoon /> : <IconSun />} onClick={toggleTheme} />{identity.data && <NotificationBell key={identity.data.user_id} userID={identity.data.user_id} />}<IconButton label="账号设置" icon={<IconUser />} onClick={() => void navigate('/account')} /><Button className="logout-button" type="text" icon={<IconExport />} aria-label="退出登录" loading={logout.isPending} onClick={() => logout.mutate()}><span className="logout-label">退出</span></Button></Space>
      </header><ErrorNotice error={logout.error} />{identity.data && <RealtimeUpdates key={identity.data.user_id} userID={identity.data.user_id} />}<main id="main-content" className="main-content"><Outlet /></main></div>
    </div>
    <Drawer visible={mobileOpen} title="Access Gateway" placement="left" width={264} footer={null} onCancel={() => setMobileOpen(false)}><Navigation onNavigate={() => setMobileOpen(false)} /></Drawer>
  </QueryState>
}
