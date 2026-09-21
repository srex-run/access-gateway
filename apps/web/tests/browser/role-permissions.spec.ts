import { expect, test } from '@playwright/test'
import type { Page } from '@playwright/test'

const userID = '11111111-1111-4111-8111-111111111111'
const catalog = [
  { key: 'directory:read', name: '浏览资产' },
  { key: 'request:manage', name: '访问申请' },
  { key: 'approval:manage', name: '处理审批' },
  { key: 'session:manage', name: '个人会话' },
  { key: 'catalog:manage', name: '资产管理' },
  { key: 'audit:read', name: '查看审计' },
  { key: 'session:override', name: '强制回收' },
  { key: 'role:manage', name: '授权管理' },
  { key: 'user:read', name: '用户目录' },
  { key: 'user:manage', name: '用户管理' },
  { key: 'workflow:manage', name: '审批流程管理' },
].map(item => ({ ...item, description: `${item.name}说明` }))

interface RoleFixture { name: string; description: string; permissions: string[]; labels: Record<string, string>; enabled: boolean; built_in: boolean; revision: number }

async function mockRoles(page: Page, roles: RoleFixture[] = [], permissions = catalog.map(item => item.key)) {
  const submitted: RoleFixture[] = []
  await page.route('**/api/v1/**', async route => {
    const path = new URL(route.request().url()).pathname.replace('/api/v1', '')
    if (path === '/auth/me') return route.fulfill({ json: { user_id: userID, permissions } })
    if (path === '/admin/permissions') return route.fulfill({ json: catalog })
    if (path === '/admin/roles') {
      if (route.request().method() === 'POST') {
        const role = route.request().postDataJSON() as RoleFixture
        submitted.push(role)
        return route.fulfill({ json: { ...role, revision: role.revision + 1 } })
      }
      return route.fulfill({ json: roles })
    }
    return route.fulfill({ json: [] })
  })
  return submitted
}

function menu(page: Page, title: string) {
  return page.getByRole('treeitem').filter({ has: page.locator('.permission-tree-name').filter({ hasText: new RegExp(`^${title}$`) }) })
}

test('new role follows sidebar order, synchronizes shared permissions and submits only permission keys', async ({ page }, testInfo) => {
  const submitted = await mockRoles(page)
  await page.goto('/admin/role-definitions/create')
  await expect(page.getByRole('heading', { name: '角色配置' })).toBeVisible()
  const groups = await page.locator('.sidebar .arco-menu-item-group-title').allTextContents()
  const menus = await page.locator('.sidebar .arco-menu-item').allTextContents()
  await expect(page.locator('.permission-tree-name')).toHaveText([
    groups[0]!, ...menus.slice(0, 2), groups[1]!, ...menus.slice(2, 5), groups[2]!, ...menus.slice(5),
  ])
  await expect(page.getByRole('treeitem')).toHaveCount(groups.length + menus.length)
  await expect(page.locator('.permission-tree .arco-tree-node-disabled-selectable')).toHaveCount(0)
  await page.getByLabel('角色名称', { exact: true }).fill('support_operator')
  await menu(page, '系统设置').locator('.permission-tree-name').click()
  await expect(menu(page, '角色与权限').getByRole('checkbox')).toBeChecked()
  await menu(page, '系统设置').getByRole('button', { name: '系统设置权限说明', exact: true }).click()
  await expect(menu(page, '系统设置').getByRole('checkbox')).toBeChecked()
  await page.keyboard.press('Escape')
  await expect(page.getByText('已选 1 项权限', { exact: true })).toBeVisible()
  await menu(page, '角色与权限').getByRole('checkbox').uncheck()
  await expect(menu(page, '系统设置').getByRole('checkbox')).not.toBeChecked()
  await menu(page, '用户中心').getByRole('checkbox').check()
  await page.getByRole('button', { name: '展开全部', exact: true }).click()
  await expect(menu(page, '用户中心').getByRole('checkbox')).toBeChecked()
  await expect(menu(page, '强制回收').getByRole('checkbox')).toBeEnabled()
  await menu(page, '安全管理').getByRole('checkbox').check()
  await expect(menu(page, '强制回收').getByRole('checkbox')).toBeChecked()
  await expect(page.getByText('已选 6 项权限', { exact: true })).toBeVisible()
  await expect(menu(page, '访问审批').locator('.arco-checkbox')).toHaveClass(/arco-checkbox-indeterminate/)
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
  await page.screenshot({ path: testInfo.outputPath('role-permission-tree.png'), fullPage: true })
  await page.getByRole('button', { name: '保存', exact: true }).click()
  await expect.poll(() => submitted.length).toBe(1)
  expect(submitted[0]!.permissions.slice().sort()).toEqual(['audit:read', 'role:manage', 'session:manage', 'session:override', 'user:manage', 'user:read'])
  await expect(page).toHaveURL('/admin/roles')
})

test('editing keeps existing selections and collapsed branches when a linked permission changes', async ({ page }) => {
  const existing: RoleFixture = { name: 'custom_reviewer', description: '审核员', permissions: ['approval:manage', 'role:manage'], labels: { team: 'ops' }, enabled: true, built_in: false, revision: 3 }
  const submitted = await mockRoles(page, [existing])
  await page.goto('/admin/role-definitions/custom_reviewer/edit')
  await expect(menu(page, '访问审批').locator('.arco-checkbox')).toHaveClass(/arco-checkbox-indeterminate/)
  await expect(menu(page, '角色与权限').getByRole('checkbox')).toBeChecked()
  await expect(menu(page, '系统设置').getByRole('checkbox')).toBeChecked()
  await page.getByRole('button', { name: '收起全部', exact: true }).click()
  await expect(page.getByRole('treeitem')).toHaveCount(3)
  await menu(page, '平台管理').locator('.arco-tree-node-switcher').click()
  await menu(page, '系统设置').getByRole('checkbox').uncheck()
  await expect(menu(page, '安全管理')).toHaveAttribute('aria-expanded', 'false')
  await expect(menu(page, '访问管理')).toHaveAttribute('aria-expanded', 'false')
  await page.getByRole('button', { name: '保存', exact: true }).click()
  await expect.poll(() => submitted.length).toBe(1)
  expect(submitted[0]).toEqual({ ...existing, permissions: ['approval:manage'] })
})

test('a failed permission catalog can be retried without presenting an empty role form', async ({ page }) => {
  await mockRoles(page)
  await page.route('**/api/v1/admin/permissions', route => route.fulfill({ status: 403, json: { error: 'forbidden' } }))
  await page.goto('/admin/role-definitions/create')
  await expect(page.getByRole('button', { name: '保存', exact: true })).toHaveCount(0)
  await expect(page.getByRole('button', { name: '重试', exact: true })).toBeVisible()
  await page.unroute('**/api/v1/admin/permissions')
  await page.getByRole('button', { name: '重试', exact: true }).click()
  await expect(menu(page, '用户中心')).toBeVisible()
})

test('audit access agrees with its menu and page guard while ordinary users have no pending approval tab', async ({ page }) => {
  await mockRoles(page, [], ['audit:read'])
  await page.goto('/audit')
  await expect(page.getByRole('heading', { name: '审计日志', exact: true })).toBeVisible()
  await expect(page.getByRole('tab', { name: '操作日志', exact: true })).toBeVisible()
  await expect(page.locator('.sidebar .arco-menu-item')).toHaveText(['访问审批', '审计日志'])
  await page.route('**/api/v1/auth/me', route => route.fulfill({ json: { user_id: userID, permissions: ['directory:read', 'request:manage', 'session:manage'] } }))
  await page.goto('/approvals')
  await expect(page.getByRole('tab', { name: '待审批', exact: true })).toHaveCount(0)
  await expect(page.getByRole('tab', { name: '我的申请', exact: true })).toBeVisible()
})

test('built-in roles open the editor and keep their identity when saving', async ({ page }) => {
  const baseline: RoleFixture = { name: 'user', description: '普通用户', permissions: ['directory:read', 'request:manage', 'session:manage'], labels: { 'access-gateway.io/role': 'user' }, enabled: true, built_in: true, revision: 2 }
  const submitted = await mockRoles(page, [baseline])
  await page.goto('/admin/roles')
  await page.getByRole('button', { name: '编辑角色 user', exact: true }).click()
  await expect(page.getByLabel('角色名称', { exact: true })).toBeDisabled()
  await expect(page.getByRole('switch')).toBeDisabled()
  await menu(page, '资产目录').getByRole('checkbox').uncheck()
  await page.getByLabel('描述', { exact: true }).fill('普通访问用户')
  await page.getByRole('button', { name: '保存', exact: true }).click()
  await expect.poll(() => submitted.length).toBe(1)
  expect(submitted[0]).toEqual({ ...baseline, description: '普通访问用户', permissions: ['request:manage', 'session:manage'] })
})

test('administrator accounts have an explicit user edit action', async ({ page }) => {
  await mockRoles(page)
  const admin = { id: userID, nickname: 'Administrator', username: 'admin', email: '', department: '', status: 'active', labels: {}, revision: 1, roles: [{ name: 'admin' }], role_grants: [], permissions: catalog.map(item => item.key), can_edit: true, can_label: true }
  await page.route('**/api/v1/admin/users?*', route => route.fulfill({ json: [admin] }))
  await page.route(`**/api/v1/admin/users/${userID}`, route => route.fulfill({ json: admin }))
  await page.goto('/admin/users')
  await page.getByRole('button', { name: '编辑用户 Administrator', exact: true }).click()
  await expect(page.getByLabel('昵称', { exact: true })).toHaveValue('Administrator')
  await expect(page.getByRole('button', { name: '保存', exact: true })).toBeVisible()
})

test('the built-in auditor remains editable and can be disabled', async ({ page }) => {
  const auditor: RoleFixture = { name: 'auditor', description: '审计员', permissions: ['audit:read'], labels: { 'access-gateway.io/role': 'auditor' }, enabled: true, built_in: true, revision: 3 }
  const submitted = await mockRoles(page, [auditor])
  await page.goto('/admin/roles')
  await page.getByRole('button', { name: '编辑角色 auditor', exact: true }).click()
  await expect(page.getByLabel('角色名称', { exact: true })).toBeDisabled()
  await expect(page.getByRole('switch')).toBeEnabled()
  await page.getByRole('switch').click()
  await page.getByRole('button', { name: '保存', exact: true }).click()
  await expect.poll(() => submitted.length).toBe(1)
  expect(submitted[0]).toEqual({ ...auditor, enabled: false })
})
