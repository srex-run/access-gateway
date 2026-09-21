import { expect, test } from '@playwright/test'
import type { Page } from '@playwright/test'

const region = '11111111-1111-4111-8111-111111111111'
const asset = '22222222-2222-4222-8222-222222222222'
const admin = '33333333-3333-4333-8333-333333333333'
const approver = '44444444-4444-4444-8444-444444444444'
const requestID = '55555555-5555-4555-8555-555555555555'
const allPermissions = ['directory:read', 'request:manage', 'session:manage', 'catalog:manage', 'role:manage']

async function setup(page: Page, permissions = allPermissions) {
  await page.route('**/api/v1/**', async route => {
    const path = new URL(route.request().url()).pathname.replace('/api/v1', '')
    let body: unknown = []
    if (path === '/auth/me') body = { user_id: admin, permissions }
    else if (path === '/access-options') body = { client_access_enabled: true }
    else if (path === '/regions') body = [{ id: region, name: '默认区域', status: 'enabled' }]
    else if (path === `/regions/${region}/assets` || path === '/admin/assets') body = [{ id: asset, region_id: region, name: 'orders-mysql', status: 'enabled', max_ttl_seconds: 3600 }]
    else if (path === `/assets/${asset}/ports`) body = [{ id: 'port', asset_id: asset, port: 3306, protocol: 'tcp' }]
    else if (path === `/assets/${asset}/workflow` || path === `/access-requests/${requestID}/workflow`) body = { snapshot: null, stages: [], approvals: [], current_level: 0, expires_at: null, status: 'preview', can_decide: false }
    else if (path === '/admin/users') body = [{ id: approver, nickname: '审批同事', username: 'approver', status: 'active', feishu_bound: false }]
    else if (path === `/assets/${asset}/approvers` || path === `/admin/assets/${asset}/approvers`) body = [{ id: 'approval', user_id: approver, name: '审批同事', username: 'approver', status: 'active', approval_level: 1, role: 'owner', feishu_bound: false }]
    else if (path === `/access-requests/${requestID}/session`) body = { id: 'session', request_id: requestID, status: 'running', connection_mode: 'native', gateway_endpoint: 'gateway.example:20003', gateway_host: 'gateway.example', gateway_port: 20003, target_port: 3306 }
    await route.fulfill({ json: body })
  })
}

test('administrator can create a test session with on-demand help', async ({ page }, testInfo) => {
  await setup(page)
  const bodies: Record<string, unknown>[] = []
  await page.route('**/api/v1/admin/access-tests', async route => {
    bodies.push(route.request().postDataJSON())
    await route.fulfill({ status: 201, json: { id: requestID, status: 'approved', approval_mode: 'admin_test' } })
  })
  await page.goto(`/requests/new?region=${region}&mode=test`)
  await page.getByLabel('资产', { exact: true }).click()
  await page.getByRole('option', { name: 'orders-mysql', exact: true }).click()
  await expect(page.getByRole('checkbox', { name: '管理员测试（免审批）' })).toBeChecked()
  await expect(page.getByText('资产需配置 TCP 端口并关联审批流程', { exact: false })).toHaveCount(0)
  await page.getByRole('button', { name: '访问申请说明' }).click()
  await expect(page.getByText('资产需配置 TCP 端口并关联审批流程', { exact: false })).toBeVisible()
  expect(bodies).toHaveLength(0)
  await page.getByRole('button', { name: '访问申请说明' }).click()
  await expect(page.getByLabel('目标端口', { exact: true })).toContainText('3306 / TCP')
  await page.getByLabel('目标账号', { exact: true }).fill('readonly')
  await page.getByRole('checkbox', { name: '同时启用本地客户端访问' }).check()
  await page.getByLabel('来源 IP', { exact: true }).fill('127.0.0.1')
  await page.getByLabel('申请原因', { exact: true }).fill('验证 MySQL 加密连接')
  await expect(page.getByText('10 分钟', { exact: true })).toBeVisible()
  await page.screenshot({ path: testInfo.outputPath('admin-test-request.png'), fullPage: true })
  await page.getByRole('button', { name: '创建测试会话' }).click()
  await expect(page.getByText('gateway.example:20003', { exact: true })).toBeVisible()
  expect(bodies).toHaveLength(1)
  expect(bodies[0]).toMatchObject({ target_port: 3306, ttl_seconds: 600, source_ip: '127.0.0.1', emergency: false })
  expect(bodies[0]).not.toHaveProperty('approval_mode')
  expect(bodies[0]).not.toHaveProperty('requested_start_at')
})

test('ordinary access chooses a duration after approval and urgent access submits without a ticket', async ({ page }) => {
  await setup(page, ['directory:read', 'request:manage', 'session:manage'])
  const bodies: Record<string, unknown>[] = []
  await page.route('**/api/v1/access-requests', async route => {
    bodies.push(route.request().postDataJSON())
    await route.fulfill({ status: 201, json: { ...bodies[0], id: requestID, status: 'pending_approval' } })
  })
  await page.route(`**/api/v1/access-requests/${requestID}`, route => route.fulfill({ json: { ...bodies[0], id: requestID, status: 'pending_approval' } }))
  await page.goto(`/requests/new?region=${region}&asset=${asset}`)
  await expect(page.getByLabel('预约开始时间', { exact: true })).toHaveCount(0)
  await page.getByLabel('会话有效期', { exact: true }).click()
  await page.getByRole('option', { name: '30 分钟', exact: true }).click()
  await expect(page.getByLabel('目标端口', { exact: true })).toContainText('3306 / TCP')
  await page.getByLabel('目标账号', { exact: true }).fill('readonly')
  await page.getByRole('checkbox', { name: '同时启用本地客户端访问' }).check()
  await page.getByLabel('来源 IP', { exact: true }).fill('127.0.0.1')
  await page.getByRole('checkbox', { name: '紧急访问（优先审批）' }).check()
  await expect(page.getByLabel('关联工单', { exact: true })).toHaveCount(0)
  await page.getByLabel('申请原因', { exact: true }).fill('处理生产故障')
  await page.getByRole('button', { name: '提交申请', exact: true }).click()
  await expect.poll(() => bodies.length).toBe(1)
  expect(bodies[0]).toMatchObject({ ttl_seconds: 1800, emergency: true, reason: '处理生产故障' })
  expect(bodies[0]).not.toHaveProperty('ticket_no')
  expect(bodies[0]).not.toHaveProperty('requested_start_at')
  await expect(page.getByText('紧急申请已在审批待办中优先展示，等待指定审批人处理。', { exact: true })).toBeVisible()
  await expect(page.getByText('关联工单', { exact: true })).toHaveCount(0)
})

test('audited ports require a target account before submitting and native ports keep it optional', async ({ page }) => {
  await setup(page, ['directory:read', 'request:manage', 'session:manage'])
  await page.route(`**/api/v1/assets/${asset}/ports`, route => route.fulfill({ json: [
    { id: 'audited', asset_id: asset, port: 3306, protocol: 'tcp', target_account_required: true },
    { id: 'native', asset_id: asset, port: 3307, protocol: 'tcp', target_account_required: false },
  ] }))
  let submissions = 0
  await page.route('**/api/v1/access-requests', route => {
    submissions++
    return route.fulfill({ status: 400, json: { error: 'test response' } })
  })
  await page.goto(`/requests/new?region=${region}&asset=${asset}`)
  await page.getByLabel('申请原因', { exact: true }).fill('验证账号必填状态')
  const account = page.getByLabel('目标账号', { exact: true })
  const accountField = page.locator('.arco-form-item').filter({ has: account })
  await page.getByLabel('目标端口', { exact: true }).click()
  await page.getByRole('option', { name: '3306 / TCP', exact: true }).click()
  await expect(account).toHaveAttribute('aria-required', 'true')
  await expect(accountField.locator('.arco-form-item-symbol')).toBeVisible()
  await page.getByRole('button', { name: '提交申请', exact: true }).click()
  await expect(page.getByText('请填写目标账号（登录资产的用户名）', { exact: true })).toBeVisible()
  expect(submissions).toBe(0)
  await account.fill('   ')
  await page.getByRole('button', { name: '提交申请', exact: true }).click()
  await expect(page.getByText('请填写目标账号（登录资产的用户名）', { exact: true })).toBeVisible()
  expect(submissions).toBe(0)
  await page.getByLabel('目标端口', { exact: true }).click()
  await page.getByRole('option', { name: '3307 / TCP', exact: true }).click()
  await expect(account).toHaveAttribute('aria-required', 'false')
  await expect(accountField.locator('.arco-form-item-symbol')).toHaveCount(0)
  await expect(page.getByText('请填写目标账号（登录资产的用户名）', { exact: true })).toHaveCount(0)
  await account.fill('')
  await page.getByRole('button', { name: '提交申请', exact: true }).click()
  await expect.poll(() => submissions).toBe(1)
})

test('account directory and asset approvers use names', async ({ page }) => {
  await setup(page)
  await page.goto('/admin/users')
  await expect(page.getByRole('heading', { name: '账户管理' })).toBeVisible()
  await expect(page.getByRole('cell', { name: '审批同事', exact: true })).toBeVisible()
  await expect(page.getByRole('link', { name: '添加账户' })).toBeVisible()
  await page.goto(`/admin/assets/${asset}?tab=approvers`)
  await expect(page.getByRole('cell', { name: '审批同事 (approver)', exact: true })).toBeVisible()
  await page.getByLabel('审批人', { exact: true }).click()
  await expect(page.getByRole('option', { name: '审批同事 (approver)' })).toBeVisible()
})

test('ordinary applicants see the assigned approver and cannot request test mode', async ({ page }) => {
  await setup(page, ['directory:read', 'request:manage', 'session:manage'])
  await page.goto(`/requests/new?region=${region}&asset=${asset}&mode=test`)
  await expect(page.getByRole('checkbox', { name: '管理员测试（免审批）' })).toHaveCount(0)
  await expect(page.getByText('审批同事 · 第 1 级')).toBeVisible()
  await expect(page.getByRole('button', { name: '提交申请' })).toBeVisible()
})
