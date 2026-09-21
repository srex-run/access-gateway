import { expect, test } from '@playwright/test'
import type { Page } from '@playwright/test'
import { sessionRecordFixture } from './session-record-fixture'

const regionID = '11111111-1111-4111-8111-111111111111'
const assetID = '22222222-2222-4222-8222-222222222222'
const requestID = '33333333-3333-4333-8333-333333333333'
const userID = '44444444-4444-4444-8444-444444444444'
const sessionID = '55555555-5555-4555-8555-555555555555'
const allPermissions = ['directory:read', 'request:manage', 'approval:manage', 'session:manage', 'catalog:manage', 'audit:read', 'session:override', 'role:manage']
const exampleRequest = { id: requestID, asset_id: assetID, applicant_id: userID, target_port: 5432, source_ip: '192.0.2.10', target_account: 'reader', reason: '排查订单数据异常', emergency: false, ttl_seconds: 3600, status: 'approved', idempotency_key: 'example', created_at: '2026-09-09T06:00:00Z', updated_at: '2026-09-09T06:00:00Z' }

async function mockAPI(page: Page, permissions = allPermissions) {
  await page.route('**/api/v1/**', async route => {
    const url = new URL(route.request().url())
    const path = url.pathname.replace('/api/v1', '')
    let body: unknown = []
    if (path === '/auth/me') body = { user_id: userID, permissions }
    else if (path === '/access-options') body = { client_access_enabled: true }
    else if (path === '/regions') body = [{ id: regionID, name: '华东生产区', code: 'cn-east-prod', status: 'enabled' }]
    else if (path === `/regions/${regionID}/assets`) body = [
      { id: assetID, region_id: regionID, name: 'orders-postgres-primary', asset_type: 'PostgreSQL', risk_level: 'sensitive', max_ttl_seconds: 3600, status: 'enabled' },
      { id: '66666666-6666-4666-8666-666666666666', region_id: regionID, name: 'payments-redis', asset_type: 'Redis', risk_level: 'critical', max_ttl_seconds: 1800, status: 'enabled' },
    ]
    else if (path === `/assets/${assetID}/ports`) body = [{ id: 'port', asset_id: assetID, port: 5432, protocol: 'tcp' }]
    else if (path === '/access-requests') body = [exampleRequest]
    else if (path === `/access-requests/${requestID}`) body = exampleRequest
    else if (path === `/access-requests/${requestID}/record` || path === `/session-records/${sessionID}`) body = sessionRecordFixture({ id: sessionID, request_id: requestID, gateway_id: regionID, status: 'running', connection_mode: 'native', source_ip: '203.0.113.10', target_account: 'readonly', gateway_host: 'gateway.example.com', gateway_port: 32001, gateway_endpoint: 'gateway.example.com:32001', target_port: 5432 })
    else if (path === `/access-requests/${requestID}/session` || path === `/sessions/${sessionID}`) body = { id: sessionID, request_id: requestID, gateway_id: regionID, status: 'running', connection_mode: 'native', source_ip: '203.0.113.10', target_account: 'readonly', gateway_host: 'gateway.example.com', gateway_port: 32001, gateway_endpoint: 'gateway.example.com:32001', target_port: 5432, started_at: '2026-09-09T06:10:00Z', expires_at: '2026-09-09T07:10:00Z', created_at: '2026-09-09T06:10:00Z', updated_at: '2026-09-09T06:10:00Z' }
    else if (path === '/approvals/pending') body = [{ id: '77777777-7777-4777-8777-777777777777', request_id: requestID, approver_id: userID, approval_level: 1, created_at: '2026-09-09T06:00:00Z' }]
    await route.fulfill({ json: body })
  })
}

test('authenticated catalog renders, filters, and fits the viewport', async ({ page }, testInfo) => {
  const errors: string[] = []
  page.on('pageerror', error => errors.push(error.message))
  await mockAPI(page)
  await page.goto('/catalog')
  await expect(page.getByRole('heading', { name: '资产目录' })).toBeVisible()
  await expect(page.getByText('orders-postgres-primary')).toBeVisible()
  await page.getByLabel('搜索资产').fill('orders')
  await expect(page.getByText('payments-redis')).toHaveCount(0)
  await page.getByLabel('搜索资产').fill('')
  if (testInfo.project.name === 'mobile') {
    await page.getByRole('button', { name: '打开导航' }).click()
    await expect(page.getByText('访问审批')).toBeVisible()
    await page.keyboard.press('Escape')
  }
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
  await page.screenshot({ path: testInfo.outputPath('catalog.png'), fullPage: true })
  expect(errors).toEqual([])
})

test('read-only users cannot enter admin routes', async ({ page }) => {
  await mockAPI(page, ['directory:read', 'request:manage', 'session:manage'])
  await page.goto('/admin/roles')
  await expect(page.getByText('无权访问此页面')).toBeVisible()
  await expect(page.getByRole('heading', { name: '角色授权' })).toHaveCount(0)
})

test('ordinary users have no pending approval tab even with a direct tab URL', async ({ page }) => {
  await mockAPI(page, ['directory:read', 'request:manage', 'session:manage'])
  let pendingQueries = 0
  await page.route('**/api/v1/approvals/pending*', route => { pendingQueries++; return route.fulfill({ status: 403, json: { error: 'forbidden' } }) })
  await page.goto('/approvals?tab=pending')
  await expect(page.getByRole('tab', { name: '待审批', exact: true })).toHaveCount(0)
  await expect(page.getByRole('tab', { name: '会话记录', exact: true })).toBeVisible()
  await page.getByRole('tab', { name: '我的申请', exact: true }).click()
  await expect(page.getByText(exampleRequest.reason, { exact: true })).toBeVisible()
  expect(pendingQueries).toBe(0)
})

test('personal session audit excludes global audit controls', async ({ page }, testInfo) => {
  await mockAPI(page, ['directory:read', 'request:manage', 'session:manage'])
  const queries: URLSearchParams[] = []
  let globalQueries = 0
  await page.route('**/api/v1/audit-events*', route => { globalQueries++; return route.fulfill({ json: [] }) })
  await page.route('**/api/v1/session-records*', route => {
    queries.push(new URL(route.request().url()).searchParams)
    return route.fulfill({ json: [{ id: sessionID, applicant_id: userID, applicant_name: '申请人', asset_id: assetID, asset_name: 'mysql', status: 'running', target_port: 3306, target_account: 'root', created_at: '2026-09-11T06:00:00Z', expires_at: '2026-09-11T07:00:00Z' }] })
  })
  await page.goto(`/audit?view=operations&session_id=${sessionID}`)
  await expect(page.getByRole('tab', { name: '会话记录', exact: true })).toBeVisible()
  await expect(page.getByText('mysql', { exact: true })).toBeVisible()
  expect(queries.at(-1)?.get('search')).toBe(sessionID)
  await page.goto(`/audit?view=access&subject_user_id=${regionID}`)
  await expect(page.getByRole('tab', { name: '会话记录', exact: true })).toBeVisible()
  await expect(page.getByRole('tab', { name: '操作日志' })).toHaveCount(0)
  await expect(page.getByRole('tab', { name: '会话命令', exact: true })).toHaveCount(0)
  await expect(page.getByRole('tab', { name: '未关联命令', exact: true })).toHaveCount(0)
  await expect(page.getByText('mysql', { exact: true })).toBeVisible()
  expect(queries.at(-1)?.get('subject_user_id')).toBeNull()
  await expect(page.getByLabel('用户 ID', { exact: true })).toHaveCount(0)
  expect(globalQueries).toBe(0)
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
  await page.screenshot({ path: testInfo.outputPath('personal-session-audit.png'), fullPage: true })
})

test('administrators can search session audit by applicant', async ({ page }, testInfo) => {
  await mockAPI(page)
  const queries: URLSearchParams[] = []
  await page.route('**/api/v1/session-records*', route => {
    queries.push(new URL(route.request().url()).searchParams)
    return route.fulfill({ json: [] })
  })
  await page.goto('/audit?view=sessions')
  await expect(page.getByRole('tab', { name: '会话记录', exact: true })).toBeVisible()
  await expect(page.getByRole('tab', { name: '操作日志' })).toBeVisible()
  await expect.poll(() => queries.length).toBeGreaterThan(0)
  expect(queries.at(-1)?.get('subject_user_id')).toBeNull()
  await page.getByLabel('搜索会话', { exact: true }).fill(userID)
  await page.getByLabel('搜索会话', { exact: true }).press('Enter')
  await expect.poll(() => queries.at(-1)?.get('search')).toBe(userID)
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
  await page.screenshot({ path: testInfo.outputPath('admin-session-audit.png'), fullPage: true })
})

test('anonymous users see Feishu login and backend failures remain visible', async ({ page }) => {
  await page.route('**/api/v1/auth/providers', route => route.fulfill({ json: [{ id: 'feishu', name: '飞书', kind: 'redirect' }] }))
  await page.route('**/api/v1/auth/me', route => route.fulfill({ status: 401, json: { error: 'authentication required' } }))
  await page.goto('/requests')
  await expect(page.getByRole('link', { name: '飞书登录' })).toBeVisible()
  await page.route('**/api/v1/auth/me', route => route.fulfill({ status: 502, json: { error: 'unavailable' } }))
  await page.reload()
  await expect(page.getByText('暂时无法连接服务，请稍后重试。')).toBeVisible()
})

test('request edits are guarded and unchanged retries reuse the idempotency key', async ({ page }) => {
  await mockAPI(page)
  const keys: string[] = []
  await page.route('**/api/v1/access-requests', async route => {
    if (route.request().method() !== 'POST') { await route.fallback(); return }
    keys.push(route.request().headers()['idempotency-key'] ?? '')
    if (keys.length === 1) await route.fulfill({ status: 502, json: { error: 'unavailable' } })
    else await route.fulfill({ status: 201, json: { ...exampleRequest, status: 'pending_approval' } })
  })
  await page.goto(`/requests/new?region=${regionID}&asset=${assetID}`)
  await expect(page.getByLabel('目标端口', { exact: true })).toContainText('5432 / TCP')
  await page.getByLabel('目标账号', { exact: true }).fill('reader')
  await page.getByRole('checkbox', { name: '同时启用本地客户端访问' }).check()
  await page.getByLabel('来源 IP', { exact: true }).fill('192.0.2.10')
  await page.getByLabel('申请原因', { exact: true }).fill('排查订单数据异常')
  await page.getByRole('button', { name: '取消', exact: true }).click()
  await expect(page.getByText('放弃未保存的修改？')).toBeVisible()
  await page.getByRole('button', { name: '继续编辑' }).click()
  await page.getByRole('button', { name: '提交申请' }).click()
  await expect(page.getByText('暂时无法连接服务，请稍后重试。')).toBeVisible()
  await page.getByRole('button', { name: '提交申请' }).click()
  await expect(page.getByRole('heading', { name: '申请详情' })).toBeVisible()
  expect(keys).toHaveLength(2)
  expect(keys[0]).not.toBe('')
  expect(keys[0]).toBe(keys[1])
})

test('session details render actual connection fields without token requests', async ({ page }, testInfo) => {
  const tokenRequests: string[] = []
  page.on('request', req => { if (req.url().endsWith('/token')) tokenRequests.push(req.url()) })
  await mockAPI(page)
  await page.goto(`/sessions/by-request/${requestID}`)
  await page.getByRole('tab', { name: '连接配置', exact: true }).click()
  await expect(page.getByText('gateway.example.com:32001')).toBeVisible()
  await expect(page.getByRole('button', { name: '结束会话' })).toBeVisible()
  await page.screenshot({ path: testInfo.outputPath('session.png'), fullPage: true })
  expect(tokenRequests).toEqual([])
})
