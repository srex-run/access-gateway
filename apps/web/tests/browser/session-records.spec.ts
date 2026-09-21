import { expect, test } from '@playwright/test'
import { sessionRecordFixture } from './session-record-fixture'

const sessionID = '11111111-1111-4111-8111-111111111111'
const base = sessionRecordFixture({ id: sessionID, request_id: 'request-1', status: 'running', connection_mode: 'audit', gateway_endpoint: '127.0.0.1:20000', target_account: 'root', target_port: 33306, created_at: '2026-09-11T14:44:00Z' })

test('session records connect applicant, approver, failed login and operations', async ({ page }, testInfo) => {
  const errors: string[] = []
  const recordQueries: URLSearchParams[] = []
  page.on('pageerror', error => errors.push(error.message))
  const trace = [
    { id: 'op-2', stage: 'operation', event_type: 'query', occurred_at: '2026-09-11T14:51:00Z', actual_account: 'root', account_verified: true, result: 'success', operation: 'SELECT ? FROM payments WHERE payment_id = ?', connection_id: 'connection-2', duration_ms: 83, protocol: 'mysql' },
    { id: 'op-1', stage: 'operation', event_type: 'query', occurred_at: '2026-09-11T14:50:00Z', actual_account: 'root', account_verified: true, result: 'success', operation: 'SELECT ? FROM payments WHERE payment_id = ?', connection_id: 'connection-2', duration_ms: 4, protocol: 'mysql' },
    { id: 'fail-1', stage: 'connection', event_type: 'disconnected', occurred_at: '2026-09-11T14:48:00Z', result: 'failure', reason: 'application_identity_rejected', source_ip: '127.0.0.1', backend_source_ip: '172.20.0.1', connection_id: 'connection-1' },
    { id: 'tcp-1', stage: 'connection', event_type: 'backend_connected', occurred_at: '2026-09-11T14:47:00Z', result: 'success', source_ip: '127.0.0.1', connection_id: 'connection-1' },
    { id: 'approval-1', stage: 'approval', event_type: 'approval.approved', occurred_at: '2026-09-11T14:42:00Z', actor_name: '审批人乙', result: 'approved' },
    { id: 'request-1', stage: 'request', event_type: 'request.created', occurred_at: '2026-09-11T14:40:00Z', actor_name: '申请人甲', reason: '排查付款失败' },
  ]
  await page.route('**/api/v1/**', route => {
    const url = new URL(route.request().url())
    if (url.pathname.endsWith('/auth/me')) return route.fulfill({ json: { user_id: 'approver', permissions: ['approval:manage'] } })
    if (url.pathname === '/api/v1/session-records') {
      recordQueries.push(url.searchParams)
      return route.fulfill({ json: [base] })
    }
    if (url.pathname.endsWith('/trace')) {
      const stage = url.searchParams.get('stage')
      const filtered = trace.filter(event => !stage || event.stage === stage)
      const offset = Number(url.searchParams.get('offset') || 0), limit = Number(url.searchParams.get('limit') || 11)
      return route.fulfill({ json: filtered.slice(offset, offset + limit) })
    }
    if (url.pathname.endsWith(sessionID)) return route.fulfill({ json: { ...base, can_close: false, evidence: { verified_accounts: ['root'], operation_count: 2, connection_count: 2, failed_connections: 1, context: { accounts: [{ name: 'root', verified: true }], protocols: ['mysql'], backend_sources: [{ ip: '172.20.0.1', port: 59866 }], client_sources: ['127.0.0.1'] } } } })
    return route.fulfill({ json: [] })
  })
  await page.goto('/sessions')
  await expect(page).toHaveURL(/\/approvals\?tab=sessions/)
  await expect(page.getByRole('heading', { name: '访问审批' })).toBeVisible()
  await expect(page.getByText('申请人甲', { exact: true })).toBeVisible()
  await page.getByLabel('搜索会话').fill('payments')
  await page.getByLabel('搜索会话').press('Enter')
  await expect.poll(() => recordQueries.at(-1)?.get('search')).toBe('payments')
  await page.locator(`a[href="/sessions/${sessionID}"]`).click()
  await expect(page.getByText('审批人乙', { exact: true })).toBeVisible()
  await expect(page.getByText('目标账号认证失败 (application_identity_rejected)')).toBeVisible()
  await expect(page.getByText('172.20.0.1:59866', { exact: true })).toBeVisible()
  await expect(page.getByText('目标 TCP 已连接', { exact: true })).toBeVisible()
  await expect(page.getByText('SELECT ? FROM payments WHERE payment_id = ?', { exact: true })).toHaveCount(2)
  await expect(page.getByText('root · 已验证', { exact: true })).toHaveCount(1)
  await expect(page.getByText('mysql', { exact: true })).toHaveCount(1)
  await expect(page.getByText('83 ms', { exact: true })).toBeVisible()
  await expect(page.getByText('4 ms', { exact: true })).toBeVisible()
  await expect(page.locator('.session-record-summary, .arco-timeline')).toHaveCount(0)
  expect(await page.locator('.session-trace tbody > tr').evaluateAll(rows => rows.every(row => row.getBoundingClientRect().height <= 36))).toBe(true)
  await expect(page.getByRole('button', { name: '结束会话' })).toHaveCount(0)
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
  await page.screenshot({ path: testInfo.outputPath('session-record-trace.png'), fullPage: true })
  await page.getByLabel('轨迹阶段', { exact: true }).click()
  await page.getByRole('option', { name: '连接', exact: true }).click()
  await expect(page.getByText('root · 已验证', { exact: true })).toHaveCount(1)
  await expect(page.getByText('172.20.0.1:59866', { exact: true })).toHaveCount(1)
  await expect(page.getByText('目标账号认证失败 (application_identity_rejected)')).toBeVisible()
  await expect(page.getByText('SELECT ? FROM payments WHERE payment_id = ?', { exact: true })).toHaveCount(0)
  await page.getByRole('tab', { name: '申请与审批', exact: true }).click()
  await expect(page.getByText('同意排查', { exact: true })).toBeVisible()
  await expect(page.getByText('排查付款失败', { exact: true })).toBeVisible()
  await page.getByRole('tab', { name: '连接配置', exact: true }).click()
  await expect(page.getByText('127.0.0.1:20000', { exact: true })).toBeVisible()
  expect(errors).toEqual([])
})

test('a running session with failed authentication has no verified account', async ({ page }) => {
  await page.route('**/api/v1/auth/me', route => route.fulfill({ json: { user_id: 'auditor', permissions: ['audit:read'] } }))
  await page.route(`**/api/v1/session-records/${sessionID}`, route => route.fulfill({ json: { ...base, can_close: false, evidence: { verified_accounts: [], operation_count: 0, connection_count: 1, failed_connections: 1 } } }))
  await page.route(`**/api/v1/session-records/${sessionID}/trace?*`, route => route.fulfill({ json: [] }))
  await page.goto(`/sessions/${sessionID}`)
  await expect(page.getByText('暂无已验证账号', { exact: true })).toBeVisible()
  await expect(page.getByText('1 / 1', { exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: '结束会话' })).toHaveCount(0)
})
