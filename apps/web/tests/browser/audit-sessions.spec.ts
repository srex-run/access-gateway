import { expect, test } from '@playwright/test'
import type { Page } from '@playwright/test'
import { sessionRecordFixture } from './session-record-fixture'

const applicantID = '11111111-1111-4111-8111-111111111111'
const sessions = Array.from({ length: 12 }, (_, index) => ({
  id: `22222222-2222-4222-8222-${String(index + 1).padStart(12, '0')}`, request_id: 'request-1',
  applicant_id: applicantID, applicant_name: '申请人甲', asset_id: 'asset-1', asset_name: `mysql-${index + 1}`,
  target_port: 33306, target_account: 'root', status: 'closed', connection_mode: 'audit',
  created_at: '2026-09-12T00:00:00Z', expires_at: '2026-09-12T01:00:00Z',
}))

async function mockAudit(page: Page, admin = true) {
  const sessionQueries: URLSearchParams[] = [], legacyQueries: URLSearchParams[] = [], accessQueries: URLSearchParams[] = []
  await page.route('**/api/v1/**', route => {
    const url = new URL(route.request().url()), params = url.searchParams
    const offset = Number(params.get('offset') ?? 0), limit = Number(params.get('limit') ?? 10)
    if (url.pathname.endsWith('/auth/me')) return route.fulfill({ json: { user_id: applicantID, permissions: admin ? ['session:manage', 'audit:read'] : ['session:manage'] } })
    if (url.pathname.endsWith('/session-records')) {
      sessionQueries.push(params)
      const values = sessions.filter(session => (!params.get('search') || [session.id, session.asset_name].includes(params.get('search')!)) && (!params.get('status') || session.status === params.get('status')))
      return route.fulfill({ json: values.slice(offset, offset + limit) })
    }
    if (url.pathname.endsWith(`/session-records/${sessions[0].id}`)) return route.fulfill({ json: sessionRecordFixture(sessions[0]) })
    if (url.pathname.endsWith(`/session-records/${sessions[0].id}/trace`)) return route.fulfill({ json: [{ id: 'command-1', stage: 'operation', event_type: 'query', operation: 'SELECT ? FROM payments', protocol: 'mysql', actual_account: 'root', account_verified: true, result: 'success', occurred_at: '2026-09-12T00:15:00Z' }] })
    if (url.pathname.endsWith('/operation-audit-sessions') || url.pathname.endsWith('/operation-audit-events')) {
      legacyQueries.push(params)
      return route.fulfill({ json: [] })
    }
    if (url.pathname.endsWith('/audit-events')) {
      accessQueries.push(params)
      return route.fulfill({ json: Array.from({ length: 11 }, (_, index) => ({ id: `access-${index}`, event_type: 'asset.created', actor_type: 'admin', actor_id: applicantID, actor_name: index === 1 ? 'GitHub 用户' : 'Administrator', actor_username: index === 1 ? '' : 'admin', category: 'resources', action: 'create', label: '创建资产', created_at: '2026-09-12T00:00:00Z' })) })
    }
    return route.fulfill({ json: [] })
  })
  return { sessionQueries, legacyQueries, accessQueries }
}

test('audit reuses approval session records and opens commands in the session trace', async ({ page }, testInfo) => {
  const errors: string[] = []
  page.on('pageerror', error => errors.push(error.message))
  const { sessionQueries, legacyQueries } = await mockAudit(page)
  await page.goto('/approvals?tab=sessions')
  await expect(page.locator('tbody > tr')).toHaveCount(10)
  const columns = await page.getByRole('columnheader').allTextContents()
  await page.goto('/audit?view=sessions')
  await expect(page.locator('tbody > tr')).toHaveCount(10)
  expect(await page.getByRole('columnheader').allTextContents()).toEqual(columns)
  expect(sessionQueries.at(-1)?.get('limit')).toBe('11')
  await expect(page.getByRole('tab', { name: '会话命令', exact: true })).toHaveCount(0)
  await expect(page.getByRole('tab', { name: '未关联命令', exact: true })).toHaveCount(0)
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
  await page.screenshot({ path: testInfo.outputPath('audit-session-records.png'), fullPage: true })
  await page.getByRole('button', { name: '下一页', exact: true }).click()
  await expect(page.locator('tbody > tr')).toHaveCount(2)
  expect(sessionQueries.at(-1)?.get('offset')).toBe('10')
  await expect(page.getByRole('button', { name: '下一页', exact: true })).toBeDisabled()
  await page.getByLabel('搜索会话', { exact: true }).fill(sessions[0].asset_name)
  await page.getByLabel('搜索会话', { exact: true }).press('Enter')
  await expect(page.locator('tbody > tr')).toHaveCount(1)
  expect(sessionQueries.at(-1)?.get('offset')).toBe('0')
  expect(sessionQueries.at(-1)?.get('search')).toBe(sessions[0].asset_name)
  await page.locator(`a[href="/sessions/${sessions[0].id}"]`).click()
  await expect(page.getByRole('tab', { name: '访问轨迹', exact: true })).toBeVisible()
  await expect(page.getByText('SELECT ? FROM payments', { exact: true })).toBeVisible()
  expect(legacyQueries).toHaveLength(0)
  expect(errors).toEqual([])
})

test('legacy command audit tabs redirect to session records without querying removed views', async ({ page }) => {
  const { sessionQueries, legacyQueries, accessQueries } = await mockAudit(page, false)
  await page.goto(`/audit?view=operations&session_id=${sessions[0].id}`)
  await expect(page.getByRole('tab', { name: '会话记录', exact: true })).toHaveAttribute('aria-selected', 'true')
  await expect(page.locator('tbody > tr')).toHaveCount(1)
  expect(sessionQueries.at(-1)?.get('search')).toBe(sessions[0].id)
  await page.goto('/audit?view=unmatched')
  await expect(page).toHaveURL(/\/audit\?view=sessions$/)
  await expect(page.locator('tbody > tr')).toHaveCount(10)
  await expect(page.getByRole('tab', { name: '未关联命令', exact: true })).toHaveCount(0)
  await expect(page.getByRole('tab', { name: '会话命令', exact: true })).toHaveCount(0)
  await expect(page.getByRole('tab', { name: '操作日志', exact: true })).toHaveCount(0)
  expect(legacyQueries).toHaveLength(0)
  expect(accessQueries).toHaveLength(0)
})


test('platform operation log exposes business categories and mutation filters', async ({ page }) => {
  const { accessQueries } = await mockAudit(page)
  await page.goto('/audit')
  await expect(page.getByRole('tab', { name: '操作日志', exact: true })).toHaveAttribute('aria-selected', 'true')
  await expect(page.getByText('创建资产', { exact: true })).toHaveCount(10)
  await expect(page.getByRole('columnheader', { name: '用户名', exact: true })).toBeVisible()
  await expect(page.getByText('admin', { exact: true })).toHaveCount(9)
  await expect(page.getByText('GitHub 用户', { exact: true })).toBeVisible()
  await page.getByRole('button', { name: '筛选审计', exact: true }).click()
  await page.getByLabel('业务分类', { exact: true }).click()
  await page.getByRole('option', { name: '资源管理', exact: true }).click()
  await page.getByLabel('操作类型', { exact: true }).click()
  await page.getByRole('option', { name: '新增', exact: true }).click()
  await page.getByLabel('操作人 ID', { exact: true }).fill(applicantID)
  await page.getByRole('button', { name: '查询', exact: true }).click()
  await expect.poll(() => accessQueries.at(-1)?.get('category')).toBe('resources')
  expect(accessQueries.at(-1)?.get('action')).toBe('create')
  expect(accessQueries.at(-1)?.get('actor_id')).toBe(applicantID)
  expect(accessQueries.at(-1)?.get('subject_user_id')).toBeNull()
  expect(accessQueries.at(-1)?.get('offset')).toBe('0')
})
