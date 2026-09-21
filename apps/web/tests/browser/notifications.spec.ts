import { expect, test } from '@playwright/test'

test('notification bell shows persisted unread messages, updates read state and links to approvals', async ({ page }) => {
  const userID = '11111111-1111-4111-8111-111111111111'
  const requestID = '22222222-2222-4222-8222-222222222222'
  const notificationID = '33333333-3333-4333-8333-333333333333'
  let readAt: string | undefined
  let reads = 0
  await page.route('**/api/v1/**', async route => {
    const path = new URL(route.request().url()).pathname.replace('/api/v1', '')
    if (path === '/auth/me') return route.fulfill({ json: { user_id: userID, permissions: ['directory:read', 'request:manage', 'approval:manage'] } })
    if (path === `/notifications/${notificationID}/read` || path === '/notifications/read') {
      expect(route.request().method()).toBe('POST')
      reads++
      readAt = new Date().toISOString()
      return route.fulfill({ status: 204 })
    }
    if (path === '/notifications') return route.fulfill({ json: { items: [{ id: notificationID, event_type: 'approval_requested', title: '有访问申请待你审批', content: '生产数据库的访问申请已到「平台管理」节点，请及时处理。', request_id: requestID, created_at: '2026-09-15T02:00:00Z', read_at: readAt }], unread_count: readAt ? 0 : 1, has_more: false } })
    return route.fulfill({ json: [] })
  })
  await page.goto('/catalog')
  await expect(page.getByRole('button', { name: '站内通知，1 条未读', exact: true })).toBeVisible()
  await expect(page.getByText('有访问申请待你审批', { exact: true })).not.toBeVisible()
  await page.getByRole('button', { name: '站内通知，1 条未读', exact: true }).click()
  await expect(page.getByText('有访问申请待你审批', { exact: true })).toBeVisible()
  expect(reads).toBe(0)
  await expect(page.getByRole('link', { name: '查看详情', exact: true })).toHaveAttribute('href', `/requests/${requestID}`)
  await page.getByRole('button', { name: '全部标为已读', exact: true }).click()
  await expect(page.getByText('0 条未读', { exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: '全部标为已读', exact: true })).toBeDisabled()
  await page.getByRole('link', { name: '前往审批', exact: true }).click()
  await expect(page).toHaveURL(/\/approvals\?tab=pending$/)
  await page.reload()
  await expect(page.getByRole('button', { name: '站内通知', exact: true })).toBeVisible()
  await page.getByRole('button', { name: '站内通知', exact: true }).click()
  await expect(page.getByText('有访问申请待你审批', { exact: true })).toBeVisible()
  await expect(page.getByLabel('未读', { exact: true })).toHaveCount(0)
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
})

test('ordinary users can read their own result notifications', async ({ page }) => {
  const sessionID = '44444444-4444-4444-8444-444444444444'
  await page.route('**/api/v1/**', route => {
    const path = new URL(route.request().url()).pathname.replace('/api/v1', '')
    const body = path === '/auth/me' ? { user_id: 'user', permissions: ['directory:read', 'request:manage', 'session:manage'] }
      : path === '/notifications' ? { items: [{ id: 'message', event_type: 'session_ready', title: '访问会话已就绪', content: '数据库的访问会话已就绪。', request_id: 'request', session_id: sessionID, created_at: '2026-09-15T02:00:00Z' }], unread_count: 1, has_more: false } : []
    return route.fulfill({ json: body })
  })
  await page.goto('/catalog')
  await page.getByRole('button', { name: '站内通知，1 条未读', exact: true }).click()
  await expect(page.getByRole('link', { name: '查看详情', exact: true })).toHaveAttribute('href', `/sessions/${sessionID}`)
  await expect(page.getByRole('link', { name: '前往审批', exact: true })).toHaveCount(0)
})
