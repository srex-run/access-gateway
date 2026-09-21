import { expect, test } from '@playwright/test'

test('notifications and session records refresh on pushed changes without idle polling', async ({ page }) => {
  await page.clock.install()
  await page.addInitScript(() => {
    const originalFetch = window.fetch.bind(window)
    window.fetch = function (this: Window | undefined, input, options) {
      // Preserve native fetch's receiver check even though the stream is fake.
      if (this != null && this !== window) throw new TypeError('Illegal invocation')
      if (input !== '/api/v1/events') return originalFetch(input, options)
      const encoder = new TextEncoder()
      let listener: (event: Event) => void
      const body = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(encoder.encode('event: ready\ndata: {}\n\n'))
          listener = event => controller.enqueue(encoder.encode(`event: change\ndata: ${JSON.stringify({ topic: (event as CustomEvent<string>).detail })}\n\n`))
          window.addEventListener('test:realtime-change', listener)
        },
        cancel() { window.removeEventListener('test:realtime-change', listener) },
      })
      return Promise.resolve(new Response(body, { headers: { 'Content-Type': 'text/event-stream' } }))
    }
  })
  let unread = 0, status = 'running', notificationReads = 0, recordReads = 0
  const sessionID = '22222222-2222-4222-8222-222222222222'
  await page.route('**/api/v1/**', route => {
    const path = new URL(route.request().url()).pathname.replace('/api/v1', '')
    if (path === '/auth/me') return route.fulfill({ json: { user_id: '11111111-1111-4111-8111-111111111111', permissions: ['session:manage', 'request:manage'] } })
    if (path === '/notifications') {
      notificationReads++
      return route.fulfill({ json: { items: [], unread_count: unread, has_more: false } })
    }
    if (path === '/session-records') {
      recordReads++
      return route.fulfill({ json: [{ id: sessionID, applicant_name: '申请人', asset_name: 'payments-mysql', target_account: 'readonly', target_port: 3306, status, created_at: '2026-09-18T00:00:00Z', expires_at: '2026-09-18T01:00:00Z' }] })
    }
    return route.fulfill({ json: [] })
  })
  await page.goto('/approvals?tab=sessions')
  await expect(page.getByText('payments-mysql', { exact: true })).toBeVisible()
  await expect(page.getByText('运行中', { exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: '站内通知', exact: true })).toBeVisible()
  await expect(page.getByText('实时更新已断开，正在重新连接。', { exact: true })).toHaveCount(0)
  const baseline = [notificationReads, recordReads]
  await page.clock.fastForward(60_000)
  expect([notificationReads, recordReads]).toEqual(baseline)

  unread = 1
  status = 'closed'
  await page.evaluate(() => {
    window.dispatchEvent(new CustomEvent('test:realtime-change', { detail: 'notifications' }))
    window.dispatchEvent(new CustomEvent('test:realtime-change', { detail: 'sessions' }))
  })
  await page.clock.fastForward(300)
  await expect(page.getByRole('button', { name: '站内通知，1 条未读', exact: true })).toBeVisible()
  await expect(page.getByText('已关闭', { exact: true })).toBeVisible()
  expect(notificationReads).toBe(baseline[0]! + 1)
  expect(recordReads).toBe(baseline[1]! + 1)
  const afterChange = [notificationReads, recordReads]
  await page.clock.fastForward(60_000)
  expect([notificationReads, recordReads]).toEqual(afterChange)
})
