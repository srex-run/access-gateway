import { expect, test } from '@playwright/test'
import { sessionRecordFixture } from './session-record-fixture'

const sessionID = '11111111-1111-4111-8111-111111111111'
const session = { id: sessionID, request_id: 'request-1', gateway_id: 'gateway-1', status: 'running', connection_mode: 'native', can_connect: true, gateway_host: 'gateway.example', gateway_port: 20000, gateway_endpoint: 'gateway.example:20000', target_port: 3306, source_ip: '203.0.113.10', target_account: 'readonly', expires_at: '2099-01-01T00:00:00Z' }

test('native session presents gateway address without a local client or credentials', async ({ page }) => {
  let credentialRequests = 0
  await page.route('**/api/v1/auth/me', route => route.fulfill({ json: { user_id: 'applicant', permissions: ['session:manage'] } }))
  await page.route(`**/api/v1/session-records/${sessionID}`, route => route.fulfill({ json: sessionRecordFixture(session) }))
  await page.route(`**/api/v1/session-records/${sessionID}/trace?*`, route => route.fulfill({ json: [] }))
  await page.route(`**/api/v1/sessions/${sessionID}/credential`, route => {
    credentialRequests++
    return route.fulfill({ status: 409, json: { message: 'Native sessions do not use credentials' } })
  })
  await page.goto(`/sessions/${sessionID}`)
  const connection = page.getByRole('region', { name: '客户端连接' })
  await expect(connection.getByText('客户端连接端口', { exact: true })).toBeVisible()
  await expect(connection.getByText('20000', { exact: true })).toBeVisible()
  await expect(connection.getByText('mysql --protocol=TCP -h gateway.example -P 20000 --user=readonly -p --ssl-mode=REQUIRED', { exact: true })).toBeVisible()
  await page.getByRole('tab', { name: '连接配置', exact: true }).click()
  await expect(page.getByText('原生加密通道', { exact: true })).toBeVisible()
  await expect(page.getByText('gateway.example:20000', { exact: true })).toBeVisible()
  await expect(page.getByText('20000', { exact: true })).toBeVisible()
  await expect(page.getByText('203.0.113.10', { exact: true })).toBeVisible()
  await expect(page.getByText('端到端 SSH / TLS 1.2+（必需）', { exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: '结束会话' })).toBeVisible()
  await expect(page.getByRole('button', { name: '下载连接凭据' })).toHaveCount(0)
  await expect(page.getByText('access-client', { exact: false })).toHaveCount(0)
  expect(credentialRequests).toBe(0)
})

test('closed native sessions do not offer session actions', async ({ page }) => {
  await page.route('**/api/v1/auth/me', route => route.fulfill({ json: { user_id: 'applicant', permissions: ['session:manage'] } }))
  await page.route(`**/api/v1/session-records/${sessionID}`, route => route.fulfill({ json: sessionRecordFixture({ ...session, can_connect: false, status: 'closed' }) }))
  await page.route(`**/api/v1/session-records/${sessionID}/trace?*`, route => route.fulfill({ json: [] }))
  await page.goto(`/sessions/${sessionID}`)
  await expect(page.getByText('已关闭', { exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: '结束会话' })).toHaveCount(0)
  await expect(page.getByRole('button', { name: '下载连接凭据' })).toHaveCount(0)
})

test('legacy sessions are not presented as native TCP connections', async ({ page }) => {
  await page.route('**/api/v1/auth/me', route => route.fulfill({ json: { user_id: 'applicant', permissions: ['session:manage'] } }))
  await page.route(`**/api/v1/session-records/${sessionID}`, route => route.fulfill({ json: sessionRecordFixture({ ...session, connection_mode: 'tunnel' }) }))
  await page.route(`**/api/v1/session-records/${sessionID}/trace?*`, route => route.fulfill({ json: [] }))
  await page.goto(`/sessions/${sessionID}`)
  await page.getByRole('tab', { name: '连接配置', exact: true }).click()
  await expect(page.getByText('旧版隧道', { exact: true })).toBeVisible()
  await expect(page.getByText('旧版会话；结束并重新申请后使用当前连接策略。', { exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: '下载连接凭据' })).toHaveCount(0)
})
