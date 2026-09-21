import { expect, test } from '@playwright/test'
import { mockEncryptedTransport } from './transport-mock'

const providers = [
  { id: 'local', name: '本地账号', kind: 'password' },
  { id: 'oidc', name: '企业 OIDC', kind: 'redirect' },
  { id: 'ldap', name: 'LDAP', kind: 'password' },
  { id: 'oauth2', name: 'OAuth2', kind: 'redirect' },
  { id: 'github', name: 'GitHub', kind: 'redirect' },
]

test('login methods render, switch and report failed credentials', async ({ page }, testInfo) => {
	const transport = await mockEncryptedTransport(page)
  const errors: string[] = []
  page.on('pageerror', error => errors.push(error.message))
  await page.route('**/api/v1/auth/me', route => route.fulfill({ status: 401, json: {} }))
  await page.route('**/api/v1/auth/providers', route => route.fulfill({ json: providers }))
  let submitted: unknown
  await page.route('**/api/v1/auth/ldap/login', async route => {
    const request = transport.open(route)
    submitted = request.body
    await request.fulfill({}, 401)
  })
  await page.goto('/login')
  await expect(page.getByRole('link', { name: '企业 OIDC登录' })).toHaveAttribute('href', '/api/v1/auth/oidc/login')
  await expect(page.getByRole('link', { name: 'OAuth2登录' })).toHaveAttribute('href', '/api/v1/auth/oauth2/login')
  await expect(page.getByRole('link', { name: 'GitHub登录' })).toHaveAttribute('href', '/api/v1/auth/github/login')
  await expect(page.getByRole('link', { name: '飞书登录' })).toHaveCount(0)
  await page.getByRole('radio', { name: 'LDAP' }).check()
  await page.getByLabel('账号', { exact: true }).fill('alice')
  await page.getByLabel('密码', { exact: true }).fill('test-password')
  await page.getByRole('button', { name: '登录', exact: true }).click()
  await expect(page.getByText('账号或密码错误，或账号已停用。')).toBeVisible()
  expect(submitted).toEqual({ username: 'alice', password: 'test-password' })
  await page.getByRole('radio', { name: '本地账号' }).check()
  await expect(page.getByLabel('密码', { exact: true })).toHaveValue('')
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
  await page.screenshot({ path: testInfo.outputPath('login.png'), fullPage: true })
  expect(errors).toEqual([])
})

test('successful local login opens the catalog', async ({ page }) => {
  let loggedIn = false
  await page.route('**/api/v1/**', async route => {
    const path = new URL(route.request().url()).pathname
    if (path.endsWith('/auth/providers')) return route.fulfill({ json: providers })
    if (path.endsWith('/auth/me')) return route.fulfill({ status: loggedIn ? 200 : 401, json: { user_id: 'user', permissions: ['directory:read'] } })
    if (path.endsWith('/auth/local/login')) { loggedIn = true; return transport.open(route).fulfill({ user_id: 'user' }) }
    return route.fulfill({ json: [] })
  })
  const transport = await mockEncryptedTransport(page)
  await page.goto('/login')
  await page.getByLabel('账号', { exact: true }).fill('alice')
  await page.getByLabel('密码', { exact: true }).fill('test-password')
  await page.getByRole('button', { name: '登录', exact: true }).click()
  await expect(page).toHaveURL(/\/catalog$/)
  await expect(page.getByRole('heading', { name: '资产目录' })).toBeVisible()
})

test('unconfigured providers and callback failure have visible states', async ({ page }) => {
  await page.route('**/api/v1/auth/me', route => route.fulfill({ status: 401, json: {} }))
  await page.route('**/api/v1/auth/providers', route => route.fulfill({ json: [] }))
  await page.goto('/login?error=authentication_failed')
  await expect(page.getByText('暂无可用的登录方式，请联系管理员。')).toBeVisible()
  await expect(page.getByText('身份验证未完成，请重新登录。')).toBeVisible()
})

test('account password confirmation and Feishu binding remain independent', async ({ page }, testInfo) => {
  const transport = await mockEncryptedTransport(page)
  await page.route('**/api/v1/auth/account/mfa', route => route.fulfill({ json: { bound: false, recovery_codes_left: 0, can_enroll: false, can_unbind: false } }))
  let passwordBody: unknown
  await page.route('**/api/v1/auth/me', route => route.fulfill({ json: { user_id: 'user', permissions: ['directory:read'] } }))
  await page.route('**/api/v1/auth/account', route => route.fulfill({ json: { user_id: '11111111-1111-4111-8111-111111111111', nickname: 'Alice', username: 'alice', providers: ['local'], feishu_bound: false, feishu_configured: true, feishu_binding_enabled: true, local_enabled: true } }))
  await page.route('**/api/v1/auth/password', async route => { const request = transport.open(route); passwordBody = request.body; await request.fulfill({}, 401) })
  await page.goto('/account')
  await expect(page.getByRole('button', { name: '绑定飞书' })).toBeEnabled()
  await page.getByLabel('当前密码', { exact: true }).fill('current-password')
  await page.getByLabel('新密码', { exact: true }).fill('new-password-123')
  await page.getByLabel('确认新密码', { exact: true }).fill('mismatched-password')
  await page.getByRole('button', { name: '更新密码' }).click()
  await expect(page.getByText('两次输入的密码不一致')).toBeVisible()
  expect(passwordBody).toBeUndefined()
  await page.getByLabel('确认新密码', { exact: true }).fill('new-password-123')
  await page.getByRole('button', { name: '更新密码' }).click()
  await expect(page.getByText('当前密码不正确。')).toBeVisible()
  expect(passwordBody).toEqual({ current_password: 'current-password', new_password: 'new-password-123' })
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
  await page.screenshot({ path: testInfo.outputPath('account.png'), fullPage: true })
})

for (const provider of ['local', 'github']) {
  test(`account hides unconfigured Feishu for ${provider} users`, async ({ page }) => {
    await page.route('**/api/v1/auth/me', route => route.fulfill({ json: { user_id: 'user', permissions: ['directory:read'] } }))
    await page.route('**/api/v1/auth/account/mfa', route => route.fulfill({ json: { bound: false, recovery_codes_left: 0, can_enroll: false, can_unbind: false } }))
    await page.route('**/api/v1/auth/account', route => route.fulfill({ json: {
      user_id: 'user', username: 'alice', nickname: '小艾', providers: [provider],
      feishu_bound: false, feishu_configured: false, feishu_binding_enabled: false,
    } }))
    await page.goto('/account?feishu=bound&error=authentication_failed')
    await expect(page.getByText('小艾', { exact: true })).toBeVisible()
    await expect(page.getByText('用户名', { exact: true })).toBeVisible()
    await expect(page.getByText('昵称', { exact: true })).toBeVisible()
    await expect(page.getByText('飞书账号', { exact: true })).toHaveCount(0)
    await expect(page.locator('.account-binding')).toHaveCount(0)
    await expect(page.getByRole('button', { name: /绑定飞书|解除绑定/ })).toHaveCount(0)
    await expect(page.getByText('飞书账号已绑定。', { exact: true })).toHaveCount(0)
    await expect(page.getByText('飞书账号绑定失败，账号可能已被其他用户绑定。', { exact: true })).toHaveCount(0)
    await expect(page.getByRole('button', { name: '更新密码' })).toHaveCount(provider === 'local' ? 1 : 0)
  })
}
