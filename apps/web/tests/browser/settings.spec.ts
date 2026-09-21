import { expect, test } from '@playwright/test'
import { mockEncryptedTransport } from './transport-mock'

function settingsView() {
  return { revision: 4, updated_at: null, has_secrets: { oidc: true, oauth2: false, github: false, ldap: false, feishu_app: false, feishu_callback: false }, config: {
    base_url: 'https://console.example.test', timeout_seconds: 10,
    auth: { local_enabled: true, allow_http: false,
      oidc: { enabled: false, name: '企业 OIDC', issuer: 'https://identity.example.test', client_id: 'client', scopes: ['profile', 'email'] },
      oauth2: { enabled: false, name: 'OAuth2', client_id: '', authorize_url: '', token_url: '', user_info_url: '', scopes: [], subject_claim: 'id', username_claim: '', name_claim: 'name', email_claim: 'email' },
      github: { enabled: false, name: 'GitHub', client_id: '' },
      ldap: { enabled: false, name: 'LDAP', url: '', bind_dn: '', base_dn: '', user_filter: '(uid={username})', id_attribute: 'entryUUID', username_attribute: '', name_attribute: 'displayName', email_attribute: 'mail', root_ca_pem: '' },
    }, feishu: { app_id: '', tenant_key: '', login_enabled: false, binding_enabled: false, notifications_enabled: false, callbacks_enabled: false },
  } }
}

test('system settings preserve untouched secrets and expose independent Feishu switches', async ({ page }, testInfo) => {
  const transport = await mockEncryptedTransport(page)
  let view = settingsView()
  const bodies: { config: typeof view.config; secrets: Record<string, string>; revision: number }[] = []
  await page.route('**/api/v1/auth/me', route => route.fulfill({ json: { user_id: 'admin', permissions: ['role:manage'] } }))
  await page.route('**/api/v1/admin/settings', async route => {
    if (route.request().method() === 'PATCH') {
      const request = transport.open(route)
      const body = request.body
      bodies.push(body)
      view = { ...view, config: body.config, revision: view.revision + 1 }
      return request.fulfill(view)
    }
    await route.fulfill({ json: view })
  })
  await page.goto('/admin/settings?tab=oidc')
  await expect(page.getByRole('heading', { name: '系统设置' })).toBeVisible()
  await expect(page.getByRole('tab', { name: '操作审计', exact: true })).toHaveCount(0)
  await expect(page.locator('input[type="password"]')).toHaveValue('')
  await expect(page.getByRole('button', { name: '复制回调地址', exact: true })).toHaveAttribute('title', 'https://console.example.test/api/v1/auth/oidc/callback')
  await page.getByLabel('显示名称').fill('公司统一登录')
  await page.getByRole('button', { name: '保存', exact: true }).click()
  await expect(page.getByText('版本 5')).toBeVisible()
  expect(bodies[0]!.revision).toBe(4)
  expect(bodies[0]!.secrets).toEqual({})
  expect(bodies[0]!.config.auth.local_enabled).toBe(true)
  await page.getByRole('checkbox', { name: '清除密钥' }).check()
  await page.getByRole('button', { name: '保存', exact: true }).click()
  await expect(page.getByText('版本 6')).toBeVisible()
  expect(bodies[1]!.secrets).toEqual({ oidc: '' })
  await page.getByRole('tab', { name: '飞书集成' }).click()
  for (const name of ['飞书登录', '账号绑定', '飞书通知', '飞书审批回调']) await expect(page.getByLabel(name, { exact: true })).not.toBeChecked()
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
  await page.screenshot({ path: testInfo.outputPath('system-settings.png'), fullPage: true })
})

test('local accounts remain available and the local account settings tab is removed', async ({ page }) => {
  await page.route('**/api/v1/auth/me', route => route.fulfill({ json: { user_id: 'admin', permissions: ['role:manage'] } }))
  await page.route('**/api/v1/admin/settings', route => route.fulfill({ json: settingsView() }))
  await page.goto('/admin/settings?tab=local')
  await expect(page.getByRole('tab', { name: '本地账号', exact: true })).toHaveCount(0)
  await expect(page.getByRole('tab', { name: '基础设置', exact: true })).toBeVisible()
})

test('GitHub settings derive the callback and preserve a saved client secret', async ({ page }) => {
  const transport = await mockEncryptedTransport(page)
  await page.addInitScript(() => {
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: {
      writeText: async (value: string) => { document.documentElement.dataset.copiedUrl = value },
    } })
  })
  let view = settingsView()
  const bodies: { config: typeof view.config; secrets: Record<string, string>; revision: number }[] = []
  await page.route('**/api/v1/auth/me', route => route.fulfill({ json: { user_id: 'admin', permissions: ['role:manage'] } }))
  await page.route('**/api/v1/admin/settings', async route => {
    if (route.request().method() === 'PATCH') {
      const request = transport.open(route)
      const body = request.body
      bodies.push(body)
      view = { ...view, config: body.config, revision: view.revision + 1, has_secrets: { ...view.has_secrets, github: true } }
      return request.fulfill(view)
    }
    return route.fulfill({ json: view })
  })
  await page.goto('/admin/settings?tab=github')
  await expect(page.getByRole('link', { name: '创建应用' })).toHaveAttribute('href', 'https://github.com/settings/applications/new')
  await expect(page.getByLabel('回调地址', { exact: true })).toHaveCount(0)
  await page.getByRole('button', { name: '复制回调地址', exact: true }).click()
  expect(await page.evaluate(() => document.documentElement.dataset.copiedUrl)).toBe('https://console.example.test/api/v1/auth/github/callback')
  await expect(page.getByLabel('授权地址', { exact: true })).toHaveCount(0)
  await expect(page.getByLabel('授权范围', { exact: true })).toHaveCount(0)
  await page.getByLabel('启用登录', { exact: true }).check()
  await page.getByLabel('Client ID', { exact: true }).fill('github-client')
  await page.locator('input[type="password"]').fill('github-client-secret')
  await page.getByRole('button', { name: '保存', exact: true }).click()
  await expect(page.getByText('版本 5')).toBeVisible()
  expect(bodies[0]!.config.auth.github).toEqual({ enabled: true, name: 'GitHub', client_id: 'github-client' })
  expect(bodies[0]!.secrets).toEqual({ github: 'github-client-secret' })
  expect(JSON.stringify(bodies[0]!.config)).not.toContain('github-client-secret')
  await expect(page.locator('input[type="password"]')).toHaveValue('')
  await page.getByLabel('显示名称', { exact: true }).fill('团队 GitHub')
  await page.getByRole('button', { name: '保存', exact: true }).click()
  await expect(page.getByText('版本 6')).toBeVisible()
  expect(bodies[1]!.secrets).toEqual({})
  expect(bodies[1]!.config.auth.oidc).toEqual(settingsView().config.auth.oidc)
  await page.getByRole('tab', { name: '基础设置', exact: true }).click()
  await expect(page.getByText(view.config.base_url, { exact: true })).toBeVisible()
  await expect(page.getByRole('textbox', { name: '平台地址', exact: true })).toHaveCount(0)
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
})
