import { expect, test } from '@playwright/test'
import { mockEncryptedTransport } from './transport-mock'

const actor = '11111111-1111-4111-8111-111111111111'
const region = '22222222-2222-4222-8222-222222222222'
const accountID = '44444444-4444-4444-8444-444444444444'
const account = { id: accountID, name: '阿里云生产', provider: 'aliyun', enabled: true, revision: 1, updated_at: '2026-09-10T08:00:00Z' }

test('cloud accounts keep secrets blank when edited', async ({ page }, testInfo) => {
  const transport = await mockEncryptedTransport(page)
  const bodies: Record<string, unknown>[] = []
  let accounts: typeof account[] = []
  await page.route('**/api/v1/auth/me', route => route.fulfill({ json: { user_id: actor, permissions: ['role:manage', 'catalog:manage', 'directory:read'] } }))
  await page.route('**/api/v1/admin/cloud-sync-jobs*', route => route.fulfill({ json: [] }))
  await page.route('**/api/v1/admin/settings', route => route.fulfill({ json: { revision: 1, updated_at: null, has_secrets: {}, config: {
    base_url: '', timeout_seconds: 10, auth: { local_enabled: true, allow_http: false,
      oidc: { enabled: false, name: 'OIDC', issuer: '', client_id: '', scopes: [] },
      oauth2: { enabled: false, name: 'OAuth2', client_id: '', scopes: [] }, ldap: { enabled: false, name: 'LDAP' },
    }, feishu: { app_id: '', tenant_key: '', login_enabled: false, binding_enabled: false, notifications_enabled: false, callbacks_enabled: false },
  } } }))
  await page.route('**/api/v1/admin/cloud-accounts**', async route => {
    if (route.request().method() !== 'GET') {
      const request = transport.open(route)
      const body = request.body
      bodies.push(body)
      accounts = [{ ...account, name: body.name, revision: bodies.length }]
      await request.fulfill(accounts[0])
    } else await route.fulfill({ json: accounts })
  })
  await page.goto('/admin/settings?tab=cloud')
  await page.getByRole('button', { name: '添加云账号', exact: true }).click()
  const form = page.locator('.resource-form-page')
  await expect(page.getByRole('dialog')).toHaveCount(0)
  await form.getByLabel('账号名称').fill(account.name)
  await form.getByLabel('Access Key', { exact: true }).fill('browser-test-ak')
  await form.getByLabel('Secret Key', { exact: true }).fill('browser-test-sk')
  await form.getByRole('button', { name: '保存', exact: true }).click()
  await expect(form).not.toBeVisible()
  expect(bodies[0]).toMatchObject({ access_key: 'browser-test-ak', secret_key: 'browser-test-sk', provider: 'aliyun' })
  await page.getByRole('button', { name: `编辑 ${account.name}` }).click()
  for (const input of await form.locator('input[type=password]').all()) await expect(input).toHaveValue('')
  await form.getByLabel('账号名称').fill('阿里云主账号')
  await form.getByRole('button', { name: '保存', exact: true }).click()
  await expect(form).not.toBeVisible()
  expect(bodies[1].access_key ?? '').toBe('')
  expect(bodies[1].secret_key ?? '').toBe('')
  expect(bodies[1].revision).toBe(1)
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
  await page.screenshot({ path: testInfo.outputPath('cloud-accounts.png'), fullPage: true })
})

test('cloud account sync defaults to a single ECS and restores its scope', async ({ page }, testInfo) => {
  await mockEncryptedTransport(page)
  const submitted: Record<string, unknown>[] = []
  const jobs: Record<string, unknown>[] = []
  await page.route('**/api/v1/auth/me', route => route.fulfill({ json: { user_id: actor, permissions: ['role:manage', 'catalog:manage', 'directory:read'] } }))
  await page.route('**/api/v1/regions', route => route.fulfill({ json: [{ id: region, name: '生产区域', code: 'production', status: 'enabled' }] }))
  await page.route(`**/api/v1/regions/${region}/assets`, route => route.fulfill({ json: [] }))
  await page.route('**/api/v1/admin/cloud-accounts', route => route.fulfill({ json: [account] }))
  await page.route('**/api/v1/admin/assets', route => route.fulfill({ json: [] }))
  await page.route('**/api/v1/admin/cloud-sync-jobs*', route => route.fulfill({ json: jobs }))
  await page.route(`**/api/v1/admin/cloud-accounts/${accountID}/sync`, async route => {
    const body = route.request().postDataJSON()
    submitted.push(body)
    const job = { id: `55555555-5555-4555-8555-${String(jobs.length + 1).padStart(12, '0')}`, account_id: accountID, actor_id: actor, input: body, status: 'success', result: { discovered: 1, created: 1, updated: 0, skipped: 0, missing_ids: [] }, error: '', created_at: '2026-09-10T08:00:00Z' }
    jobs.unshift(job)
    await route.fulfill({ status: 202, json: job })
  })
  await page.goto('/admin/assets?tab=cloud')
  await page.getByRole('button', { name: '同步云资产', exact: true }).click()
  const form = page.locator('.resource-form-page')
  await expect(page.getByRole('dialog')).toHaveCount(0)
  await expect(form.getByText(account.name, { exact: true })).toBeVisible()
  await form.getByLabel('云 Region', { exact: true }).click()
  await page.getByRole('option', { name: 'cn-hangzhou', exact: true }).click()
  await expect(form.getByLabel('实例 ID', { exact: true })).toBeVisible()
  await form.getByLabel('实例 ID', { exact: true }).fill('i-one')
  await expect(form.getByLabel('网关', { exact: true })).toHaveCount(0)
  await form.getByLabel('TCP 端口', { exact: true }).fill('22, 3306')
  await form.getByRole('button', { name: '开始同步', exact: true }).click()
  await expect(form).not.toBeVisible()
  expect(submitted[0]).toMatchObject({ cloud_region: 'cn-hangzhou', instance_ids: ['i-one'], ports: [22, 3306], approver_id: actor })
  expect(submitted[0]).not.toHaveProperty('region_id')
  await expect(page.getByText('已完成', { exact: true })).toBeVisible()
  await page.getByRole('button', { name: '再次同步', exact: true }).click()
  await expect(form.getByLabel('实例 ID', { exact: true })).toHaveValue('i-one')
  await expect(form.getByLabel('TCP 端口', { exact: true })).toHaveValue('22, 3306')
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
  await page.screenshot({ path: testInfo.outputPath('cloud-sync-form.png'), fullPage: true })
  await form.getByRole('button', { name: '取消', exact: true }).click()
  await expect(page.getByRole('button', { name: '下载 Agent 目录' })).toHaveCount(0)
  expect(submitted[0]).not.toHaveProperty('gateway_id')
  await page.getByRole('button', { name: '再次同步', exact: true }).click()
  await form.getByText('整个云 Region', { exact: true }).click()
  await expect(form.getByLabel('实例 ID', { exact: true })).toHaveCount(0)
  await form.getByRole('button', { name: '开始同步', exact: true }).click()
  await expect(form).not.toBeVisible()
  expect(submitted[1].instance_ids).toEqual([])
})
