import { expect, test, type Page } from '@playwright/test'
import type { AssetUpdateInput } from '../../src/features/admin/types'
import type { AssetAuditInput } from '../../src/features/admin/asset-form-model'
import { mockEncryptedTransport } from './transport-mock'

const assetID = '22222222-2222-4222-8222-222222222222'
const gatewayID = '33333333-3333-4333-8333-333333333333'
const userID = '44444444-4444-4444-8444-444444444444'
const workflowID = '55555555-5555-4555-8555-555555555555'
const workflow = { id: workflowID, name: '生产数据库审批', enabled: true, timeout_seconds: 3600, steps: [{ name: '数据库负责人', kind: 'user_selector', mode: 'all', selector: 'team=database' }, { name: '平台管理员', kind: 'role_selector', mode: 'any', selector: 'access-gateway.io/role=admin' }] }
const asset = { id: assetID, region_id: gatewayID, name: 'orders-mysql', asset_type: 'mysql', risk_level: 'normal', max_ttl_seconds: 600, status: 'enabled' }
const profile = { name: `asset.${assetID}.3306`, protocol: 'mysql', port: 3306, selector: '', certificate: 'legacy-certificate', gateway_ca: 'legacy-ca',
  target_ca: '', target_server_name: 'legacy-target', target_certificate_sha256: 'b'.repeat(64), ssh_host_public_key: '', target_host_keys: [], authorized_keys: [] }

async function mockAssetPage(page: Page) {
  await page.route('**/api/v1/**', async route => {
    const path = new URL(route.request().url()).pathname.replace('/api/v1', '')
    const body = path === '/auth/me' ? { user_id: userID, permissions: ['catalog:manage', 'role:manage', 'directory:read', 'workflow:manage'] }
      : path === '/admin/assets' ? [asset]
        : path === '/admin/asset-workflows' ? [workflow]
          : path === `/assets/${assetID}/ports` ? [{ id: 'mysql-port', asset_id: assetID, port: 3306, protocol: 'tcp' }]
            : path === `/assets/${assetID}/labels` ? { asset_id: assetID, revision: 1, labels: { team: 'database' } }
            : path === `/admin/assets/${assetID}/audit` ? { revision: 2, profiles: [profile], has_secrets: { [profile.name]: { private_key: true } } }
              : []
    await route.fulfill({ json: body })
  })
  return mockEncryptedTransport(page)
}

for (const entry of ['list', 'detail']) {
  test(`asset deletion from ${entry} requires confirmation and refreshes the list`, async ({ page }) => {
    await mockAssetPage(page)
    let deleted = false
    let calls = 0
    await page.route('**/api/v1/admin/assets', route => route.fulfill({ json: deleted ? [] : [asset] }))
    await page.route(`**/api/v1/admin/assets/${assetID}`, async route => {
      expect(route.request().method()).toBe('DELETE')
      calls++
      deleted = true
      await route.fulfill({ status: 204 })
    })
    await page.goto(entry === 'list' ? '/admin/assets' : `/admin/assets/${assetID}`)
    await page.getByRole('button', { name: `删除资产 ${asset.name}`, exact: true }).click()
    await page.getByRole('button', { name: '取消', exact: true }).click()
    expect(calls).toBe(0)
    await page.getByRole('button', { name: `删除资产 ${asset.name}`, exact: true }).click()
    await page.getByRole('button', { name: '删除', exact: true }).click()
    await expect.poll(() => calls).toBe(1)
    await expect(page.getByRole('button', { name: `删除资产 ${asset.name}`, exact: true })).toHaveCount(0)
    await expect(page).toHaveURL(/\/admin\/assets(?:\?|$)/)
  })
}

test('asset labels select an owner account and save its ID', async ({ page }) => {
  const transport = await mockAssetPage(page)
  const owner = { id: '77777777-7777-4777-8777-777777777777', nickname: 'Alice', username: 'alice' }
  let labels: Record<string, string> = { env: 'prod' }
  let revision = 1
  const submitted: Record<string, string>[] = []
  await page.route('**/api/v1/auth/me', route => route.fulfill({ json: { user_id: userID, permissions: ['catalog:manage', 'directory:read', 'workflow:manage', 'user:read'] } }))
  await page.route('**/api/v1/admin/users**', route => route.fulfill({ json: new URL(route.request().url()).pathname.endsWith(owner.id) ? owner : [owner] }))
  await page.route(`**/api/v1/assets/${assetID}/labels`, route => route.fulfill({ json: { asset_id: assetID, labels, revision } }))
  await page.route(`**/api/v1/admin/assets/${assetID}/labels`, async route => {
    const submission = transport.open(route)
    labels = submission.body.labels as Record<string, string>
    submitted.push(labels)
    revision++
    await submission.fulfill({ asset_id: assetID, labels, revision })
  })
  await page.goto(`/admin/assets/${assetID}`)
  const region = page.getByRole('region', { name: '资源标签', exact: true })
  await expect(region.getByText('资源标签', { exact: true })).toHaveCount(1)
  await region.getByRole('button', { name: '添加标签', exact: true }).click()
  await region.getByLabel('标签键', { exact: true }).fill('owner')
  await expect(region.getByRole('button', { name: '确认添加标签', exact: true })).toBeDisabled()
  await region.getByLabel('标签值', { exact: true }).click()
  await page.getByRole('option', { name: 'Alice (alice)', exact: true }).click()
  await region.getByRole('button', { name: '确认添加标签', exact: true }).click()
  await expect(region.getByText('owner:alice', { exact: true })).toBeVisible()
  await expect(region.getByText('env:prod', { exact: true })).toBeVisible()
  await region.getByRole('button', { name: '保存', exact: true }).click()
  await expect.poll(() => submitted.length).toBe(1)
  expect(submitted[0]).toEqual({ env: 'prod', owner: owner.id })
  await expect(region.getByText('owner:alice', { exact: true })).toBeVisible()
})

test('resource creation saves only the native tunnel protocol and port', async ({ page }, testInfo) => {
  const transport = await mockAssetPage(page)
  const submissions: (AssetUpdateInput & { audit: AssetAuditInput })[] = []
  await page.route('**/api/v1/admin/assets', async route => {
    if (route.request().method() === 'GET') return route.fulfill({ json: [asset] })
    const request = transport.open(route)
    submissions.push(request.body)
    await request.fulfill(asset, 201)
  })
  await page.goto('/admin/assets/new?assets_search=orders')
  await expect(page).toHaveURL('/admin/assets/create?assets_search=orders')
  await expect(page.getByRole('dialog')).toHaveCount(0)
  await expect(page.getByRole('heading', { name: '添加资产' })).toBeVisible()
  await page.getByLabel('资产名称', { exact: true }).fill('orders-mysql')
  await expect(page.getByLabel('网关', { exact: true })).toHaveCount(0)
  await expect(page.getByLabel('网关域名 / IP', { exact: true })).toHaveCount(0)
  await expect(page.getByRole('link', { name: '网关管理', exact: true })).toHaveCount(0)
  await page.getByLabel('目标地址', { exact: true }).fill('mysql.internal')
  await expect(page.getByText('原生加密隧道', { exact: true })).toBeVisible()
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
  await page.screenshot({ path: testInfo.outputPath('resource-create.png'), fullPage: true })
  await page.getByRole('button', { name: '保存', exact: true }).click()
  await expect(page.getByRole('heading', { name: '资产管理', exact: true })).toBeVisible()
  await expect(page.getByRole('dialog')).toHaveCount(0)
  expect(submissions).toHaveLength(1)
  expect(submissions[0]).toMatchObject({ name: 'orders-mysql', target: 'mysql.internal', asset_type: 'mysql', audit: { revision: 0, profiles: [{ protocol: 'mysql', port: 3306, certificate: '', gateway_ca: '', target_ca: '', target_server_name: '', target_certificate_sha256: '', ssh_host_public_key: '', target_host_keys: [], authorized_keys: [] }] } })
  expect(submissions[0]).not.toHaveProperty('gateway_id')
  const rule = submissions[0]!.audit.profiles[0]!
  expect(submissions[0]!.audit.keys[rule.name]).toEqual({})
  expect(new URL(page.url()).searchParams.get('assets_search')).toBe('orders')
})

test('asset editor opens the selected workflow preview on demand and saves it with the asset', async ({ page }) => {
  const transport = await mockAssetPage(page)
  const submissions: AssetUpdateInput[] = []
  let savedID: string | undefined
  await page.route('**/api/v1/admin/assets', route => route.fulfill({ json: [{ ...asset, approval_workflow_id: savedID }] }))
  await page.route(`**/api/v1/admin/assets/${assetID}`, async route => {
    const request = transport.open(route)
    submissions.push(request.body)
    if (request.body.approval_workflow_id !== undefined) savedID = request.body.approval_workflow_id
    await request.fulfill({ ...asset, approval_workflow_id: savedID })
  })
  await page.goto(`/admin/assets/${assetID}/edit`)
  await page.getByLabel('审批流程', { exact: true }).click()
  await page.getByRole('option', { name: workflow.name, exact: true }).click()
  const diagram = page.getByRole('region', { name: workflow.name, exact: true })
  await expect(diagram).not.toBeVisible()
  await page.getByRole('button', { name: '查看审批流程', exact: true }).click()
  await expect(page.getByRole('dialog', { name: '审批流程预览' })).toBeVisible()
  await expect(diagram.locator('.workflow-diagram-node')).toHaveText(['提交申请', '数据库负责人', '平台管理员', '审批结束'])
  await page.keyboard.press('Escape')
  await expect(diagram).not.toBeVisible()
  await page.getByRole('button', { name: '保存', exact: true }).click()
  await expect.poll(() => submissions.length).toBe(1)
  expect(submissions[0]!.approval_workflow_id).toBe(workflowID)
  await page.goto(`/admin/assets/${assetID}/edit`)
  await expect(page.getByLabel('审批流程', { exact: true })).toContainText(workflow.name)
  await page.getByLabel('审批流程', { exact: true }).click()
  await expect(page.getByRole('option', { name: '按资源标签或历史审批人匹配', exact: true })).toHaveCount(0)
  await page.keyboard.press('Escape')
  await page.goto(`/admin/assets/${assetID}`)
  const configuration = page.getByRole('region', { name: '基本配置', exact: true })
  await expect(configuration.getByText('审批流程', { exact: true })).toBeVisible()
  await expect(configuration.getByRole('link', { name: '编辑资产', exact: true })).toBeVisible()
  await expect(configuration.getByText(workflow.name, { exact: true })).toBeVisible()
  await expect(configuration.getByRole('button', { name: '查看审批流程', exact: true })).toBeVisible()
  await expect(configuration.getByRole('link', { name: '管理审批流程', exact: true })).toBeVisible()
  await expect(page.getByRole('region', { name: '端口', exact: true }).getByRole('cell', { name: '3306', exact: true })).toBeVisible()
  await expect(page.getByRole('region', { name: '资源标签', exact: true }).getByText('team:database', { exact: true })).toBeVisible()
  await expect(page.getByRole('tab')).toHaveCount(0)
})

test('resource edit keeps the native tunnel configuration and does not expose credentials', async ({ page }, testInfo) => {
  const transport = await mockAssetPage(page)
  const submissions: (AssetUpdateInput & { audit: AssetAuditInput })[] = []
  await page.route(`**/api/v1/admin/assets/${assetID}`, async route => {
    const request = transport.open(route)
    submissions.push(request.body)
    await request.fulfill({ ...asset, name: request.body.name })
  })
  await page.goto(`/admin/assets/${assetID}/edit?assets_page=2`)
  await expect(page.getByRole('heading', { name: '编辑资产' })).toBeVisible()
  await expect(page.getByLabel('资产名称', { exact: true })).toHaveValue(asset.name)
  await expect(page.getByLabel('目标地址', { exact: true })).toHaveValue('')
  await page.getByLabel('资产名称', { exact: true }).fill('orders-renamed')
  await page.getByRole('button', { name: '保存', exact: true }).click()
  await expect(page.getByRole('heading', { name: '资产管理', exact: true })).toBeVisible()
  expect(submissions[0]).toMatchObject({ name: 'orders-renamed', audit: { revision: 2 } })
  expect(submissions[0]).not.toHaveProperty('target')
  expect(submissions[0]!.audit.keys).toEqual({ [profile.name]: {} })
  expect(JSON.stringify(submissions[0])).not.toContain('legacy-')
  await page.goto(`/admin/assets/${assetID}/edit`)
  await page.getByLabel('资产名称', { exact: true }).fill('metadata-only')
  await page.getByRole('button', { name: '保存', exact: true }).click()
  await expect.poll(() => submissions.length).toBe(2)
  expect(submissions[1]).not.toHaveProperty('target')
  expect(submissions[1]!.audit.keys).toEqual({ [profile.name]: {} })
  await page.screenshot({ path: testInfo.outputPath('resource-edit.png'), fullPage: true })
})

test('resource protocol switching clears incompatible certificate material and stays on the page', async ({ page }) => {
  await mockAssetPage(page)
  await page.goto('/admin/assets/create')
  await page.getByLabel('资产类型', { exact: true }).click()
  for (const label of ['MySQL', 'PostgreSQL', 'Redis', 'MongoDB', 'HTTP / HTTPS', 'SSH / SSHD']) await expect(page.getByRole('option', { name: label, exact: true })).toBeVisible()
  await page.getByRole('option', { name: 'SSH / SSHD', exact: true }).click()
  await expect(page.getByLabel('TCP 端口', { exact: true })).toHaveValue('22')
  await expect(page.getByText('原生加密隧道', { exact: true })).toBeVisible()
  await expect(page.getByLabel('资产 SSH 主机公钥', { exact: true })).toHaveCount(0)
  await expect(page.getByRole('button', { name: '一键生成全部', exact: true })).toHaveCount(0)
  await expect(page.getByRole('dialog')).toHaveCount(0)
  await page.getByLabel('资产类型', { exact: true }).click()
  await page.getByRole('option', { name: 'PostgreSQL', exact: true }).click()
  await expect(page.getByLabel('TCP 端口', { exact: true })).toHaveValue('5432')
  await expect(page.getByLabel('资产 SSH 主机公钥', { exact: true })).toHaveCount(0)
})

test('agent audit enables SSH trust configuration and submits through encrypted transport', async ({ page }, testInfo) => {
  const transport = await mockAssetPage(page)
  const submissions: (AssetUpdateInput & { audit: AssetAuditInput })[] = []
  await page.route('**/api/v1/admin/assets', async route => {
    if (route.request().method() === 'GET') return route.fulfill({ json: [asset] })
    const request = transport.open(route)
    submissions.push(request.body)
    await request.fulfill(asset, 201)
  })
  await page.goto('/admin/assets/create')
  await page.getByLabel('资产名称', { exact: true }).fill('ssh-audit')
  await page.getByLabel('目标地址', { exact: true }).fill('ssh.internal')
  await page.getByLabel('资产类型', { exact: true }).click()
  await page.getByRole('option', { name: 'SSH / SSHD', exact: true }).click()
  await page.getByRole('switch', { name: '操作审计', exact: true }).click()
  await page.getByText('高级配置（手动调整）', { exact: true }).click()
  await page.getByLabel('资产 SSH 主机公钥', { exact: true }).fill('ssh-ed25519 trusted-target')
  await page.getByLabel('允许的客户端公钥', { exact: true }).fill('ssh-ed25519 client')
  await page.getByLabel('资产登录私钥', { exact: true }).fill('private-login-key')
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
  await page.screenshot({ path: testInfo.outputPath('agent-ssh-audit.png'), fullPage: true })
  await page.getByRole('button', { name: '保存', exact: true }).click()
  await expect.poll(() => submissions.length).toBe(1)
  const saved = submissions[0]!.audit
  expect(saved.profiles[0]).toMatchObject({ protocol: 'ssh', audit_enabled: true, target_host_keys: ['ssh-ed25519 trusted-target'], authorized_keys: ['ssh-ed25519 client'] })
  expect(saved.keys[saved.profiles[0]!.name]).toEqual({ target_ssh_key: 'private-login-key' })
})

test('agent audit exposes TLS target trust for database protocols', async ({ page }, testInfo) => {
  await mockAssetPage(page)
  await page.goto('/admin/assets/create')
  await page.getByRole('switch', { name: '操作审计', exact: true }).click()
  await expect(page.getByLabel('目标服务身份校验', { exact: true })).not.toBeVisible()
  await page.getByText('高级配置（手动调整）', { exact: true }).click()
  await expect(page.getByLabel('目标服务身份校验', { exact: true })).toContainText('系统信任库（公共 CA）')
  await expect(page.getByLabel('目标服务 CA', { exact: true })).toHaveCount(0)
  await expect(page.getByLabel('目标证书 SHA-256', { exact: true })).toHaveCount(0)
  await page.getByLabel('目标服务身份校验', { exact: true }).click()
  await page.getByRole('option', { name: '自定义 CA', exact: true }).click()
  await page.getByLabel('目标服务 CA', { exact: true }).fill('public CA')
  await page.getByText('证书域名（可选）', { exact: true }).click()
  await page.getByLabel('目标证书域名', { exact: true }).fill('mysql.internal')
  await expect(page.getByLabel('资产 SSH 主机公钥', { exact: true })).toHaveCount(0)
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
  await page.screenshot({ path: testInfo.outputPath('agent-tls-audit.png'), fullPage: true })
  await page.getByRole('switch', { name: '操作审计', exact: true }).click()
  await expect(page.getByLabel('目标服务 CA', { exact: true })).toHaveCount(0)
})

test('one-click setup fills gateway certificates and target trust before saving', async ({ page }) => {
  const transport = await mockAssetPage(page)
  const submissions: (AssetUpdateInput & { audit: AssetAuditInput })[] = []
  await page.route('**/api/v1/admin/assets/audit/certificates', async route => {
    const request = transport.open(route)
    expect(request.body).toEqual({ purpose: 'setup', protocol: 'mysql', asset_id: assetID, target_port: 3306, hosts: [], valid_days: 365 })
    await request.fulfill({ certificate: 'generated-certificate', ca: 'generated-public-ca', private_key: 'generated-private-key', target_certificate_sha256: 'a'.repeat(64) })
  })
  await page.route(`**/api/v1/admin/assets/${assetID}`, async route => {
    const request = transport.open(route)
    submissions.push(request.body)
    await request.fulfill(asset)
  })
  await page.goto(`/admin/assets/${assetID}/edit`)
  await page.getByRole('switch', { name: '操作审计', exact: true }).click()
  await page.getByRole('button', { name: '一键生成全部', exact: true }).click()
  await expect(page.getByText('网关与目标服务配置已全部就绪，保存资产后生效', { exact: true })).toBeVisible()
  await expect(page.getByRole('region', { name: '网关身份', exact: true }).getByText('已生成，待保存', { exact: true })).toBeVisible()
  await expect(page.getByLabel('网关证书', { exact: true })).toHaveValue('generated-certificate')
  await expect(page.getByLabel('网关证书', { exact: true })).toHaveAttribute('readonly', '')
  await expect(page.getByLabel('客户端信任 CA', { exact: true })).toHaveValue('generated-public-ca')
  await expect(page.getByLabel('目标服务身份', { exact: true })).toHaveValue('a'.repeat(64))
  await expect(page.getByLabel('目标服务身份校验', { exact: true })).not.toBeVisible()
  await expect(page.getByLabel('目标服务 CA', { exact: true })).toHaveCount(0)
  const pendingDownload = page.waitForEvent('download')
  await page.getByRole('button', { name: '下载客户端信任证书', exact: true }).click()
  const download = await pendingDownload
  const chunks: Buffer[] = []
  for await (const chunk of await download.createReadStream()) chunks.push(Buffer.from(chunk))
  expect(Buffer.concat(chunks).toString()).toBe('generated-public-ca')
  expect(await page.evaluate(() => JSON.stringify({ ...localStorage, ...sessionStorage }))).not.toContain('generated-private-key')
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
  await page.getByRole('button', { name: '保存', exact: true }).click()
  await expect.poll(() => submissions.length).toBe(1)
  expect(submissions[0]!.audit.profiles[0]).toMatchObject({ certificate: 'generated-certificate', gateway_ca: 'generated-public-ca', target_certificate_sha256: 'a'.repeat(64), target_ca: '', target_server_name: '' })
  expect(submissions[0]!.audit.keys[profile.name]).toEqual({ private_key: 'generated-private-key' })
})

test('one-click SSH setup reads the target host key for a new asset without manual input', async ({ page }) => {
  const transport = await mockAssetPage(page)
  const submissions: (AssetUpdateInput & { audit: AssetAuditInput })[] = []
  await page.route('**/api/v1/admin/assets/audit/certificates', async route => {
    const request = transport.open(route)
    expect(request.body).toEqual({ purpose: 'setup', protocol: 'ssh', target: 'ssh.internal', target_port: 22, hosts: [], valid_days: 365 })
    await request.fulfill({ ssh_host_key: 'generated-host-private-key', ssh_public_key: 'ssh-ed25519 generated-host', target_host_keys: ['ssh-ed25519 trusted-target'] })
  })
  await page.route('**/api/v1/admin/assets', async route => {
    if (route.request().method() === 'GET') return route.fulfill({ json: [asset] })
    const request = transport.open(route)
    submissions.push(request.body)
    await request.fulfill(asset, 201)
  })
  await page.goto('/admin/assets/create')
  await page.getByLabel('资产名称', { exact: true }).fill('ssh-audit')
  await page.getByLabel('目标地址', { exact: true }).fill('ssh.internal')
  await page.getByLabel('资产类型', { exact: true }).click()
  await page.getByRole('option', { name: 'SSH / SSHD', exact: true }).click()
  await page.getByRole('switch', { name: '操作审计', exact: true }).click()
  await page.getByRole('button', { name: '一键生成全部', exact: true }).click()
  await expect(page.getByRole('button', { name: '下载网关 SSH 公钥', exact: true })).toBeVisible()
  await expect(page.getByLabel('网关 SSH 公钥', { exact: true })).toHaveValue('ssh-ed25519 generated-host')
  await expect(page.getByLabel('目标服务身份', { exact: true })).toHaveValue('ssh-ed25519 trusted-target')
  await expect(page.getByRole('region', { name: '网关身份', exact: true }).getByText('已生成，待保存', { exact: true })).toBeVisible()
  await page.getByRole('button', { name: '保存', exact: true }).click()
  await expect.poll(() => submissions.length).toBe(1)
  const saved = submissions[0]!.audit
  expect(saved.profiles[0]).toMatchObject({ ssh_host_public_key: 'ssh-ed25519 generated-host', target_host_keys: ['ssh-ed25519 trusted-target'] })
  expect(saved.keys[saved.profiles[0]!.name]).toMatchObject({ ssh_host_key: 'generated-host-private-key' })
})

test('one-click setup reports failures and retries the current draft target', async ({ page }) => {
  const transport = await mockAssetPage(page)
  let attempts = 0
  await page.route('**/api/v1/admin/assets/audit/certificates', async route => {
    const request = transport.open(route)
    expect(request.body).toEqual({ purpose: 'setup', protocol: 'mysql', target: 'unsaved.mysql.internal', hosts: [], valid_days: 365, asset_id: assetID, target_port: 3306 })
    if (++attempts === 1) await request.fulfill({ error: '无法读取 MySQL 资产证书' }, 400)
    else await request.fulfill({ certificate: 'new-certificate', ca: 'new-ca', private_key: 'new-private-key', target_certificate_sha256: 'a'.repeat(64) })
  })
  await page.goto(`/admin/assets/${assetID}/edit`)
  await page.getByRole('switch', { name: '操作审计', exact: true }).click()
  const generate = page.getByRole('button', { name: '一键生成全部', exact: true })
  await page.getByLabel('目标地址', { exact: true }).fill('unsaved.mysql.internal')
  await expect(generate).toBeEnabled()
  await generate.click()
  await expect(page.getByText('无法读取 MySQL 资产证书', { exact: true })).toBeVisible()
  await generate.click()
  await expect(page.getByLabel('目标服务身份', { exact: true })).toHaveValue('a'.repeat(64))
  await expect(page.getByLabel('网关证书', { exact: true })).toHaveValue('new-certificate')
  await expect(page.getByLabel('客户端信任 CA', { exact: true })).toHaveValue('new-ca')
  await expect(page.getByText('无法读取 MySQL 资产证书', { exact: true })).toHaveCount(0)
})
