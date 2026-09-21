import { expect, test } from '@playwright/test'
import type { Page } from '@playwright/test'

const regionID = '11111111-1111-4111-8111-111111111111'
const assetID = '22222222-2222-4222-8222-222222222222'
const gatewayID = '33333333-3333-4333-8333-333333333333'
const userID = '44444444-4444-4444-8444-444444444444'
const otherRegionID = '55555555-5555-4555-8555-555555555555'
const regionName = '华北生产区'
const permissions = ['directory:read', 'catalog:manage', 'role:manage']

async function mockAdmin(page: Page) {
  await page.route('**/api/v1/**', async route => {
    const url = new URL(route.request().url())
    const path = url.pathname.replace('/api/v1', '')
    let body: unknown = []
    if (path === '/auth/me') body = { user_id: userID, permissions }
    else if (path === '/regions') body = [
      { id: otherRegionID, name: '华东测试区', code: 'east-test', status: 'enabled' },
      { id: regionID, name: regionName, code: 'north-prod', status: 'enabled' },
    ]
    else if (path === '/admin/assets') body = Array.from({ length: 25 }, (_, index) => ({
      id: index === 10 ? assetID : `66666666-6666-4666-8666-${String(index).padStart(12, '0')}`,
      region_id: index % 2 ? regionID : otherRegionID, name: `database-${String(index + 1).padStart(2, '0')}`, asset_type: 'MySQL',
      status: 'enabled', risk_level: 'sensitive', max_ttl_seconds: 3600, external_id: 'cn-north-1/i-production-database-long-instance-identifier',
    }))
    else if (path === `/assets/${assetID}/ports`) body = [{ id: 'port', asset_id: assetID, port: 3306, protocol: 'tcp' }]
    else if (path === `/assets/${assetID}/labels`) body = { asset_id: assetID, revision: 1, labels: {} }
    else if (path === `/admin/assets/${assetID}/audit`) body = { revision: 0, profiles: [], has_secrets: {} }
    await route.fulfill({ json: body })
  })
}

test('unified assets preserve search and page without manual region setup', async ({ page }, testInfo) => {
  await mockAdmin(page)
  const initialSearch = 'tab=assets&assets_page=2&assets_size=10&assets_search=database'
  await page.goto(`/admin/regions?${initialSearch}&region=${regionID}`)
  await expect(page.getByRole('heading', { name: '资产管理' })).toBeVisible()
  await expect(page.getByRole('tab', { name: '区域', exact: true })).toHaveCount(0)
  await expect(page.getByRole('link', { name: '新建区域', exact: true })).toHaveCount(0)
  await expect(page.getByRole('link', { name: 'database-11', exact: true })).toBeVisible()
  await expect(page.getByText('共 25 条，第 2 页')).toBeVisible()
  await page.getByRole('tab', { name: '云账号', exact: true }).click()
  await expect(page.getByLabel('搜索云账号')).toBeVisible()
  await expect(page.getByLabel('搜索资产')).toHaveCount(0)
  await expect(page.getByRole('button', { name: '同步云资产', exact: true })).toHaveCount(0)
  await page.getByRole('tab', { name: '资产', exact: true }).click()
  await expect(page.getByLabel('搜索资产')).toHaveValue('database')
  await expect(page.getByText('共 25 条，第 2 页')).toBeVisible()
  await page.getByRole('link', { name: '新建资产', exact: true }).click()
  await expect(page.getByRole('heading', { name: '添加资产' })).toBeVisible()
  await expect(page.getByLabel('区域', { exact: true })).toHaveCount(0)
  await expect(page.getByLabel('网关', { exact: true })).toHaveCount(0)
  await page.getByRole('button', { name: '取消', exact: true }).click()
  expect(Object.fromEntries(new URL(page.url()).searchParams)).toEqual(Object.fromEntries(new URLSearchParams(initialSearch)))
  await page.getByRole('link', { name: 'database-11', exact: true }).click()
  await expect(page.getByRole('heading', { name: '资产配置' })).toBeVisible()
  await page.getByRole('navigation', { name: '面包屑' }).getByRole('link', { name: '资产管理' }).click()
  expect(Object.fromEntries(new URL(page.url()).searchParams)).toEqual(Object.fromEntries(new URLSearchParams(initialSearch)))
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
  await page.screenshot({ path: testInfo.outputPath('admin-assets.png'), fullPage: true })
})

test('port management guards unsaved edits and refreshes the table after adding and deleting', async ({ page }) => {
  await mockAdmin(page)
  const ports = [{ id: 'mysql', asset_id: assetID, port: 3306, protocol: 'tcp' }]
  const submitted: unknown[] = []
  const deleted: string[] = []
  await page.route(`**/api/v1/assets/${assetID}/ports`, route => route.fulfill({ json: ports }))
  await page.route(`**/api/v1/admin/assets/${assetID}/ports`, async route => {
    const body = route.request().postDataJSON()
    submitted.push(body)
    ports.push({ id: 'ssh', asset_id: assetID, ...body })
    await route.fulfill({ status: 201, json: ports[1] })
  })
  await page.route(`**/api/v1/admin/assets/${assetID}/ports/ssh`, async route => {
    expect(route.request().method()).toBe('DELETE')
    deleted.push('ssh')
    ports.splice(ports.findIndex(port => port.id === 'ssh'), 1)
    await route.fulfill({ status: 204 })
  })
  await page.goto(`/admin/assets/${assetID}?tab=ports&region=${regionID}`)
  await expect(page.locator('form').getByLabel('端口', { exact: true })).toHaveCount(0)
  await page.getByRole('link', { name: '添加端口' }).click()
  await page.getByLabel('端口', { exact: true }).fill('22')
  await page.getByRole('button', { name: '取消', exact: true }).click()
  await expect(page.getByText('放弃未保存的修改？')).toBeVisible()
  await page.getByRole('button', { name: '继续编辑' }).click()
  await page.getByRole('button', { name: '添加端口', exact: true }).click()
  await expect(page.getByRole('heading', { name: '资产配置' })).toBeVisible()
  await expect(page.getByRole('cell', { name: '22', exact: true })).toBeVisible()
  await expect(page.getByText('放弃未保存的修改？')).toHaveCount(0)
  expect(submitted).toEqual([{ port: 22, protocol: 'tcp' }])
  expect(new URL(page.url()).searchParams.has('tab')).toBe(false)
  await page.getByRole('button', { name: '删除端口 22', exact: true }).click()
  await expect(page.getByText('删除端口 22 / TCP？', { exact: true })).toBeVisible()
  await page.getByRole('button', { name: '取消', exact: true }).click()
  expect(deleted).toEqual([])
  await expect(page.getByRole('cell', { name: '22', exact: true })).toBeVisible()
  await page.getByRole('button', { name: '删除端口 22', exact: true }).click()
  await page.getByRole('button', { name: '删除', exact: true }).click()
  await expect(page.getByRole('cell', { name: '22', exact: true })).toHaveCount(0)
  await expect(page.getByRole('cell', { name: '3306', exact: true })).toBeVisible()
  expect(deleted).toEqual(['ssh'])
})

test('legacy gateway links return to assets without management controls', async ({ page }) => {
  await mockAdmin(page)
  for (const path of ['/admin/gateways', '/admin/gateways/create', `/admin/gateways/${gatewayID}/status/edit`]) {
    await page.goto(path)
    await expect(page).toHaveURL('/admin/assets')
    await expect(page.getByRole('link', { name: '网关管理', exact: true })).toHaveCount(0)
  }
  await page.goto(`/admin/assets/${assetID}/gateways/${gatewayID}/edit`)
  await expect(page).toHaveURL(`/admin/assets/${assetID}`)
  await expect(page.getByRole('tab', { name: '网关绑定', exact: true })).toHaveCount(0)
})

test('role grants retain their list context', async ({ page }, testInfo) => {
  await mockAdmin(page)
  const grants: Record<string, unknown>[] = []
  await page.route('**/api/v1/admin/role-assignments**', async route => {
    if (route.request().method() === 'POST') {
      const body = route.request().postDataJSON()
      const value = { id: 'grant', ...body, created_at: '2026-09-10T08:00:00Z' }
      grants.push(value)
      await route.fulfill({ status: 201, json: value })
    } else await route.fulfill({ json: grants })
  })
  await page.goto(`/admin/roles?user=${userID}`)
  await expect(page.getByLabel('角色', { exact: true })).toHaveCount(0)
  await page.getByRole('link', { name: '授予角色', exact: true }).click()
  await expect(page.getByLabel('用户 ID', { exact: true })).toHaveValue(userID)
  await page.getByLabel('角色', { exact: true }).click()
  await page.getByRole('option', { name: '审计员', exact: true }).click()
  await page.getByRole('button', { name: '授予角色', exact: true }).click()
  await expect(page.getByRole('heading', { name: '角色授权' })).toBeVisible()
  await expect(page.getByRole('cell', { name: '审计员', exact: true })).toBeVisible()
  expect(grants[0]).toMatchObject({ user_id: userID, role: 'auditor' })
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
  await page.screenshot({ path: testInfo.outputPath('admin-roles.png'), fullPage: true })
})
