import { expect, test } from '@playwright/test'
import type { Workflow } from '../../src/features/governance/types'

test('default workflow can be edited and saved without a built-in badge', async ({ page }) => {
  let workflow: Workflow = {
    id: '00000000-0000-4000-8000-000000000020', name: '负责人及平台审批', description: '负责人通过后，由平台审批角色处理。',
    labels: { template: 'owner-platform' }, asset_selector: 'approval=owner-platform', enabled: true, built_in: true,
    revision: 2, timeout_seconds: 86400,
    steps: [{ name: '资源负责人', kind: 'owners', mode: 'any', selector: '' }, { name: '平台运维', kind: 'role_selector', mode: 'any', selector: 'access-gateway.io/approval=platform' }],
  }
  const submitted: Workflow[] = []
  await page.route('**/api/v1/**', async route => {
    const path = new URL(route.request().url()).pathname.replace('/api/v1', '')
    if (path === '/auth/me') return route.fulfill({ json: { user_id: '11111111-1111-4111-8111-111111111111', permissions: ['workflow:manage'] } })
    if (path === '/admin/workflows') {
      if (route.request().method() === 'POST') {
        const input = route.request().postDataJSON() as Workflow
        submitted.push(input)
        workflow = { ...input, revision: input.revision + 1, built_in: false }
        return route.fulfill({ json: workflow })
      }
      return route.fulfill({ json: [workflow] })
    }
    return route.fulfill({ json: [] })
  })
  await page.goto('/admin/workflows')
  const row = page.getByRole('row').filter({ hasText: workflow.name })
  await expect(row).toBeVisible()
  await expect(row.getByText('内置', { exact: true })).toHaveCount(0)
  await row.getByRole('button', { name: '编辑审批流程', exact: true }).click()
  await expect(page.getByLabel('流程名称', { exact: true })).toHaveValue(workflow.name)
  await page.getByLabel('流程名称', { exact: true }).fill('业务负责人及平台审批')
  await page.getByLabel('第 1 级名称', { exact: true }).fill('业务负责人')
  await page.getByLabel('审批期限（秒）', { exact: true }).fill('7200')
  await page.getByRole('switch', { name: '启用', exact: true }).click()
  await page.getByRole('button', { name: '保存', exact: true }).click()
  await expect.poll(() => submitted.length).toBe(1)
  expect(submitted[0]).toMatchObject({ id: workflow.id, revision: 2, built_in: false, name: '业务负责人及平台审批', timeout_seconds: 7200, enabled: false, labels: { template: 'owner-platform' }, asset_selector: 'approval=owner-platform' })
  expect(submitted[0]!.steps[0]!.name).toBe('业务负责人')
  await expect(page).toHaveURL(/\/admin\/workflows$/)
  const savedRow = page.getByRole('row').filter({ hasText: '业务负责人及平台审批' })
  await expect(savedRow.getByText('停用', { exact: true })).toBeVisible()
  await savedRow.getByRole('button', { name: '编辑审批流程', exact: true }).click()
  await expect(page.getByLabel('第 1 级名称', { exact: true })).toHaveValue('业务负责人')
  await expect(page.getByLabel('审批期限（秒）', { exact: true })).toHaveValue('7200')
  await expect(page.getByRole('switch', { name: '启用', exact: true })).not.toBeChecked()
})

test('creating a workflow previews changes in order and permits direct asset assignment without labels', async ({ page }, testInfo) => {
  const submitted: Workflow[] = []
  await page.route('**/api/v1/**', async route => {
    const path = new URL(route.request().url()).pathname.replace('/api/v1', '')
    if (path === '/auth/me') return route.fulfill({ json: { user_id: '11111111-1111-4111-8111-111111111111', permissions: ['workflow:manage'] } })
    if (path === '/admin/workflows' && route.request().method() === 'POST') {
      const flow = route.request().postDataJSON() as Workflow
      submitted.push(flow)
      return route.fulfill({ json: { ...flow, id: '55555555-5555-4555-8555-555555555555', revision: 1 } })
    }
    return route.fulfill({ json: [] })
  })
  await page.goto('/admin/workflows/create')
  const diagram = page.getByRole('region', { name: '审批流程预览', exact: true })
  await expect(diagram.locator('.workflow-diagram-node')).toHaveText(['提交申请', '资源负责人', '平台运维', '审批结束'])
  await page.getByLabel('流程名称', { exact: true }).fill('生产变更审批')
  await page.getByLabel('第 1 级名称', { exact: true }).fill('业务负责人')
  await expect(diagram.getByRole('button', { name: '业务负责人', exact: true })).toBeVisible()
  await page.getByRole('button', { name: '上移第 2 级', exact: true }).click()
  await expect(diagram.locator('.workflow-diagram-step-link')).toHaveText(['平台运维', '业务负责人'])
  await page.getByLabel('第 1 级审批方式', { exact: true }).click()
  await page.getByRole('option', { name: '会签', exact: true }).click()
  await expect(diagram.locator('.workflow-diagram-step-link')).toHaveText(['平台运维', '业务负责人'])
  await diagram.getByRole('button', { name: '业务负责人', exact: true }).click()
  await expect(page.getByLabel('第 2 级名称', { exact: true })).toBeFocused()
  await page.getByRole('button', { name: '删除第 2 级', exact: true }).click()
  await expect(diagram.locator('.workflow-diagram-step-link')).toHaveCount(1)
  await page.getByLabel('第 1 级审批人来源', { exact: true }).click()
  await page.getByRole('option', { name: '平台管理', exact: true }).click()
  await expect(page.getByLabel('第 1 级审批人来源', { exact: true })).toContainText('平台管理')
  await expect(page.getByLabel('第 1 级名称', { exact: true })).toHaveValue('平台管理员')
  await expect(diagram.locator('.workflow-diagram-step-link')).toHaveText(['平台管理员'])
  await expect(page.getByLabel('第 1 级标签条件', { exact: true })).not.toBeVisible()
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
  await page.screenshot({ path: testInfo.outputPath('workflow-form.png'), fullPage: true })
  await page.getByRole('button', { name: '保存', exact: true }).click()
  await expect.poll(() => submitted.length).toBe(1)
  expect(submitted[0]!.asset_selector ?? '').toBe('')
  expect(submitted[0]!.steps).toEqual([{ name: '平台管理员', kind: 'role_selector', mode: 'all', selector: 'access-gateway.io/role=admin' }])
})
