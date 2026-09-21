import assert from 'node:assert/strict'
import { after, before, test } from 'node:test'
import { mkdtemp, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { pathToFileURL } from 'node:url'
import { build } from 'vite'

let directory, model, catalog, nodes
before(async () => {
  directory = await mkdtemp(path.join(tmpdir(), 'role-permissions-'))
  const entry = path.join(directory, 'fixture.tsx')
  await writeFile(entry, `
    import { renderToStaticMarkup } from 'react-dom/server'
    import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
    import { MemoryRouter } from 'react-router-dom'
    import { PermissionTree } from '@/features/governance/permission-tree'
    import { RoleCenter } from '@/features/governance/workspaces'
    import { UserWorkspace } from '@/features/admin/users'
    export * from '@/features/governance/permission-tree-model'
    export * from '@/shared/config/navigation'
    export * from '@/shared/lib/permissions'
    export function renderTree(items, value, disabled = false, options = {}) {
      return renderToStaticMarkup(<PermissionTree items={items} value={value} disabled={disabled} {...options} />)
    }
    export function renderManagementTables(permissions) {
      const client = new QueryClient({ defaultOptions: { queries: { staleTime: Infinity, gcTime: Infinity, retry: false } } })
      client.setQueryData(['identity'], { user_id: 'admin-user', permissions })
      client.setQueryData(['governance', 'roles'], ['admin', 'auditor', 'user'].map(name => ({ name, description: name, permissions: [], labels: {}, enabled: true, built_in: true, revision: 1 })))
      client.setQueryDefaults(['users'], { initialData: [{ id: 'admin-user', name: 'Administrator', username: 'admin', status: 'active', labels: {}, created_at: '2026-09-15T08:00:00Z' }] })
      const html = renderToStaticMarkup(<MemoryRouter><QueryClientProvider client={client}><RoleCenter /><UserWorkspace /></QueryClientProvider></MemoryRouter>)
      client.clear()
      return html
    }
  `)
  await symlink(path.resolve('node_modules'), path.join(directory, 'node_modules'))
  await build({ configFile: false, logLevel: 'silent', ssr: { noExternal: [/^@arco-design\//] }, resolve: { alias: { '@': path.resolve('src') } },
    build: { ssr: entry, outDir: path.join(directory, 'dist'), emptyOutDir: true },
  })
  model = await import(pathToFileURL(path.join(directory, 'dist/fixture.js')).href)
  catalog = [...new Set(model.navigationItems.flatMap(item => item.permissions))].map(key => ({ key, name: key, description: key }))
  nodes = model.buildPermissionTree(catalog)
})
after(async () => { if (directory) await rm(directory, { recursive: true, force: true }) })

test('permission tree has exactly the sidebar groups and menu leaves in two levels', () => {
  assert.deepEqual(nodes.map(node => node.title), ['访问管理', '安全管理', '平台管理'])
  assert.deepEqual(nodes.flatMap(group => group.children.map(node => node.title)), model.navigationItems.map(item => item.label))
  assert.ok(nodes.every(group => group.children.every(node => !node.children)))
  for (const item of model.navigationItems) {
    const gate = model.navigationPermission(item.path)
    for (const permission of Array.isArray(gate) ? gate : [gate]) assert.ok(item.permissions.includes(permission))
    const node = nodes.flatMap(group => group.children).find(node => node.key === `menu:${item.path}`)
    assert.deepEqual(node.permissions.map(permission => permission.key), item.permissions)
  }
  const restricted = model.permissionNodes(model.buildPermissionTree(catalog.filter(item => item.key === 'audit:read')))
  assert.ok(restricted.every(node => node.permissions.every(permission => permission.key === 'audit:read')))
})

test('checking settings and unchecking roles changes their shared permission exactly once', () => {
  let value = model.changePermissionSelection(nodes, ['approval:manage'], 'menu:/admin/settings', true)
  assert.deepEqual(value, ['approval:manage', 'role:manage'])
  value = model.changePermissionSelection(nodes, value, 'menu:/admin/roles', true)
  assert.deepEqual(value, ['approval:manage', 'role:manage'])
  value = model.changePermissionSelection(nodes, value, 'menu:/admin/roles', false)
  assert.deepEqual(value, ['approval:manage'])
})

test('custom roles can select force-close, and group removal preserves unrelated and unknown grants', () => {
  let value = model.changePermissionSelection(nodes, ['user:manage', 'future:read'], 'group:安全管理', true)
  assert.deepEqual(value.slice().sort(), ['audit:read', 'future:read', 'role:manage', 'session:manage', 'session:override', 'user:manage'])
  value = model.changePermissionSelection(nodes, value, 'menu:/admin/force-close', true)
  assert.equal(value.filter(key => key === 'session:override').length, 1)
  value = model.changePermissionSelection(nodes, value, 'group:安全管理', false)
  assert.deepEqual(value, ['user:manage', 'future:read'])
  assert.deepEqual(model.changePermissionSelection(nodes, [], 'menu:/admin/force-close', true), ['session:override'])
})

test('selecting every group creates a custom administrator with every catalog permission', () => {
  const value = nodes.reduce((selected, group) => model.changePermissionSelection(nodes, selected, group.key, true), [])
  assert.deepEqual(value.slice().sort(), catalog.map(item => item.key).sort())
  const state = model.permissionSelectionState(nodes, value)
  assert.deepEqual(state.checkedKeys, model.permissionNodes(nodes).map(node => node.key))
  assert.deepEqual(state.halfCheckedKeys, [])
})

test('menu bundles show partial grants without widening them when a different menu changes', () => {
  const original = ['approval:manage', 'user:read']
  let value = model.changePermissionSelection(nodes, original, 'menu:/admin/assets', true)
  assert.deepEqual(value, [...original, 'catalog:manage'])
  let state = model.permissionSelectionState(nodes, value)
  assert.ok(state.halfCheckedKeys.includes('menu:/approvals'))
  assert.ok(state.halfCheckedKeys.includes('menu:/admin/users'))
  assert.ok(!state.checkedKeys.includes('menu:/approvals'))
  value = model.changePermissionSelection(nodes, value, 'menu:/admin/users', true)
  assert.deepEqual(value, [...original, 'catalog:manage', 'user:manage'])
  state = model.permissionSelectionState(nodes, value)
  assert.ok(state.checkedKeys.includes('menu:/admin/users'))
  assert.ok(state.halfCheckedKeys.includes('menu:/approvals'))
  value = model.changePermissionSelection(nodes, value, 'menu:/admin/users', false)
  assert.deepEqual(value, ['approval:manage', 'catalog:manage'])
  assert.deepEqual(original, ['approval:manage', 'user:read'])
})

test('permissions from a newer backend remain visible and can be deselected', () => {
  const updated = model.buildPermissionTree([...catalog, { key: 'future:read', name: '未来权限', description: '新增权限' }])
  assert.equal(updated.at(-1).title, '其他权限')
  const value = model.changePermissionSelection(updated, ['future:read', 'user:read'], 'group:other', false)
  assert.deepEqual(value, ['user:read'])
})

test('editing renders checked and partial menu checkboxes without selectable-disabled gray titles', () => {
  const value = ['approval:manage', 'role:manage']
  assert.deepEqual(model.expandedPermissionKeys(nodes), nodes.map(group => group.key))
  const markup = model.renderTree(catalog, value)
  const checked = [...markup.matchAll(/<input\b([^>]+)>/g)].filter(([, attributes]) => /\bchecked=""/.test(attributes)).map(([, attributes]) => attributes.match(/\bvalue="([^"]+)"/)?.[1])
  assert.deepEqual(checked, ['menu:/admin/roles', 'menu:/admin/settings'])
  assert.match(markup, /arco-checkbox-indeterminate/)
  assert.doesNotMatch(markup, /arco-tree-node-disabled-selectable/)
  assert.doesNotMatch(markup, /arco-tree-node-selected/)
  assert.equal([...markup.matchAll(/role="treeitem"/g)].length, nodes.length + model.navigationItems.length)
  assert.match(markup, /已选 2 项权限/)
  const saving = model.renderTree(catalog, value, true)
  for (const [, attributes] of saving.matchAll(/<input\b([^>]+)>/g)) assert.match(attributes, /\bdisabled=""/)
})

test('menu and page access allow audit readers and do not grant administration or approval to ordinary users', () => {
  assert.equal(model.hasPermission(['audit:read'], model.navigationPermission('/audit')), true)
  const baseline = ['directory:read', 'request:manage', 'session:manage']
  assert.equal(model.hasPermission(baseline, 'approval:manage'), false)
  assert.deepEqual(model.navigationItems.filter(item => model.hasPermission(baseline, item.permission)).map(item => item.path), ['/catalog', '/approvals', '/audit'])
  assert.equal(model.hasPermission(['role:manage'], model.navigationPermission('/admin/settings')), true)
  assert.equal(model.hasPermission(['role:manage'], model.navigationPermission('/admin/force-close')), false)
})

test('editing builtin admin cannot remove management through either linked menu or a group', () => {
  const adminNodes = model.buildPermissionTree(catalog, { lockedPermissions: ['role:manage'] })
  let value = model.changePermissionSelection(adminNodes, ['role:manage'], 'menu:/admin/force-close', true)
  assert.deepEqual(value, ['role:manage', 'session:override'])
  value = model.changePermissionSelection(adminNodes, value, 'menu:/admin/settings', false)
  assert.ok(value.includes('role:manage'))
  value = model.changePermissionSelection(adminNodes, value, 'group:安全管理', false)
  assert.deepEqual(value, ['role:manage'])
  const markup = model.renderTree(catalog, value, false, { lockedPermissions: ['role:manage'] })
  const managementInputs = [...markup.matchAll(/<input\b([^>]+)>/g)].filter(([, attrs]) => /value="menu:\/admin\/(roles|settings)"/.test(attrs))
  assert.equal(managementInputs.length, 2)
  for (const [, attrs] of managementInputs) assert.match(attrs, /\bdisabled=""/)
})

test('built-in roles and administrator accounts have edit buttons while user readers cannot edit accounts', () => {
  const html = model.renderManagementTables(['role:manage', 'user:manage', 'user:read'])
  assert.match(html, /aria-label="编辑角色 admin"/)
  assert.match(html, /aria-label="编辑角色 auditor"/)
  assert.match(html, /aria-label="编辑角色 user"/)
  assert.match(html, /aria-label="编辑用户 Administrator"/)
  const readOnly = model.renderManagementTables(['user:read'])
  assert.doesNotMatch(readOnly, /aria-label="编辑用户 Administrator"/)
  assert.match(readOnly, /用户详情/)
})
