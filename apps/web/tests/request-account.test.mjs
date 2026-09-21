import assert from 'node:assert/strict'
import { after, before, test } from 'node:test'
import { mkdtemp, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { pathToFileURL } from 'node:url'
import { build } from 'vite'

let directory, renderRequest
before(async () => {
  directory = await mkdtemp(path.join(tmpdir(), 'request-account-'))
  const entry = path.join(directory, 'fixture.tsx')
  await writeFile(entry, `
    import { renderToStaticMarkup } from 'react-dom/server'
    import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
    import { createMemoryRouter, RouterProvider } from 'react-router-dom'
    import { RequestForm } from '@/features/requests/request-form'
    import { catalogKeys } from '@/features/catalog/api'
    export function renderRequest(ports, adminTest = false) {
      const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity, gcTime: Infinity } } })
      client.setQueryData(['identity'], { user_id: 'applicant', permissions: ['request:manage', 'role:manage'] })
      client.setQueryData(['access-options'], { client_access_enabled: true })
      client.setQueryData(catalogKeys.regions, [{ id: 'region', name: '测试区域', status: 'enabled' }])
      client.setQueryData(catalogKeys.assets('region'), [{ id: 'asset', region_id: 'region', name: 'test-asset', asset_type: 'ssh', status: 'enabled', max_ttl_seconds: 3600 }])
      client.setQueryData(catalogKeys.ports('asset'), ports)
      const router = createMemoryRouter([{ path: '/requests/new', element: <RequestForm /> }], {
        initialEntries: ['/requests/new?region=region&asset=asset' + (adminTest ? '&mode=test' : '')],
      })
      try {
        return renderToStaticMarkup(<QueryClientProvider client={client}><RouterProvider router={router} /></QueryClientProvider>)
      } finally { router.dispose(); client.clear() }
    }
  `)
  await symlink(path.resolve('node_modules'), path.join(directory, 'node_modules'))
  await build({ configFile: false, logLevel: 'silent', ssr: { noExternal: [/^@arco-design\//] }, resolve: { alias: { '@': path.resolve('src') } },
    build: { ssr: entry, outDir: path.join(directory, 'dist'), emptyOutDir: true } })
  ;({ renderRequest } = await import(pathToFileURL(path.join(directory, 'dist/fixture.js')).href))
})
after(async () => { if (directory) await rm(directory, { recursive: true, force: true }) })

test('an automatically selected audited port marks target account required in ordinary and admin test forms', () => {
  const port = { id: 'audited', asset_id: 'asset', port: 60022, protocol: 'tcp', target_account_required: true }
  for (const adminTest of [false, true]) {
    const markup = renderRequest([port], adminTest)
    const input = markup.match(/<input[^>]*aria-label="目标账号"[^>]*>/)?.[0]
    assert.ok(input, 'request form did not render')
    assert.match(input, /aria-required="true"/)
    assert.match(input, /placeholder="必填，登录用户名/)
    const label = markup.match(/<label[^>]*for="[^"]*target_account[^"]*"[^]*?<\/label>/)?.[0]
    assert.ok(label, 'target account label did not render')
    assert.match(label, /arco-form-item-symbol/)
  }
})

test('the requirement comes from the chosen port instead of making all SSH assets require an account', () => {
  const native = { id: 'native', asset_id: 'asset', port: 22, protocol: 'tcp', target_account_required: false }
  const audited = { ...native, id: 'audited', port: 60022, target_account_required: true }
  for (const ports of [[native], [native, audited], []]) {
    const markup = renderRequest(ports)
    const input = markup.match(/<input[^>]*aria-label="目标账号"[^>]*>/)?.[0]
    assert.ok(input, 'request form did not render')
    assert.match(input, /aria-required="false"/)
    assert.match(input, /placeholder="选填，登录用户名"/)
    const label = markup.match(/<label[^>]*for="[^"]*target_account[^"]*"[^]*?<\/label>/)?.[0]
    assert.ok(label, 'target account label did not render')
    assert.doesNotMatch(label, /arco-form-item-symbol/)
  }
})
