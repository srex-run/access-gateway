import assert from 'node:assert/strict'
import { after, afterEach, before, test } from 'node:test'
import { mkdtemp, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { pathToFileURL } from 'node:url'
import { QueryClient, QueryObserver } from '@tanstack/react-query'
import { build } from 'vite'

let directory, workflowQuery, catalogKeys, renderProgress
const originalFetch = globalThis.fetch
before(async () => {
  directory = await mkdtemp(path.join(tmpdir(), 'workflow-preview-'))
  const entry = path.join(directory, 'fixture.tsx')
  await writeFile(entry, `
    import { renderToStaticMarkup } from 'react-dom/server'
    import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
    import { MemoryRouter } from 'react-router-dom'
    import { WorkflowProgress } from '@/features/governance/progress'
    import { workflowQuery } from '@/features/governance/api'
    export { workflowQuery }
    export { catalogKeys } from '@/features/catalog/api'
    export function renderProgress(view) {
      const client = new QueryClient({ defaultOptions: { queries: { gcTime: Infinity, retry: false } } })
      client.setQueryData(workflowQuery('existing-request').queryKey, view)
      const markup = renderToStaticMarkup(<MemoryRouter><QueryClientProvider client={client}>
        <WorkflowProgress requestID="existing-request" />
      </QueryClientProvider></MemoryRouter>)
      client.clear()
      return markup
    }
  `)
  await symlink(path.resolve('node_modules'), path.join(directory, 'node_modules'))
  await build({ configFile: false, logLevel: 'silent', ssr: { noExternal: [/^@arco-design\//] }, resolve: { alias: { '@': path.resolve('src') } },
    build: { ssr: entry, outDir: path.join(directory, 'dist'), emptyOutDir: true } })
  ;({ workflowQuery, catalogKeys, renderProgress } = await import(pathToFileURL(path.join(directory, 'dist/fixture.js')).href))
})
afterEach(() => { globalThis.fetch = originalFetch })
after(async () => { if (directory) await rm(directory, { recursive: true, force: true }) })

function workflow(kind, selector, name = '资源负责人') {
  return {
    snapshot: { workflow_id: kind, name: '测试环境审批', revision: 2, steps: [{ level: 1, name, kind, selector, mode: 'any', required: 1, candidates: [{ user_id: 'approver', name: '审批同事' }] }] },
    approvals: [{ id: 'approval', user_id: 'approver', name: '审批同事', level: 1, required: 1, step_name: name, decision: null, comment: null, decided_at: null }],
    stages: [{ level: 1, name, required: 1, approved: 0, candidates: 1, status: 'pending' }],
    current_level: 1, expires_at: null, status: 'pending_approval', can_decide: false,
  }
}

test('saving an asset refreshes its cached owner preview while existing requests retain their snapshot', async () => {
  const previous = workflow('owners', '')
  const updated = workflow('role_selector', 'access-gateway.io/role=admin', '平台管理员')
  let configured = previous
  let requestReads = 0
  globalThis.fetch = async url => {
    if (url === '/api/v1/assets/test-asset/workflow') return Response.json(configured)
    assert.equal(url, '/api/v1/access-requests/existing-request/workflow')
    requestReads++
    return Response.json(previous)
  }
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: Infinity, staleTime: 30_000 } } })
  const observer = new QueryObserver(client, workflowQuery(undefined, 'test-asset'))
  const unsubscribe = observer.subscribe(() => {})
  try {
    assert.deepEqual((await observer.refetch()).data, previous)
    await client.fetchQuery(workflowQuery('existing-request'))
    configured = updated
    await client.invalidateQueries({ queryKey: catalogKeys.all })
    assert.deepEqual(observer.getCurrentResult().data, updated)
    assert.deepEqual(client.getQueryData(workflowQuery('existing-request').queryKey), previous)
    assert.equal(requestReads, 1)
  } finally {
    unsubscribe()
    observer.destroy()
    client.clear()
  }
})

test('request details show the actual admin source even when a saved node is still named owner', () => {
  const markup = renderProgress(workflow('role_selector', 'access-gateway.io/role=admin'))
  assert.match(markup, /资源负责人/)
  assert.match(markup, /审批人来源/)
  assert.match(markup, /平台管理员（admin）/)
  assert.doesNotMatch(markup, /资源负责人（owner）/)
})
