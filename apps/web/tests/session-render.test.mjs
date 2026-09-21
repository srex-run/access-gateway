import assert from 'node:assert/strict'
import { after, before, test } from 'node:test'
import { mkdtemp, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { pathToFileURL } from 'node:url'
import { build } from 'vite'

let directory, renderSession
before(async () => {
  directory = await mkdtemp(path.join(tmpdir(), 'session-render-'))
  const entry = path.join(directory, 'fixture.tsx')
  await writeFile(entry, `
    import { renderToStaticMarkup } from 'react-dom/server'
    import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
    import { MemoryRouter } from 'react-router-dom'
    import { SessionDetails } from '@/features/sessions/components'
    export function renderSession(evidence, trace, page = 1, stage = '', session = {}) {
      const id = 'session-render-test'
      const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity, gcTime: Infinity } } })
      client.setQueryData(['sessions', 'record', id, false], {
        id, asset_name: 'Payments', asset_type: 'mysql', target_port: 33306, target_account: 'readonly', applicant_name: 'Administrator', request_id: 'request-1',
        request: { status: 'approved', approval_mode: 'admin_test' }, workflow: { approvals: [] },
        session: { id, status: 'running', connection_mode: 'audit', ...session }, evidence, can_close: false,
      })
      client.setQueryData(['sessions', 'trace', id, page, 10, stage], trace)
      const markup = renderToStaticMarkup(<MemoryRouter initialEntries={['/sessions/' + id + '?trace_page=' + page + '&stage=' + stage]}>
        <QueryClientProvider client={client}><SessionDetails id={id} /></QueryClientProvider>
      </MemoryRouter>)
      client.clear()
      return markup
    }
  `)
  await symlink(path.resolve('node_modules'), path.join(directory, 'node_modules'))
  await build({ configFile: false, logLevel: 'silent', ssr: { noExternal: [/^@arco-design\//, /^@xterm\//] }, resolve: { alias: { '@': path.resolve('src') } },
    build: { ssr: entry, outDir: path.join(directory, 'dist'), emptyOutDir: true },
  })
  ;({ renderSession } = await import(pathToFileURL(path.join(directory, 'dist/fixture.js')).href))
})
after(async () => { if (directory) await rm(directory, { recursive: true, force: true }) })

const evidence = {
  verified_accounts: ['root'], operation_count: 12, connection_count: 1, failed_connections: 0,
  context: { accounts: [{ name: 'root', verified: true }], protocols: ['mysql'], backend_sources: [{ ip: '192.168.3.24', port: 59866 }], client_sources: ['127.0.0.1'] },
}
const operation = { stage: 'operation', event_type: 'query', occurred_at: '2026-09-11T14:50:00Z', actual_account: 'root', account_verified: true, protocol: 'mysql', result: 'success', backend_source_ip: '192.168.3.24', backend_source_port: 59866, operation: 'SELECT ? FROM payments' }

test('session metadata appears once while repeated commands keep their own results and durations', () => {
  const markup = renderSession(evidence, [{ ...operation, id: 'first', duration_ms: 83 }, { ...operation, id: 'second', result: 'failed', duration_ms: 4 }])
  assert.equal(markup.split('root · 已验证').length - 1, 1)
  assert.equal(markup.split('192.168.3.24:59866').length - 1, 1)
  assert.equal(markup.split('>mysql<').length - 1, 1)
  assert.equal(markup.split('SELECT ? FROM payments').length - 1, 2)
  assert.match(markup, /83 ms/)
  assert.match(markup, /4 ms/)
  assert.match(markup, /失败/)
  assert.doesNotMatch(markup, /session-record-summary|arco-timeline/)
})

test('lookahead is hidden and session evidence survives a different page and stage', () => {
  const rows = Array.from({ length: 11 }, (_, index) => ({ ...operation, id: String(index), operation: 'command-' + index }))
  const markup = renderSession(evidence, rows, 2, 'operation')
  assert.match(markup, /command-9/)
  assert.doesNotMatch(markup, /command-10/)
  assert.match(markup, /root · 已验证/)
  assert.match(markup, /192\.168\.3\.24:59866/)
  const connections = renderSession(evidence, [], 1, 'connection')
  assert.match(connections, /root · 已验证/)
  assert.match(connections, /192\.168\.3\.24:59866/)
})

test('a running session does not imply successful account authentication', () => {
  const markup = renderSession({ verified_accounts: [], operation_count: 0, connection_count: 1, failed_connections: 1 }, [])
  assert.match(markup, /暂无已验证账号/)
  assert.doesNotMatch(markup, /root|· 已验证/)
})

test('connection host, allocated port and TLS command are visible on the initial details tab', () => {
  const markup = renderSession({ verified_accounts: [], operation_count: 0, connection_count: 0, failed_connections: 0 }, [], 1, '', {
    connection_mode: 'native', can_connect: true, gateway_host: '127.0.0.1', gateway_port: 20027, gateway_endpoint: '127.0.0.1:20027',
  })
  assert.match(markup, /aria-label="客户端连接"/)
  assert.match(markup, /客户端连接端口/)
  assert.match(markup, /<code>20027<\/code>/)
  assert.match(markup, /目标服务端口/)
  assert.match(markup, /33306/)
  assert.match(markup, /mysql --protocol=TCP -h 127\.0\.0\.1 -P 20027 --user=readonly -p --ssl-mode=REQUIRED/)
  assert.ok(markup.indexOf('客户端连接端口') < markup.indexOf('访问轨迹'))
})
