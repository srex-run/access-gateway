import assert from 'node:assert/strict'
import { after, afterEach, before, test } from 'node:test'
import { mkdtemp, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { pathToFileURL } from 'node:url'
import { InfiniteQueryObserver, QueryClient } from '@tanstack/react-query'
import { build } from 'vite'

let directory, openRecordsQuery, forceCloseSession
const originalFetch = globalThis.fetch
before(async () => {
  directory = await mkdtemp(path.join(tmpdir(), 'force-close-query-'))
  const entry = path.join(directory, 'fixture.ts')
  await writeFile(entry, `export { openRecordsQuery, forceCloseSession } from '@/features/sessions/api'`)
  await symlink(path.resolve('node_modules'), path.join(directory, 'node_modules'))
  await build({ configFile: false, logLevel: 'silent', resolve: { alias: { '@': path.resolve('src') } }, build: { ssr: entry, outDir: path.join(directory, 'dist'), emptyOutDir: true } })
  ;({ openRecordsQuery, forceCloseSession } = await import(pathToFileURL(path.join(directory, 'dist/fixture.js')).href))
})
afterEach(() => { globalThis.fetch = originalFetch })
after(async () => { if (directory) await rm(directory, { recursive: true, force: true }) })

test('the selector can load more than 200 open sessions without duplicate lookahead records', async () => {
  const records = Array.from({ length: 213 }, (_, index) => ({ id: `session-${index}`, status: 'running' }))
  const offsets = []
  globalThis.fetch = async url => {
    const query = new URL(url, 'http://localhost').searchParams
    assert.equal(query.get('status'), 'open')
    const offset = Number(query.get('offset'))
    offsets.push(offset)
    return Response.json(records.slice(offset, offset + Number(query.get('limit'))))
  }
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: Infinity } } })
  const observer = new InfiniteQueryObserver(client, openRecordsQuery(''))
  try {
    let result = await observer.refetch()
    while (result.hasNextPage) result = await observer.fetchNextPage()
    assert.equal(result.isSuccess, true)
    assert.deepEqual(result.data.pages.flatMap(page => page.records), records)
    assert.deepEqual(offsets, [0, 50, 100, 150, 200])
  } finally {
    observer.destroy()
    client.clear()
  }
})

test('search starts from the first page and refreshing removes sessions that have closed', async () => {
  let records = [{ id: 'selected-session', status: 'running' }]
  const searches = []
  globalThis.fetch = async url => {
    const query = new URL(url, 'http://localhost').searchParams
    assert.equal(query.get('status'), 'open')
    assert.equal(query.get('offset'), '0')
    searches.push(query.get('search'))
    return Response.json(records)
  }
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: Infinity } } })
  const observer = new InfiniteQueryObserver(client, openRecordsQuery('root'))
  try {
    const initial = await observer.refetch()
    assert.equal(initial.data.pages[0].records.length, 1)
    observer.setOptions(openRecordsQuery('Payments MySQL'))
    assert.equal((await observer.refetch()).data.pages[0].records.length, 1)
    records = []
    const refreshed = await observer.refetch()
    assert.deepEqual(refreshed.data.pages.flatMap(page => page.records), [])
    assert.equal(refreshed.hasNextPage, false)
    assert.deepEqual(searches, ['root', 'Payments MySQL', 'Payments MySQL'])
  } finally {
    observer.destroy()
    client.clear()
  }
})

test('failed queries surface an error instead of presenting an empty session list', async () => {
  globalThis.fetch = async () => Response.json({ error: 'forbidden' }, { status: 403 })
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: Infinity } } })
  try {
    await assert.rejects(client.fetchInfiniteQuery(openRecordsQuery('')), error => error.status === 403)
  } finally {
    client.clear()
  }
})

test('an old backend rejecting the open filter reports a list-loading error with a recovery action', async () => {
  globalThis.fetch = async () => Response.json({ error: 'bad request' }, { status: 400 })
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: Infinity } } })
  try {
    await assert.rejects(client.fetchInfiniteQuery(openRecordsQuery('')), error => {
      assert.equal(error.status, 400)
      assert.match(error.message, /加载开放会话失败/)
      assert.match(error.message, /重新启动服务/)
      assert.doesNotMatch(error.message, /提交内容不符合要求/)
      return true
    })
  } finally {
    client.clear()
  }
})

test('session search displays the public field validation instead of the generic submit error', async () => {
  globalThis.fetch = async () => Response.json({ error: '搜索内容过长，请缩短后重试' }, { status: 400 })
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: Infinity } } })
  try {
    await assert.rejects(client.fetchInfiniteQuery(openRecordsQuery('root')), error => error.message === '加载开放会话失败：搜索内容过长，请缩短后重试')
  } finally {
    client.clear()
  }
})

test('force-close preserves the selected ID and reason and displays the server validation', async () => {
  const sessionID = '519d5466-589c-4d19-bc6d-4dee6affb162'
  globalThis.fetch = async (url, options) => {
    assert.equal(url, `/api/v1/admin/sessions/${sessionID}/force-close`)
    assert.equal(options.method, 'POST')
    assert.deepEqual(JSON.parse(options.body), { reason: '例行维护' })
    return Response.json({ error: '会话编号无效，请刷新后重新选择会话' }, { status: 400 })
  }
  await assert.rejects(forceCloseSession(sessionID, '例行维护'), error => error.status === 400 && error.message === '会话编号无效，请刷新后重新选择会话')
})
