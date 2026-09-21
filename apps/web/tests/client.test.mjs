import assert from 'node:assert/strict'
import { afterEach, test } from 'node:test'
import { ApiError, request, resourcePath } from '../src/shared/api/client.ts'

const originalFetch = globalThis.fetch
afterEach(() => { globalThis.fetch = originalFetch })

test('requests preserve the same origin, abort signal, JSON body and idempotency key', async () => {
  const controller = new AbortController()
  globalThis.fetch = async (url, options) => {
    assert.equal(url, '/api/v1/access-requests?offset=0&emergency=false')
    assert.equal(options.credentials, 'same-origin')
    assert.equal(options.cache, 'no-store')
    assert.equal(options.signal, controller.signal)
    assert.equal(options.headers.get('Idempotency-Key'), 'retry-key')
    assert.equal(options.headers.get('Content-Type'), 'application/json')
    assert.equal(options.body, '{"reason":"maintenance"}')
    return Response.json({ id: 'created' })
  }
  const value = await request('/access-requests', { method: 'POST', body: { reason: 'maintenance' }, idempotencyKey: 'retry-key', signal: controller.signal, query: { offset: 0, emergency: false, empty: '', absent: undefined } })
  assert.equal(value.id, 'created')
})

test('unauthorized responses are typed and mutations are never retried', async () => {
  let calls = 0
  globalThis.fetch = async () => { calls++; return Response.json({ error: 'authentication required' }, { status: 401 }) }
  await assert.rejects(() => request('/auth/logout', { method: 'POST' }), error => error instanceof ApiError && error.status === 401)
  assert.equal(calls, 1)
})

test('settings challenge origin errors are distinct from role permission errors', async () => {
  for (const [code, expected] of [
    ['origin_mismatch', '当前访问地址与系统配置不一致，请使用系统配置的访问地址重新打开页面。'],
    ['terminal_unavailable', '当前会话不可连接，请确认会话仍在有效期内，并使用申请账号登录。'],
    [undefined, '当前账号没有此操作权限。'],
    ['unknown', '当前账号没有此操作权限。'],
  ]) {
    let calls = 0
    globalThis.fetch = async (url, options) => {
      calls++
      assert.equal(url, '/api/v1/auth/transport/challenges')
      assert.deepEqual(JSON.parse(options.body), { method: 'PATCH', path: '/api/v1/admin/settings' })
      return Response.json({ error: 'internal-detail', code }, { status: 403 })
    }
    await assert.rejects(() => request('/admin/settings', { method: 'PATCH', body: { github: { enabled: true } } }),
      error => error instanceof ApiError && error.status === 403 && error.message === expected)
    assert.equal(calls, 1, 'failed challenges must not submit the settings change or retry')
  }
})

test('unencrypted mutations distinguish origin errors and tolerate malformed forbidden responses', async () => {
  globalThis.fetch = async () => Response.json({ code: 'origin_mismatch' }, { status: 403 })
  await assert.rejects(() => request('/auth/logout', { method: 'POST' }),
    error => error instanceof ApiError && error.status === 403 && error.message.includes('访问地址'))
  globalThis.fetch = async () => new Response('<html>Forbidden</html>', { status: 403 })
  await assert.rejects(() => request('/auth/logout', { method: 'POST' }),
    error => error instanceof ApiError && error.status === 403 && error.message === '当前账号没有此操作权限。')
})

test('empty successful responses and malformed upstream pages are handled', async () => {
  globalThis.fetch = async () => new Response(null, { status: 204 })
  assert.equal(await request('/auth/logout', { method: 'POST' }), undefined)
  globalThis.fetch = async () => new Response('<html>upstream error</html>', { headers: { 'Content-Type': 'text/html' } })
  await assert.rejects(() => request('/regions'), error => error instanceof ApiError && error.status === 502)
})

test('transport rejects external paths and encodes resource identifiers', async () => {
  for (const path of ['https://external.invalid', '//external.invalid', '/../internal']) await assert.rejects(() => request(path))
  assert.equal(resourcePath('assets', 'a/b?x'), '/assets/a%2Fb%3Fx')
})

test('settings can display bounded validation errors without exposing server failures', async () => {
  globalThis.fetch = async () => Response.json({ error: '至少保留一种登录方式' }, { status: 400 })
  await assert.rejects(() => request('/admin/settings', { method: 'PATCH', validationMessages: true }), error => error instanceof ApiError && error.message === '至少保留一种登录方式')
  await assert.rejects(() => request('/admin/settings', { method: 'PATCH' }), error => error instanceof ApiError && error.message !== '至少保留一种登录方式')
  globalThis.fetch = async () => Response.json({ error: 'internal-secret-detail' }, { status: 500 })
  await assert.rejects(() => request('/admin/settings', { validationMessages: true }), error => error instanceof ApiError && !error.message.includes('internal-secret-detail'))
  globalThis.fetch = async () => Response.json({ error: 'x'.repeat(513) }, { status: 400 })
  await assert.rejects(() => request('/admin/settings', { validationMessages: true }), error => error instanceof ApiError && error.message.length < 513)
})

test('access requests show actionable validation and preserve retry identifiers', async () => {
  const message = '该资产尚未配置审批人，请先在资产管理的“审批人”中添加其他启用的用户'
  globalThis.fetch = async (url, options) => {
    assert.equal(url, '/api/v1/access-requests')
    assert.equal(options.headers.get('Idempotency-Key'), 'request-validation-retry')
    return Response.json({ error: message }, { status: 400 })
  }
  await assert.rejects(() => request('/access-requests', { method: 'POST', body: { target_port: 3306 }, idempotencyKey: 'request-validation-retry', validationMessages: true }), error => error instanceof ApiError && error.status === 400 && error.message === message)
})

test('old backends returning bad request have a useful fallback', async () => {
  globalThis.fetch = async () => Response.json({ error: 'bad request' }, { status: 400 })
  await assert.rejects(() => request('/access-requests', { method: 'POST', validationMessages: true }), error => error instanceof ApiError && error.message.includes('未返回具体原因') && error.message.includes('重新启动'))
})
