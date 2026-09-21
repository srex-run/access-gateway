import assert from 'node:assert/strict'
import test from 'node:test'
import { connectEventStream, readEventStream } from '../src/shared/api/event-stream.ts'
import { changedQueryRoots } from '../src/features/realtime/model.ts'

const encoder = new TextEncoder()
function streamResponse(text) {
  return new Response(text, { headers: { 'Content-Type': 'text/event-stream' } })
}

test('SSE decoder preserves fragmented UTF-8, CRLF, multiple frames and multiline data', async () => {
  const bytes = encoder.encode(': keepalive\r\nevent: change\r\ndata: {"topic":\r\ndata: "通知"}\r\n\r\nevent: ready\ndata: {}\n\n')
  const body = new ReadableStream({ start(controller) {
    for (const value of bytes) controller.enqueue(Uint8Array.of(value))
    controller.close()
  } })
  const events = []
  await readEventStream(body, new AbortController().signal, event => { events.push(event) })
  assert.deepEqual(events, [{ event: 'change', data: '{"topic":\n"通知"}' }, { event: 'ready', data: '{}' }])
})

test('the default connection preserves the browser fetch receiver', async t => {
  const controller = new AbortController()
  let attempts = 0, ready = 0, disconnected = 0
  t.mock.method(globalThis, 'fetch', async function (url, options) {
    attempts++
    // Browser Web IDL methods reject a plain object as their receiver. Node's
    // fetch and arrow-function mocks do not, so enforce the browser contract.
    if (this != null && this !== globalThis) throw new TypeError('Illegal invocation')
    assert.equal(url, '/api/v1/events')
    assert.equal(options.signal, controller.signal)
    return streamResponse('event: ready\ndata: {}\n\n')
  })
  await connectEventStream({
    signal: controller.signal,
    ready: () => { ready++; controller.abort() },
    change: () => assert.fail('unexpected change'),
    disconnected: () => { disconnected++; controller.abort() },
    unauthorized: () => assert.fail('unexpected authentication failure'),
  })
  assert.equal(attempts, 1)
  assert.equal(disconnected, 0, 'native fetch failed before sending the event request')
  assert.equal(ready, 1)
})

test('an idle or heartbeat stream never fetches lists and only change events invalidate data', async () => {
  const controller = new AbortController()
  let ready = 0, disconnected = 0, requests = 0
  const changes = []
  await connectEventStream({ signal: controller.signal, ready: () => { ready++ }, change: topic => changes.push(topic), disconnected: () => { disconnected++ }, unauthorized: () => assert.fail('unexpected authentication failure') }, {
    fetch: async (url, options) => {
      requests++
      assert.equal(url, '/api/v1/events')
      assert.equal(options.credentials, 'same-origin')
      return streamResponse('event: ready\ndata: {}\n\nevent: heartbeat\ndata: {}\n\nevent: change\ndata: {"topic":"notifications"}\n\nevent: heartbeat\ndata: {}\n\n')
    },
    wait: async () => controller.abort(),
  })
  assert.equal(requests, 1)
  assert.equal(ready, 1)
  assert.equal(disconnected, 1)
  assert.deepEqual(changes, ['notifications'])
})

test('reconnect requests a new snapshot and cancels the previous reader', async () => {
  const controller = new AbortController()
  let requests = 0, snapshots = 0, retries = 0
  await connectEventStream({ signal: controller.signal, ready: () => { if (++snapshots === 2) controller.abort() }, change: () => {}, disconnected: () => {}, unauthorized: () => assert.fail('unexpected authentication failure') }, {
    fetch: async () => { requests++; return streamResponse('event: ready\ndata: {}\n\n') },
    wait: async () => { retries++ },
  })
  assert.equal(requests, 2)
  assert.equal(snapshots, 2)
  assert.equal(retries, 1)
})

test('HTTP auth rejection and in-stream expiry stop reconnecting', async () => {
  for (const response of [new Response(null, { status: 401 }), new Response(null, { status: 403 }), streamResponse('event: auth-expired\ndata: {}\n\n')]) {
    let rejected = 0, requests = 0
    await connectEventStream({ signal: new AbortController().signal, ready: () => {}, change: () => {}, disconnected: () => assert.fail('auth failure retried'), unauthorized: () => { rejected++ } }, {
      fetch: async () => { requests++; return response },
      wait: async () => assert.fail('authentication must not retry'),
    })
    assert.equal(requests, 1)
    assert.equal(rejected, 1)
  }
})

test('HTTP and response-format failures report their cause and retry only the event connection', async () => {
  for (const [response, expected] of [
    [new Response(null, { status: 404 }), /HTTP 404/],
    [new Response(null, { status: 503 }), /HTTP 503/],
    [new Response('<html>proxy response</html>', { headers: { 'Content-Type': 'text/html' } }), /响应格式异常/],
  ]) {
    const controller = new AbortController()
    const failures = []
    const requests = []
    let retries = 0
    await connectEventStream({
      signal: controller.signal,
      ready: () => assert.fail('failed connection reported ready'),
      change: () => assert.fail('failed connection changed data'),
      disconnected: reason => failures.push(reason),
      unauthorized: () => assert.fail('unavailable service is not an expired login'),
    }, {
      fetch: async url => { requests.push(url); return response },
      wait: async () => { retries++; controller.abort() },
    })
    assert.deepEqual(requests, ['/api/v1/events'])
    assert.equal(retries, 1)
    assert.equal(failures.length, 1)
    assert.match(failures[0], expected)
    assert.ok(!failures[0].includes('proxy response'))
  }
})

test('permission reset reconnects through authentication before refreshing a snapshot', async () => {
  let requests = 0, rejected = 0
  await connectEventStream({ signal: new AbortController().signal, ready: () => assert.fail('unauthorized snapshot'), change: () => {}, disconnected: () => {}, unauthorized: () => { rejected++ } }, {
    fetch: async () => ++requests === 1 ? streamResponse('event: reset\ndata: {}\n\n') : new Response(null, { status: 401 }),
    wait: async () => assert.fail('permission reset should reconnect immediately'),
  })
  assert.equal(requests, 2)
  assert.equal(rejected, 1)
})

test('aborting an idle reader releases its stream', async () => {
  const controller = new AbortController()
  let cancelled = false
  const body = new ReadableStream({ cancel() { cancelled = true } })
  const result = readEventStream(body, controller.signal, () => assert.fail('idle stream emitted data'))
  controller.abort()
  await result
  assert.equal(cancelled, true)
})

test('event invalidations include every formerly polled resource and ignore unknown topics', () => {
  assert.deepEqual([...changedQueryRoots(['notifications'])], ['notifications'])
  const roots = changedQueryRoots(['requests', 'sessions', 'cloud', 'catalog', '__proto__', 'unknown'])
  for (const root of ['requests', 'approvals', 'workflow-progress', 'sessions', 'admin', 'catalog']) assert.ok(roots.has(root))
  assert.ok(!roots.has('notifications'))
  assert.equal(changedQueryRoots(['__proto__', 'unknown']).size, 0)
})
