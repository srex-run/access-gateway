interface StreamEvent { event: string; data: string }

// Streaming fetch exposes 401/403 to the caller, unlike EventSource.onerror.
// The decoder preserves UTF-8 and SSE records split across network chunks.
export async function readEventStream(body: ReadableStream<Uint8Array>, signal: AbortSignal, receive: (event: StreamEvent) => boolean | void) {
  const reader = body.getReader()
  const decoder = new TextDecoder()
  let buffer = '', event = '', data: string[] = []
  const abort = () => { void reader.cancel().catch(() => undefined) }
  signal.addEventListener('abort', abort, { once: true })
  try {
    while (!signal.aborted) {
      const chunk = await reader.read()
      if (chunk.done) return
      buffer += decoder.decode(chunk.value, { stream: true })
      let boundary: number
      while ((boundary = buffer.indexOf('\n')) >= 0) {
        const line = buffer.slice(0, boundary).replace(/\r$/, '')
        buffer = buffer.slice(boundary + 1)
        if (!line) {
          if (data.length && receive({ event: event || 'message', data: data.join('\n') }) === false) return
          event = ''; data = []
        } else if (!line.startsWith(':')) {
          const colon = line.indexOf(':')
          const field = colon < 0 ? line : line.slice(0, colon)
          const value = colon < 0 ? '' : line.slice(colon + 1).replace(/^ /, '')
          if (field === 'event') event = value
          if (field === 'data') data.push(value)
        }
        if (event.length + data.reduce((size, value) => size + value.length, 0) > 65_536) throw new Error('Event stream frame too large')
      }
      if (buffer.length > 65_536) throw new Error('Event stream line too large')
    }
  } finally {
    signal.removeEventListener('abort', abort)
    await reader.cancel().catch(() => undefined)
    reader.releaseLock()
  }
}

interface StreamCallbacks {
  signal: AbortSignal
  ready: () => void
  change: (topic: string) => void
  disconnected: (reason: string) => void
  unauthorized: () => void
}

function waitForRetry(ms: number, signal: AbortSignal) {
  return new Promise<void>(resolve => {
    const finish = () => { clearTimeout(timer); signal.removeEventListener('abort', finish); resolve() }
    const timer = setTimeout(finish, ms)
    signal.addEventListener('abort', finish, { once: true })
    if (signal.aborted) finish()
  })
}

// Native browser fetch requires the global receiver. Calling an unbound fetch
// through the dependency object otherwise throws before any request is sent.
export async function connectEventStream(callbacks: StreamCallbacks, dependencies = { fetch: globalThis.fetch.bind(globalThis), wait: waitForRetry }) {
  const { signal } = callbacks
  let retry = 1000
  while (!signal.aborted) {
    let reset = false, unauthorized = false
    let failure = '实时更新已断开，正在重新连接。'
    try {
      const response = await dependencies.fetch('/api/v1/events', { credentials: 'same-origin', cache: 'no-store', headers: { Accept: 'text/event-stream' }, signal })
      if (response.status === 401 || response.status === 403) {
        await response.body?.cancel()
        if (!signal.aborted) callbacks.unauthorized()
        return
      }
      if (!response.ok) {
        failure = `实时更新服务暂时不可用（HTTP ${response.status}），正在重新连接。`
        await response.body?.cancel()
        throw new Error('Event stream request failed')
      }
      if (!response.headers.get('Content-Type')?.startsWith('text/event-stream') || !response.body) {
        failure = '实时更新响应格式异常，正在重新连接。'
        await response.body?.cancel()
        throw new Error('Event stream unavailable')
      }
      await readEventStream(response.body, signal, message => {
        if (signal.aborted) return false
        if (message.event === 'ready') { retry = 1000; callbacks.ready() }
        if (message.event === 'change') {
          const data: unknown = JSON.parse(message.data)
          if (data && typeof data === 'object' && 'topic' in data && typeof data.topic === 'string') callbacks.change(data.topic)
        }
        if (message.event === 'reset') { reset = true; return false }
        if (message.event === 'auth-expired') { unauthorized = true; callbacks.unauthorized(); return false }
      })
    } catch {
      // Only connection failures retry; business queries have no interval.
    }
    if (signal.aborted || unauthorized) return
    if (reset) continue
    callbacks.disconnected(failure)
    await dependencies.wait(Math.round(retry * (0.8 + Math.random() * 0.4)), signal)
    retry = Math.min(retry * 2, 30_000)
  }
}
