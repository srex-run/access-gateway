import { expect, test, type Page } from '@playwright/test'
import { generateKeyPairSync } from 'node:crypto'
import { sessionRecordFixture } from './session-record-fixture'
import { mockEncryptedTransport } from './transport-mock'

const sessionID = '55555555-5555-4555-8555-555555555555'
const requestID = '33333333-3333-4333-8333-333333333333'
const terminalPath = `/api/v1/sessions/${sessionID}/terminal`

async function mockTerminalTransport(page: Page) {
  const transport = await mockEncryptedTransport(page)
  await page.route(`**${terminalPath}/demo-defaults`, route => transport.open(route).fulfill({ enabled: false }))
  return transport
}

function deferredResponse() {
  let release!: () => void
  const pending = new Promise<void>(resolve => { release = resolve })
  return { pending, release }
}

async function mockDemoTerminal(page: Page, protocol: string, options: { enabled?: boolean; delay?: Promise<void> } = {}) {
  const messages: Record<string, unknown>[] = []
  const defaultsRequests: Record<string, unknown>[] = []
  const defaultsComplete = deferredResponse()
  await page.route('**/api/v1/**', async route => {
    const path = new URL(route.request().url()).pathname.replace('/api/v1', '')
    const body = path === '/auth/me' ? { user_id: 'applicant', permissions: ['session:manage'] }
      : path === `/session-records/${sessionID}` ? { ...sessionRecordFixture({ id: sessionID, request_id: requestID, status: 'running', can_web_connect: true, can_connect: false, connection_mode: 'audit', audit_policy: { protocol, profile: protocol, revision: 'revision' }, target_account: 'test' }), asset_type: protocol, target_account: 'test' }
      : path === `/sessions/${sessionID}/terminal/preflight` ? { expires_at: new Date(Date.now() + 600000).toISOString() } : []
    await route.fulfill({ json: body })
  })
  const transport = await mockTerminalTransport(page)
  await page.route(`**${terminalPath}/demo-defaults`, async route => {
    expect(route.request().method()).toBe('POST')
    const request = transport.open(route)
    expect(request.body).toEqual({})
    defaultsRequests.push(request.body)
    await options.delay
    try {
      await request.fulfill(options.enabled === false ? { enabled: false } : { enabled: true, password: '123456', database: 'test' })
    } catch (error) {
      // Connecting aborts this request; a released mock response may then be
      // rejected by the browser instead of reaching the component.
      if (!route.request().failure()) throw error
    } finally {
      defaultsComplete.release()
    }
  })
  await page.routeWebSocket(`**${terminalPath}`, ws => {
    ws.onMessage(data => {
      const message = terminalMessage(transport, data)
      messages.push(message)
      if (message.type === 'start') ws.send(JSON.stringify({ type: 'ready' }))
    })
  })
  return { messages, defaultsRequests, defaultsComplete: defaultsComplete.pending }
}

for (const protocol of ['mysql', 'postgresql', 'mongodb', 'redis']) {
  test(`${protocol} demo defaults stay masked and editable before the encrypted terminal start`, async ({ page }) => {
    const { messages, defaultsRequests } = await mockDemoTerminal(page, protocol)
    await page.goto(`/sessions/${sessionID}`)
    const password = page.getByLabel('终端目标密码')
    const database = page.getByLabel('终端数据库', { exact: true })
    await expect(password).toHaveValue('123456')
    await expect(password).toHaveAttribute('type', 'password')
    await expect(password).toBeEditable()
    await expect(database).toHaveValue(protocol === 'redis' ? '0' : 'test')
    await password.fill('custom-demo-password')
    await database.fill(protocol === 'redis' ? '2' : 'application')
    await page.getByRole('button', { name: '连接终端', exact: true }).click()
    await expect(page.getByText('已连接', { exact: true })).toBeVisible()
    expect(messages[0]).toMatchObject({ type: 'start', password: 'custom-demo-password', database: protocol === 'redis' ? '2' : 'application' })
    await page.getByRole('button', { name: '断开终端', exact: true }).click()
    await expect(password).toHaveValue('')
    await expect(database).toHaveValue(protocol === 'redis' ? '2' : 'application')
    expect(defaultsRequests).toHaveLength(1)
    expect(await page.evaluate(() => JSON.stringify({ ...localStorage, ...sessionStorage }))).not.toContain('custom-demo-password')
  })
}

test('demo credentials can connect unchanged through the encrypted terminal start', async ({ page }) => {
  const { messages } = await mockDemoTerminal(page, 'mysql')
  await page.goto(`/sessions/${sessionID}`)
  await expect(page.getByLabel('终端目标密码')).toHaveValue('123456')
  await expect(page.getByLabel('终端数据库', { exact: true })).toHaveValue('test')
  await page.getByRole('button', { name: '连接终端', exact: true }).click()
  await expect(page.getByText('已连接', { exact: true })).toBeVisible()
  expect(messages[0]).toMatchObject({ type: 'start', password: '123456', database: 'test' })
})

for (const clearedField of ['password', 'database']) {
  test(`late demo defaults preserve a ${clearedField} explicitly cleared by the user`, async ({ page }) => {
    const response = deferredResponse()
    const { defaultsRequests } = await mockDemoTerminal(page, 'postgresql', { delay: response.pending })
    await page.goto(`/sessions/${sessionID}`)
    await expect.poll(() => defaultsRequests.length).toBe(1)
    const password = page.getByLabel('终端目标密码')
    const database = page.getByLabel('终端数据库', { exact: true })
    const edited = clearedField === 'password' ? password : database
    await edited.fill('temporary-value')
    await edited.fill('')
    response.release()
    // The untouched field applying its default confirms the delayed response
    // has been consumed before checking the field deliberately left empty.
    await expect(clearedField === 'password' ? database : password).toHaveValue(clearedField === 'password' ? 'test' : '123456')
    await expect(edited).toHaveValue('')
  })
}

test('connecting aborts pending demo defaults and a late response cannot refill a disconnected terminal', async ({ page }) => {
  const response = deferredResponse()
  const { messages, defaultsRequests, defaultsComplete } = await mockDemoTerminal(page, 'mysql', { delay: response.pending })
  await page.goto(`/sessions/${sessionID}`)
  await expect.poll(() => defaultsRequests.length).toBe(1)
  const aborted = page.waitForEvent('requestfailed', request => new URL(request.url()).pathname === `${terminalPath}/demo-defaults`)
  await page.getByRole('button', { name: '连接终端', exact: true }).click()
  await aborted
  await expect(page.getByText('已连接', { exact: true })).toBeVisible()
  expect(messages[0]).toMatchObject({ type: 'start', password: '', database: '' })
  await page.getByRole('button', { name: '断开终端', exact: true }).click()
  response.release()
  await defaultsComplete
  await expect(page.getByLabel('终端目标密码')).toHaveValue('')
  await expect(page.getByLabel('终端数据库', { exact: true })).toHaveValue('')
  expect(defaultsRequests).toHaveLength(1)
})

for (const [protocol, database] of [['mysql', ''], ['postgresql', 'postgres'], ['mongodb', 'test'], ['redis', '0']] as const) {
  test(`${protocol} keeps its original login defaults when demo defaults are disabled`, async ({ page }) => {
    const { messages, defaultsComplete } = await mockDemoTerminal(page, protocol, { enabled: false })
    await page.goto(`/sessions/${sessionID}`)
    await defaultsComplete
    await expect(page.getByLabel('终端目标密码')).toHaveValue('')
    await expect(page.getByLabel('终端数据库', { exact: true })).toHaveValue(database)
    await page.getByRole('button', { name: '连接终端', exact: true }).click()
    await expect(page.getByText('已连接', { exact: true })).toBeVisible()
    expect(messages[0]).toMatchObject({ type: 'start', password: '', database })
  })
}

test('SSH unencrypted private key survives denied preflight and connects in an encrypted frame', async ({ page }) => {
  const { privateKey } = generateKeyPairSync('ed25519', { publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } })
  let permitted = false
  let opened = 0
  const messages: Record<string, unknown>[] = []
  await page.route('**/api/v1/**', async route => {
    const path = new URL(route.request().url()).pathname.replace('/api/v1', '')
    if (path === `/sessions/${sessionID}/terminal/preflight`) return route.fulfill({ status: permitted ? 200 : 403, json: permitted ? { expires_at: new Date(Date.now() + 600000).toISOString() } : { error: 'forbidden', code: 'terminal_unavailable' } })
    const body = path === '/auth/me' ? { user_id: 'applicant', permissions: ['session:manage'] }
      : path === `/session-records/${sessionID}` ? { ...sessionRecordFixture({ id: sessionID, request_id: requestID, status: 'running', can_web_connect: true, can_connect: false, connection_mode: 'audit', audit_policy: { protocol: 'ssh', profile: 'ssh', revision: 'revision' }, target_account: 'reader' }), asset_type: 'ssh', target_account: 'reader' } : []
    await route.fulfill({ json: body })
  })
  const transport = await mockTerminalTransport(page)
  await page.routeWebSocket(`**${terminalPath}`, ws => {
    opened++
    ws.onMessage(data => {
      const message = terminalMessage(transport, data)
      messages.push(message)
      if (message.type === 'start') {
        ws.send(JSON.stringify({ type: 'ready' }))
        ws.send(Buffer.from('reader@target:~$ '))
      }
    })
  })
  await page.goto(`/sessions/${sessionID}`)
  await page.getByLabel('终端认证方式').click()
  await page.getByRole('option', { name: 'SSH 私钥', exact: true }).click()
  await page.getByLabel('终端 SSH 私钥').fill(privateKey)
  await page.getByRole('button', { name: '连接终端', exact: true }).click()
  await expect(page.getByText('当前会话不可连接，请确认会话仍在有效期内，并使用申请账号登录。', { exact: true })).toBeVisible()
  expect(opened).toBe(0)
  await expect(page.getByLabel('终端 SSH 私钥')).toHaveValue(privateKey)
  permitted = true
  await page.getByRole('button', { name: '连接终端', exact: true }).click()
  await expect(page.getByText('已连接', { exact: true })).toBeVisible()
  await expect(page.locator('.xterm-rows')).toContainText('reader@target:~$')
  await expect(page.locator('.xterm-helper-textarea')).toBeFocused()
  await expect(page.locator('.xterm-cursor-blink')).toBeVisible()
  await page.keyboard.type('pwd')
  await page.keyboard.press('Enter')
  await expect.poll(() => messages.filter(message => message.type === 'input').map(message => message.data).join('')).toBe('pwd\r')
  expect(messages[0]).toMatchObject({ type: 'start', private_key: privateKey, passphrase: '' })
  expect(messages[0]).not.toHaveProperty('password')
  await page.getByRole('button', { name: '断开终端', exact: true }).click()
  await expect(page.getByLabel('终端 SSH 私钥')).toHaveValue('')
  expect(await page.evaluate(() => JSON.stringify({ ...localStorage, ...sessionStorage }))).not.toContain(privateKey)
})

function terminalMessage(transport: Awaited<ReturnType<typeof mockEncryptedTransport>>, data: string | Buffer): Record<string, unknown> {
  const wire = JSON.parse(String(data)) as Record<string, unknown>
  expect(wire.type).not.toBe('start')
  for (const field of ['password', 'private_key', 'passphrase']) expect(wire).not.toHaveProperty(field)
  return 'challenge_id' in wire ? transport.open({ message: String(data), path: terminalPath }).body : wire
}

test('PostgreSQL terminal regains focus and accepts Enter after a query error', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop', 'mouse hover and keyboard interactions')
  const queries: string[] = []
  let pending = ''
  let opened = 0
  await page.route('**/api/v1/**', async route => {
    const path = new URL(route.request().url()).pathname.replace('/api/v1', '')
    const body = path === '/auth/me' ? { user_id: 'applicant', permissions: ['session:manage'] }
      : path === `/session-records/${sessionID}` ? { ...sessionRecordFixture({ id: sessionID, request_id: requestID, status: 'running', can_web_connect: true, can_connect: false, connection_mode: 'audit', audit_policy: { protocol: 'postgresql', profile: 'postgresql', revision: 'revision' }, target_account: 'test' }), asset_type: 'postgresql', target_account: 'test' } : []
    await route.fulfill({ json: body })
  })
  const transport = await mockTerminalTransport(page)
  await page.routeWebSocket(`**${terminalPath}`, ws => {
    opened++
    ws.onMessage(data => {
      const message = terminalMessage(transport, data)
      if (message.type === 'start') {
        ws.send(JSON.stringify({ type: 'ready' }))
        ws.send(Buffer.from('test=> '))
      } else if (message.type === 'input') {
        for (const character of String(message.data)) {
          if (character !== '\r') {
            pending += character
            ws.send(Buffer.from(character))
            continue
          }
          queries.push(pending)
          // These are PTY bytes, including the prompt emitted by psql.
          ws.send(Buffer.from(pending.includes('gateway_test')
            ? '\r\nERROR:  relation "gateway_test" does not exist\r\nLINE 1: SELECT * FROM gateway_test;\r\n                      ^\r\ntest=> '
            : pending ? '\r\n ?column?\r\n----------\r\n        1\r\n(1 row)\r\ntest=> ' : '\r\ntest=> '))
          pending = ''
        }
      }
    })
  })
  await page.goto(`/sessions/${sessionID}`)
  await page.getByLabel('终端目标密码').fill('123456')
  await page.getByLabel('终端数据库', { exact: true }).fill('test')
  await page.getByRole('button', { name: '连接终端', exact: true }).click()
  await expect(page.getByText('已连接', { exact: true })).toBeVisible()
  await expect(page.locator('.xterm-rows')).toContainText('test=>')

  const refresh = page.getByRole('button', { name: '刷新会话详情', exact: true })
  const screen = page.locator('.terminal-screen')
  const input = page.locator('.xterm-helper-textarea')
  let navigations = 0
  let pageEnters = 0
  page.on('framenavigated', frame => { if (frame === page.mainFrame()) navigations++ })
  // A page shortcut must not receive Enter intended for the terminal.
  await page.exposeFunction('terminalTestPageEnter', () => { pageEnters++ })
  await page.evaluate(() => {
    document.addEventListener('keydown', event => {
      if (event.key === 'Enter') void (window as unknown as { terminalTestPageEnter: () => Promise<void> }).terminalTestPageEnter()
    })
  })

  await refresh.hover()
  await refresh.focus()
  await expect(input).not.toBeFocused()
  // xterm never blinks the caret while unfocused, so the hint carries that signal.
  const hint = page.getByRole('button', { name: '点击终端继续输入', exact: true })
  await expect(hint).toBeVisible()
  await expect(page.locator('.xterm-cursor-blink')).toHaveCount(0)
  await hint.click()
  await expect(input).toBeFocused()
  await expect(hint).toBeHidden()
  await expect(page.locator('.xterm-cursor-blink')).toBeVisible()
  await refresh.focus()
  await expect(input).not.toBeFocused()
  // Exercise the padding too: it lies outside xterm's own mouse handlers.
  await screen.hover({ position: { x: 4, y: 4 } })
  await expect(input).toBeFocused()
  await expect(page.locator('.xterm-cursor-blink')).toBeVisible()
  await page.keyboard.type('SELECT * FROM gateway_test;')
  await page.keyboard.press('Enter')
  await expect(page.locator('.xterm-rows')).toContainText('relation "gateway_test" does not exist')
  await expect.poll(() => queries).toEqual(['SELECT * FROM gateway_test;'])

  await refresh.hover()
  await refresh.focus()
  await screen.hover({ position: { x: 4, y: 4 } })
  await expect(input).toBeFocused()
  await expect(page.locator('.xterm-cursor-blink')).toBeVisible()
  await page.keyboard.press('Enter')
  await page.keyboard.type('SELECT 1;')
  await page.keyboard.press('Enter')
  await expect.poll(() => queries).toEqual(['SELECT * FROM gateway_test;', '', 'SELECT 1;'])
  await expect(page.locator('.xterm-rows')).toContainText('(1 row)')
  await expect(page.getByText('已连接', { exact: true })).toBeVisible()
  expect(opened).toBe(1)
  expect(navigations).toBe(0)
  expect(pageEnters).toBe(0)
})

for (const protocol of ['mysql', 'postgresql', 'redis', 'mongodb', 'http']) {
  test(`${protocol} provides a web client without enabling public client access`, async ({ page }) => {
    const messages: Record<string, unknown>[] = []
    await page.route('**/api/v1/**', async route => {
      const path = new URL(route.request().url()).pathname.replace('/api/v1', '')
      let body: unknown = []
      if (path === '/auth/me') body = { user_id: 'applicant', permissions: ['directory:read', 'request:manage', 'session:manage'] }
      if (path === `/session-records/${sessionID}`) body = { ...sessionRecordFixture({ id: sessionID, request_id: requestID, status: 'running', can_web_connect: true, can_connect: false, connection_mode: 'audit', audit_policy: { protocol, profile: protocol, revision: 'revision' }, target_account: 'admin', source_ip: '', gateway_host: '', gateway_port: 0 }), asset_type: protocol, target_account: protocol === 'http' ? '' : 'admin' }
      await route.fulfill({ json: body })
    })
    const transport = await mockTerminalTransport(page)
    await page.routeWebSocket(`**/api/v1/sessions/${sessionID}/terminal`, ws => {
      ws.onMessage(data => {
        const message = terminalMessage(transport, data)
        messages.push(message)
        if (message.type === 'start') ws.send(JSON.stringify({ type: 'ready' }))
      })
    })
    await page.goto(`/sessions/${sessionID}`)
    await expect(page.getByRole('region', { name: '站内终端' })).toBeVisible()
    await expect(page.getByLabel('终端认证方式')).toHaveCount(0)
    if (protocol !== 'http') {
      await expect(page.getByLabel('终端目标账号')).toHaveValue('admin')
      await expect(page.getByLabel('终端目标账号')).toHaveAttribute('readonly', '')
      await page.getByLabel('终端目标密码').fill('temporary-client-password')
      await page.getByLabel('终端数据库', { exact: true }).fill(protocol === 'redis' ? '2' : 'application')
    }
    if (protocol === 'mongodb') await page.getByLabel('终端认证数据库').fill('admin')
    await page.getByRole('button', { name: '连接终端', exact: true }).click()
    await expect.poll(() => messages.length).toBeGreaterThan(0)
    expect(messages[0]?.type).toBe('start')
    expect(messages[0]).not.toHaveProperty('host')
    expect(messages[0]).not.toHaveProperty('port')
    expect(messages[0]).not.toHaveProperty('username')
    expect(messages[0]).not.toHaveProperty('private_key')
    if (protocol !== 'http') expect(messages[0]).toMatchObject({ password: 'temporary-client-password', database: protocol === 'redis' ? '2' : 'application' })
    if (protocol === 'mongodb') expect(messages[0]?.auth_source).toBe('admin')
    await page.getByRole('button', { name: '断开终端', exact: true }).click()
    if (protocol !== 'http') await expect(page.getByLabel('终端目标密码')).toHaveValue('')
  })
}

test('web terminal uses WSS and keeps client access alongside it', async ({ page }) => {
  const messages: Record<string, unknown>[] = []
  await page.route('**/api/v1/**', async route => {
    const path = new URL(route.request().url()).pathname.replace('/api/v1', '')
    let body: unknown = []
    if (path === '/auth/me') body = { user_id: 'applicant', permissions: ['directory:read', 'request:manage', 'session:manage'] }
    if (path === `/session-records/${sessionID}`) body = { ...sessionRecordFixture({ id: sessionID, request_id: requestID, status: 'running', can_web_connect: true, can_connect: true, connection_mode: 'audit', audit_policy: { protocol: 'ssh', profile: 'ssh', revision: 'revision' }, target_account: 'reader', source_ip: '192.0.2.1', gateway_host: 'gateway.test', gateway_port: 20001 }), asset_type: 'ssh', target_account: 'reader' }
    await route.fulfill({ json: body })
  })
  const transport = await mockTerminalTransport(page)
  await page.routeWebSocket(`**/api/v1/sessions/${sessionID}/terminal`, ws => {
    ws.onMessage(data => {
      const message = terminalMessage(transport, data)
      messages.push(message)
      if (message.type === 'start') { ws.send(JSON.stringify({ type: 'ready' })); ws.send(Buffer.from('terminal-ready\r\n')) }
    })
  })
  await page.goto(`/sessions/${sessionID}`)
  await expect(page.getByRole('region', { name: '站内终端' })).toBeVisible()
  await expect(page.getByRole('region', { name: '客户端连接', exact: true })).toBeVisible()
  await page.getByLabel('终端目标密码').fill('ephemeral-browser-password')
  await page.getByRole('button', { name: '连接终端', exact: true }).click()
  await expect.poll(() => messages.length).toBeGreaterThan(0)
  expect(messages[0]).toMatchObject({ type: 'start', password: 'ephemeral-browser-password' })
  await expect(page.getByText('已连接', { exact: true })).toBeVisible()
  await page.getByRole('button', { name: '断开终端', exact: true }).click()
  await expect(page.getByText('已断开', { exact: true })).toBeVisible()
  await expect(page.getByLabel('终端目标密码')).toHaveValue('')
  const stored = await page.evaluate(() => JSON.stringify({ ...localStorage, ...sessionStorage }))
  expect(stored).not.toContain('ephemeral-browser-password')
})

test('request form defaults to web access and hides client controls until enabled', async ({ page }) => {
  await page.route('**/api/v1/**', async route => {
    const path = new URL(route.request().url()).pathname.replace('/api/v1', '')
    await route.fulfill({ json: path === '/auth/me' ? { user_id: 'applicant', permissions: ['directory:read', 'request:manage', 'session:manage'] } : path === '/access-options' ? { client_access_enabled: false } : [] })
  })
  await page.goto('/requests/new')
  await expect(page.getByLabel('来源 IP', { exact: true })).toHaveCount(0)
  await expect(page.getByRole('checkbox', { name: '同时启用本地客户端访问' })).toHaveCount(0)
  await expect(page.getByText('站内访问', { exact: true })).toBeVisible()
})

test('native terminal streams bytes and forwards shell interactions and window size', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop', 'desktop fullscreen and keyboard interactions')
  const messages: Record<string, unknown>[] = []
  const binary: Buffer[] = []
  let send: (data: string | Buffer) => void = () => { throw new Error('terminal socket not connected') }
  let close: () => void = () => { throw new Error('terminal socket not connected') }
  await page.route('**/api/v1/**', async route => {
    const path = new URL(route.request().url()).pathname.replace('/api/v1', '')
    let body: unknown = []
    if (path === '/auth/me') body = { user_id: 'applicant', permissions: ['directory:read', 'request:manage', 'session:manage'] }
    if (path === `/session-records/${sessionID}`) body = { ...sessionRecordFixture({ id: sessionID, request_id: requestID, status: 'running', can_web_connect: true, can_connect: false, connection_mode: 'audit', audit_policy: { protocol: 'ssh', profile: 'ssh', revision: 'revision' }, target_account: 'reader', source_ip: '', gateway_host: '', gateway_port: 0 }), asset_type: 'ssh', target_account: 'reader' }
    await route.fulfill({ json: body })
  })
  const transport = await mockTerminalTransport(page)
  await page.routeWebSocket(`**/api/v1/sessions/${sessionID}/terminal`, ws => {
    send = data => ws.send(data)
    close = () => ws.close({ code: 1011, reason: 'test interruption' })
    ws.onMessage(data => {
      if (typeof data === 'string') messages.push(terminalMessage(transport, data))
      else binary.push(Buffer.from(data))
    })
  })
  const input = () => messages.filter(message => message.type === 'input').map(message => message.data).join('')
  const sizes = () => messages.filter(message => message.type === 'resize')
  const expectTerminalFits = async () => {
    await expect.poll(() => page.locator('.terminal-host').evaluate(host => {
      const screen = host.querySelector('.xterm-screen')!.getBoundingClientRect()
      const bounds = host.getBoundingClientRect()
      return screen.bottom <= bounds.bottom && screen.right <= bounds.right
    })).toBe(true)
  }
  await page.goto(`/sessions/${sessionID}`)
  await page.getByLabel('终端目标密码').fill('ephemeral-shell-password')
  await page.getByRole('button', { name: '连接终端', exact: true }).click()
  await expect.poll(() => messages.length).toBe(1)
  await expect(page.getByText('连接中', { exact: true })).toBeVisible()
  const startCols = Number(messages[0]?.cols)
  await page.setViewportSize({ width: 1000, height: 720 })
  await expect(page.locator('.terminal-panel')).toHaveCSS('width', /\d+px/)
  send(JSON.stringify({ type: 'ready' }))
  await expect.poll(() => sizes().length).toBeGreaterThan(0)
  await expect.poll(() => Number(sizes().at(-1)?.cols)).toBeLessThan(startCols)
  await expectTerminalFits()

  // Real PTY reads can split UTF-8 code points across binary WebSocket frames.
  const output = Buffer.from('流式响应：\x1b[32mnative shell ready\x1b[0m\r\n$ ')
  send(output.subarray(0, 2))
  send(output.subarray(2))
  await expect(page.locator('.xterm-rows')).toContainText('流式响应：native shell ready')
  await expect(page.locator('.xterm-helper-textarea')).toBeFocused()
  await expect(page.locator('.xterm-cursor-blink')).toBeVisible()
  await page.keyboard.type('echo hello')
  await page.keyboard.press('ArrowUp')
  await page.keyboard.press('Tab')
  await page.keyboard.press('Control+c')
  await page.keyboard.insertText('中文')
  await expect.poll(input).toContain('echo hello\x1b[A\t\x03中文')

  // Let xterm apply bracketed-paste semantics and chunk a large Unicode paste.
  send(Buffer.from('\x1b[?2004h\r\npaste-ready\r\n'))
  await expect(page.locator('.xterm-rows')).toContainText('paste-ready')
  await page.locator('.xterm-helper-textarea').evaluate(element => {
    const clipboard = new DataTransfer()
    clipboard.setData('text/plain', '粘贴内容'.repeat(2000))
    element.dispatchEvent(new ClipboardEvent('paste', { bubbles: true, clipboardData: clipboard }))
  })
  await expect.poll(input).toContain(`\x1b[200~${'粘贴内容'.repeat(2000)}\x1b[201~`)
  for (const message of messages.filter(message => message.type === 'input')) expect(Buffer.byteLength(String(message.data))).toBeLessThanOrEqual(16384)

  const rows = Number(sizes().at(-1)?.rows)
  await page.getByRole('button', { name: '全屏终端', exact: true }).click()
  await expect(page.locator('.terminal-panel:fullscreen')).toBeVisible()
  await expect.poll(() => Number(sizes().at(-1)?.rows)).toBeGreaterThan(rows)
  const cols = Number(sizes().at(-1)?.cols)
  await page.getByLabel('终端字号').click()
  await page.getByRole('option', { name: '18 px', exact: true }).click()
  await expect.poll(() => Number(sizes().at(-1)?.cols)).toBeLessThan(cols)
  await expectTerminalFits()

  // Fullscreen programs use an alternate buffer and legacy mouse reports.
  send(Buffer.from('\x1b[?1049h\x1b[2J\x1b[Hnative-fullscreen-app\x1b[?1000h'))
  await expect(page.locator('.xterm-rows')).toContainText('native-fullscreen-app')
  await page.locator('.xterm-screen').click({ position: { x: 400, y: 150 } })
  await expect.poll(() => binary.length).toBeGreaterThan(0)
  expect(binary[0]?.subarray(0, 3).toString()).toBe('\x1b[M')
  send(Buffer.from('\x1b[?1000l\x1b[?1049l'))
  await expect(page.locator('.xterm-rows')).toContainText('native shell ready')
  const interrupted = messages.filter(message => message.type === 'input' && message.data === '\x03').length
  await page.getByRole('button', { name: '中断 Ctrl+C', exact: true }).click()
  await expect.poll(() => messages.filter(message => message.type === 'input' && message.data === '\x03').length).toBe(interrupted + 1)
  await page.screenshot({ path: testInfo.outputPath('native-terminal-fullscreen.png') })
  await page.getByRole('button', { name: '退出全屏', exact: true }).click()
  await expect(page.locator('.terminal-panel:fullscreen')).toHaveCount(0)
  await expectTerminalFits()
  for (const trigger of ['keyboard', 'button']) {
    send(Buffer.from(Array.from({ length: 80 }, (_, index) => `\r\nold-output-${index}`).join('') + '\r\n$ pending-input'))
    await expect(page.locator('.xterm-rows')).toContainText('$ pending-input')
    const clears = messages.filter(message => message.type === 'input' && message.data === '\x0c').length
    if (trigger === 'keyboard') {
      await page.locator('.xterm-helper-textarea').focus()
      await page.keyboard.press('Control+l')
    } else await page.getByRole('button', { name: '清屏 Ctrl+L', exact: true }).click()
    await expect.poll(() => messages.filter(message => message.type === 'input' && message.data === '\x0c').length).toBe(clears + 1)
    await expect(page.locator('.xterm-rows')).not.toContainText('old-output-')
    await expect(page.locator('.xterm-rows')).toContainText('$ pending-input')
    await expect(page.locator('.xterm-helper-textarea')).toBeFocused()
  }
  close()
  await expect(page.getByText('终端连接已中断，请重新连接。')).toBeVisible()
  await expect(page.getByLabel('终端目标密码')).toHaveValue('')
  await page.getByLabel('终端目标密码').fill('new-ephemeral-password')
  await page.getByRole('button', { name: '连接终端', exact: true }).click()
  await expect.poll(() => messages.filter(message => message.type === 'start').length).toBe(2)
  send(JSON.stringify({ type: 'ready' }))
  await expect(page.getByText('已连接', { exact: true })).toBeVisible()
  send(Buffer.from('reader@target:~$ '))
  await expect(page.locator('.xterm-rows')).toContainText('reader@target:~$')
  await expect(page.locator('.xterm-helper-textarea')).toBeFocused()
  await page.getByRole('button', { name: '断开终端', exact: true }).click()
  const stored = await page.evaluate(() => JSON.stringify({ ...localStorage, ...sessionStorage }))
  expect(stored).not.toContain('ephemeral')
})
