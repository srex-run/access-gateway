import assert from 'node:assert/strict'
import { afterEach, test } from 'node:test'
import { generateKeyPairSync, privateDecrypt, hkdfSync, createDecipheriv, createCipheriv, randomBytes, constants } from 'node:crypto'
import { encryptedFetch, requiresEncryption, sealTerminalStart } from '../src/shared/api/transport.mjs'

const originalFetch = globalThis.fetch
afterEach(() => { globalThis.fetch = originalFetch })
const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
const prefix = 'access-gateway/browser-transport/v1'

test('all current browser credential operations require encryption', () => {
  for (const [method, path] of [
    ['POST', '/auth/local/login'], ['POST', '/auth/ldap/login'], ['POST', '/auth/password'],
    ['PATCH', '/admin/settings'], ['POST', '/admin/cloud-accounts'], ['PATCH', '/admin/cloud-accounts/account'],
    ['POST', '/admin/assets'], ['POST', '/admin/gateways/gateway/release'],
    ['PATCH', '/admin/assets/asset'],
    ['POST', '/admin/users'],
    ['POST', '/admin/invitations'], ['POST', '/admin/invitations/invite/resend'],
    ['POST', '/auth/invitation/preview'], ['POST', '/auth/invitation/accept'],
    ['POST', '/auth/mfa/enroll'], ['POST', '/auth/mfa/confirm'], ['POST', '/auth/mfa/verify'],
    ['POST', '/auth/account/mfa/enroll'], ['POST', '/auth/account/mfa/recovery-codes'], ['POST', '/auth/account/mfa/unbind'],
    ['POST', '/admin/settings/audit/certificates'],
    ['POST', '/admin/assets/audit/certificates'],
    ['GET', '/sessions/session/terminal'],
    ['POST', '/sessions/session/terminal/demo-defaults'],
  ]) assert.equal(requiresEncryption(method, '/api/v1' + path), true)
  assert.equal(requiresEncryption('GET', '/api/v1/admin/cloud-accounts'), false)
  assert.equal(requiresEncryption('POST', '/api/v1/admin/cloud-accounts/account/sync'), false)
  assert.equal(requiresEncryption('PATCH', '/api/v1/admin/assets/asset/status'), false)
  assert.equal(requiresEncryption('POST', '/api/v1/admin/assets/asset/ports'), false)
  assert.equal(requiresEncryption('GET', '/api/v1/sessions/session/terminal/demo-defaults'), false)
})

test('terminal encrypts the complete first frame and binds each login to its WebSocket path', async () => {
  const path = '/api/v1/sessions/session/terminal'
  const controller = new AbortController()
  let challenge
  let count = 0
  globalThis.fetch = async (url, options) => {
    assert.equal(url, '/api/v1/auth/transport/challenges')
    assert.deepEqual(JSON.parse(options.body), { method: 'GET', path })
    assert.equal(options.signal, controller.signal)
    assert.equal(options.cache, 'no-store')
    assert.equal(options.redirect, 'error')
    assert.equal(options.credentials, 'same-origin')
    challenge = { id: `terminal-${++count}`, kid: 'test-key', method: 'GET', path, subject: 'user:test', algorithm: 'RSA-OAEP-256+A256GCM', public_key: publicKey.export({ type: 'spki', format: 'pem' }) }
    return Response.json(challenge)
  }
  for (const credentials of [{ password: 'terminal-password' }, { private_key: 'terminal-private-key', passphrase: 'terminal-key-passphrase' }]) {
    const payload = { type: 'start', cols: 80, rows: 24, ...credentials }
    const sealed = await sealTerminalStart(path, payload, controller.signal)
    for (const value of Object.values(credentials)) assert.equal(JSON.stringify(sealed).includes(value), false)
    assert.equal(sealed.challenge_id, challenge.id)
    const { envelope } = sealed
    const seed = privateDecrypt({ key: privateKey, oaepHash: 'sha256', padding: constants.RSA_PKCS1_OAEP_PADDING }, Buffer.from(envelope.encrypted_key, 'base64'))
    const key = hkdfSync('sha256', seed, Buffer.alloc(0), `${prefix}/request`, 32)
    const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(envelope.nonce, 'base64'))
    decipher.setAAD(Buffer.from([prefix, 'request', challenge.id, challenge.kid, challenge.method, path, challenge.subject].join('\n')))
    const ciphertext = Buffer.from(envelope.ciphertext, 'base64')
    decipher.setAuthTag(ciphertext.subarray(-16))
    assert.deepEqual(JSON.parse(Buffer.concat([decipher.update(ciphertext.subarray(0, -16)), decipher.final()])), payload)
    seed.fill(0)
  }
  assert.equal(count, 2)
})

test('terminal refuses missing encryption, failed challenges and challenge substitution', async () => {
  const path = '/api/v1/sessions/session/terminal'
  let calls = 0
  globalThis.fetch = async () => { calls++; return Response.json({}, { status: 503 }) }
  await assert.rejects(() => sealTerminalStart(path, { password: 'secret' }), /加密凭据/)
  assert.equal(calls, 1)
  globalThis.fetch = async () => Response.json({ id: 'id', kid: 'key', method: 'GET', path: '/another-session', subject: 'user:test' })
  await assert.rejects(() => sealTerminalStart(path, { password: 'secret' }), /挑战校验/)
  await assert.rejects(() => sealTerminalStart(path + '?password=secret', {}), /请求地址/)
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto')
  try {
    Object.defineProperty(globalThis, 'crypto', { value: undefined, configurable: true })
    globalThis.fetch = async () => { throw new Error('must not request without encryption') }
    await assert.rejects(() => sealTerminalStart(path, { password: 'secret' }), /HTTPS/)
  } finally { Object.defineProperty(globalThis, 'crypto', descriptor) }
})

for (const scenario of [
  { name: 'nested secrets', method: 'PATCH', path: '/api/v1/admin/settings', payload: { pass: 'secret-pass', password: 'password-value', key: 'key-value', nested: { apikey: 'apikey-value', secret_key: 'sk-value' } }, response: { private_key: 'download-secret' } },
  { name: 'enabled demo terminal defaults', method: 'POST', path: '/api/v1/sessions/session/terminal/demo-defaults', payload: {}, response: { enabled: true, password: '123456', database: 'test' } },
  { name: 'disabled demo terminal defaults', method: 'POST', path: '/api/v1/sessions/session/terminal/demo-defaults', payload: {}, response: { enabled: false } },
]) test(`fetch encrypts ${scenario.name} and decrypts responses, with a fresh challenge for each submission`, async () => {
  let count = 0
  let challenge
  const { method, path, payload } = scenario
  const controller = new AbortController()
  globalThis.fetch = async (url, options) => {
    assert.equal(options.cache, 'no-store')
    assert.equal(options.credentials, 'same-origin')
    assert.equal(options.signal, controller.signal)
    assert.equal(options.redirect, 'error')
    if (url === '/api/v1/auth/transport/challenges') {
      count++
      assert.deepEqual(JSON.parse(options.body), { method, path })
      challenge = { id: `challenge-${count}`, kid: 'test-key', method, path, subject: 'user:test', algorithm: 'RSA-OAEP-256+A256GCM', public_key: publicKey.export({ format: 'pem', type: 'spki' }) }
      return Response.json(challenge)
    }
    assert.equal(url, path)
    assert.equal(options.method, method)
    for (const value of ['secret-pass', 'password-value', 'key-value', 'apikey-value', 'sk-value']) assert.equal(options.body.includes(value), false)
    assert.equal(options.headers.get('Idempotency-Key'), 'preserved')
    const { envelope } = JSON.parse(options.body)
    const seed = privateDecrypt({ key: privateKey, oaepHash: 'sha256', padding: constants.RSA_PKCS1_OAEP_PADDING }, Buffer.from(envelope.encrypted_key, 'base64'))
    const aad = direction => Buffer.from([prefix, direction, challenge.id, challenge.kid, challenge.method, challenge.path, challenge.subject].join('\n'))
    const key = direction => hkdfSync('sha256', seed, Buffer.alloc(0), `${prefix}/${direction}`, 32)
    const decipher = createDecipheriv('aes-256-gcm', key('request'), Buffer.from(envelope.nonce, 'base64'))
    decipher.setAAD(aad('request'))
    const ciphertext = Buffer.from(envelope.ciphertext, 'base64')
    decipher.setAuthTag(ciphertext.subarray(-16))
    assert.deepEqual(JSON.parse(Buffer.concat([decipher.update(ciphertext.subarray(0, -16)), decipher.final()])), payload)
    const nonce = randomBytes(12)
    const cipher = createCipheriv('aes-256-gcm', key('response'), nonce)
    cipher.setAAD(aad('response:200'))
    const encrypted = Buffer.concat([cipher.update(JSON.stringify(scenario.response)), cipher.final(), cipher.getAuthTag()])
    seed.fill(0)
    const wireResponse = { version: 1, challenge_id: challenge.id, nonce: nonce.toString('base64'), ciphertext: encrypted.toString('base64') }
    for (const field of ['private_key', 'password', 'database']) {
      if (!(field in scenario.response)) continue
      assert.equal(JSON.stringify(wireResponse).includes(JSON.stringify(scenario.response[field])), false)
      assert.equal(Object.hasOwn(wireResponse, field), false)
    }
    return Response.json(wireResponse, { headers: { 'X-AG-Encrypted': '1' } })
  }
  for (let index = 0; index < 2; index++) {
    const response = await encryptedFetch(path, { method, body: JSON.stringify(payload), signal: controller.signal, headers: { 'Idempotency-Key': 'preserved' } })
    assert.deepEqual(await response.json(), scenario.response)
  }
  assert.equal(count, 2)
})

test('challenge failure and missing WebCrypto never send plaintext or retry', async () => {
  let calls = 0
  globalThis.fetch = async () => { calls++; return Response.json({ error: 'unavailable' }, { status: 503 }) }
  const response = await encryptedFetch('/api/v1/auth/local/login', { method: 'POST', body: '{"password":"secret"}' })
  assert.equal(response.status, 503)
  assert.equal(calls, 1)
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto')
  try {
    Object.defineProperty(globalThis, 'crypto', { value: undefined, configurable: true })
    await assert.rejects(() => encryptedFetch('/api/v1/auth/local/login', { method: 'POST', body: '{"password":"secret"}' }), /HTTPS/)
    assert.equal(calls, 1)
  } finally { Object.defineProperty(globalThis, 'crypto', descriptor) }
})

test('successful plaintext responses and fragment paths cannot downgrade the protocol', async () => {
  let calls = 0
  globalThis.fetch = async (url, options) => {
    calls++
    if (url === '/api/v1/auth/transport/challenges') {
      return Response.json({ ...JSON.parse(options.body), id: 'challenge', kid: 'key', subject: 'user:test', algorithm: 'RSA-OAEP-256+A256GCM', public_key: publicKey.export({ type: 'spki', format: 'pem' }) })
    }
    return Response.json(url.endsWith('/terminal/demo-defaults') ? { enabled: true, password: '123456', database: 'test' } : { private_key: 'must-not-be-accepted' })
  }
  for (const path of ['/api/v1/admin/gateways/gateway/release', '/api/v1/sessions/session/terminal/demo-defaults']) {
    await assert.rejects(() => encryptedFetch(path, { method: 'POST', body: '{}' }), /加密响应/)
  }
  assert.equal(calls, 4)
  await assert.rejects(() => encryptedFetch('/api/v1/auth/local/login#fragment', { method: 'POST', body: '{"password":"secret"}' }), /请求地址/)
  assert.equal(calls, 4)
})
