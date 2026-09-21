import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { developmentConfig, loadDevelopmentEnvironment } from './dev-config.mjs'

test('dotenv values are parsed as data and explicit environment overrides win', () => {
  const directory = mkdtempSync(join(tmpdir(), 'access-gateway-dev-env-'))
  try {
    writeFileSync(join(directory, '.env'), 'DATABASE_URL="postgres://user:p#ss@localhost:15432/access_gateway_dev"\nLITERAL="$(touch /tmp/do-not-execute)"\nDEV_WEB_PORT=5173\n')
    const env = loadDevelopmentEnvironment(directory, { DEV_WEB_PORT: '5174' })
    assert.equal(env.DATABASE_URL, 'postgres://user:p#ss@localhost:15432/access_gateway_dev')
    assert.equal(env.LITERAL, '$(touch /tmp/do-not-execute)')
    assert.equal(env.DEV_WEB_PORT, '5174')
  } finally { rmSync(directory, { recursive: true, force: true }) }
})

test('custom API ports propagate to the same-origin Vite proxy without changing the database', () => {
  const database = 'postgres://test:example@localhost:15432/access_gateway_dev?sslmode=disable'
  const config = developmentConfig({ DATABASE_URL: database, HTTP_ADDR: ':18080', DEV_WEB_PORT: '15173' })
  assert.equal(config.env.DATABASE_URL, database)
  assert.equal(config.env.HTTP_ADDR, '127.0.0.1:18080')
  assert.equal(config.env.ACCESS_GATEWAY_UPSTREAM, 'http://127.0.0.1:18080')
  assert.equal(config.env.GATEWAY_RUNTIME, 'local')
  assert.equal(config.webURL, 'http://127.0.0.1:15173')
  assert.equal(config.env.PUBLIC_URL, config.webURL)
})

test('PUBLIC_URL controls the displayed address and local frontend port', () => {
  const env = { DATABASE_URL: 'postgres://local/access_gateway_dev' }
  for (const [publicURL, port, host] of [
    ['http://localhost:19527', 19527, '127.0.0.1'],
    ['http://127.0.0.1:9527/', 9527, '127.0.0.1'],
    ['http://[::1]:9527', 9527, '::1'],
    ['http://localhost', 80, '127.0.0.1'],
  ]) {
    const config = developmentConfig({ ...env, PUBLIC_URL: publicURL })
    assert.equal(config.webURL, publicURL.replace(/\/$/, ''))
    assert.equal(config.env.PUBLIC_URL, config.webURL)
    assert.equal(config.webPort, port)
    assert.equal(config.webHost, host)
    assert.equal(config.env.ACCESS_GATEWAY_UPSTREAM, 'http://127.0.0.1:8080')
  }
  const proxied = developmentConfig({ ...env, PUBLIC_URL: 'https://access.example.test', DEV_WEB_PORT: '9527' })
  assert.equal(proxied.webURL, 'https://access.example.test')
  assert.equal(proxied.webPort, 9527)
  assert.throws(() => developmentConfig({ ...env, PUBLIC_URL: 'http://localhost:9527', DEV_WEB_PORT: '5173' }), /must match/)
  for (const PUBLIC_URL of ['https://user:password@example.test', 'https://example.test/path', 'https://example.test?x', 'https://example.test#', 'http://0.0.0.0:9527']) {
    assert.throws(() => developmentConfig({ ...env, PUBLIC_URL }))
  }
})

test('invalid or colliding ports and ambiguous database configuration fail before spawning', () => {
  const base = { DATABASE_URL: 'postgres://local/access_gateway_dev' }
  for (const invalid of [{ HTTP_ADDR: ':x' }, { HTTP_ADDR: ':65536' }, { HTTP_ADDR: '0.0.0.0:8080' }, { DEV_WEB_PORT: '8080' }, { DEV_WEB_PORT: '1.5' }, { DATABASE_URL_FILE: '/secret' }]) {
    assert.throws(() => developmentConfig({ ...base, ...invalid }))
  }
  assert.throws(() => developmentConfig({}))
})
