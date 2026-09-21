import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { test } from 'node:test'

const helper = fileURLToPath(new URL('./public-url.sh', import.meta.url))
function parse(PUBLIC_URL) {
  return spawnSync('sh', ['-ec', '. "$1"; load_public_url; printf "%s\\n%s\\n" "$public_url" "$public_host"', 'public-url-test', helper], { env: { ...process.env, PUBLIC_URL }, encoding: 'utf8' })
}

test('production origin supplies the ingress DNS name while preserving an external TLS port', () => {
  for (const [value, expected] of [
    ['https://access.example.test', 'https://access.example.test\naccess.example.test\n'],
    ['https://ACCESS.example.test:8443/', 'https://access.example.test:8443\naccess.example.test\n'],
  ]) {
    const result = parse(value)
    assert.equal(result.status, 0, result.stderr)
    assert.equal(result.stdout, expected)
  }
})

test('production rendering rejects malformed origins before substitution or network checks', () => {
  for (const value of ['', 'http://access.example.test', 'https://user:pass@example.test', 'https://access.example.test/path', 'https://access.example.test?query', 'https://access.example.test#fragment', 'https://example..test', 'https://-bad.test', 'https://example.invalid', 'https://127.0.0.1', 'https://[::1]', 'https://example.test:0', 'https://example.test:65536', 'https://example.test\nINJECT=value', 'https://example.test|x']) {
    const result = parse(value)
    assert.notEqual(result.status, 0, value)
    assert.match(result.stderr, /PUBLIC_URL/)
    assert.equal(result.stdout, '')
  }
})
