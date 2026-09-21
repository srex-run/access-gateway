import { generateKeyPairSync, privateDecrypt, hkdfSync, createDecipheriv, createCipheriv, randomBytes, randomUUID, constants } from 'node:crypto'
import { expect, type Page, type Route } from '@playwright/test'

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
const prefix = 'access-gateway/browser-transport/v1'
type Challenge = { id: string; kid: string; method: string; path: string; subject: string }

// Real WebCrypto runs in the page; only the backend is simulated. Assertions
// ensure existing browser tests can no longer accidentally accept plaintext.
export async function mockEncryptedTransport(page: Page) {
  const challenges = new Map<string, Challenge>()
  await page.route('**/api/v1/auth/transport/challenges', async route => {
    const { method, path } = route.request().postDataJSON()
    const challenge = { id: randomUUID(), kid: 'browser-test-key', method, path, subject: 'user:test' }
    challenges.set(challenge.id, challenge)
    await route.fulfill({ json: { ...challenge, algorithm: 'RSA-OAEP-256+A256GCM', public_key: publicKey.export({ type: 'spki', format: 'pem' }), expires_at: new Date(Date.now() + 120_000).toISOString() } })
  })
  return {
    open(route: Route | { message: string; path: string }) {
      const request = 'message' in route
        ? { body: JSON.parse(route.message), method: 'GET', path: route.path }
        : { body: route.request().postDataJSON(), method: route.request().method(), path: new URL(route.request().url()).pathname }
      const { challenge_id: id, envelope } = request.body
      const challenge = challenges.get(id)
      expect(challenge).toBeDefined()
      if (!challenge) throw new Error('unknown test encryption challenge')
      challenges.delete(id)
      expect(challenge.method).toBe(request.method)
      expect(challenge.path).toBe(request.path)
      expect(envelope.version).toBe(1)
      expect(envelope.kid).toBe(challenge.kid)
      const aad = (direction: string) => Buffer.from([prefix, direction, challenge.id, challenge.kid, challenge.method, challenge.path, challenge.subject].join('\n'))
      const seed = privateDecrypt({ key: privateKey, oaepHash: 'sha256', padding: constants.RSA_PKCS1_OAEP_PADDING }, Buffer.from(envelope.encrypted_key, 'base64'))
      const requestKey = Buffer.from(hkdfSync('sha256', seed, Buffer.alloc(0), `${prefix}/request`, 32))
      const responseKey = Buffer.from(hkdfSync('sha256', seed, Buffer.alloc(0), `${prefix}/response`, 32))
      seed.fill(0)
      const decipher = createDecipheriv('aes-256-gcm', requestKey, Buffer.from(envelope.nonce, 'base64'))
      decipher.setAAD(aad('request'))
      const ciphertext = Buffer.from(envelope.ciphertext, 'base64')
      decipher.setAuthTag(ciphertext.subarray(-16))
      const body = JSON.parse(Buffer.concat([decipher.update(ciphertext.subarray(0, -16)), decipher.final()]).toString())
      return {
        body,
        async fulfill(json: unknown, status = 200) {
          if ('message' in route) throw new Error('WebSocket frames do not have an HTTP response')
          const nonce = randomBytes(12)
          const cipher = createCipheriv('aes-256-gcm', responseKey, nonce)
          cipher.setAAD(aad(`response:${status}`))
          const encrypted = Buffer.concat([cipher.update(JSON.stringify(json)), cipher.final(), cipher.getAuthTag()])
          await route.fulfill({ status, headers: { 'X-AG-Encrypted': '1' }, json: { version: 1, challenge_id: challenge.id, nonce: nonce.toString('base64'), ciphertext: encrypted.toString('base64') } })
        },
      }
    },
  }
}
