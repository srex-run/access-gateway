import assert from 'node:assert/strict'
import { test } from 'node:test'
import { connectionAddress, connectionCommand } from '../src/features/sessions/connection-model.ts'

function record(asset_type, session = {}) {
  return { asset_type, target_account: 'readonly', target_port: 33306, evidence: {}, session: { status: 'running', can_connect: true, connection_mode: 'native', gateway_host: 'gateway.example', gateway_port: 20027, ...session } }
}

test('commands use the allocated client port and require native protocol encryption', () => {
  assert.equal(connectionCommand(record('mysql')), 'mysql --protocol=TCP -h gateway.example -P 20027 --user=readonly -p --ssl-mode=REQUIRED')
  assert.match(connectionCommand(record('postgresql')), /^PGSSLMODE=require psql .*--port=20027/)
  assert.match(connectionCommand(record('redis')), /^redis-cli --tls .* -p 20027$/)
  assert.match(connectionCommand(record('mongodb')), /^mongosh .*--port=20027 --tls$/)
  assert.equal(connectionCommand(record('sshd')), 'ssh -p 20027 -l readonly -- gateway.example')
  assert.equal(connectionCommand(record('https')), 'curl https://gateway.example:20027/')
  assert.equal(connectionCommand(record('unknown')), null)
})

test('address parsing supports existing endpoint-only responses and IPv6 without guessing a port', () => {
  assert.deepEqual(connectionAddress({ gateway_endpoint: '[2001:db8::10]:20000', target_port: 3306 }), { host: '2001:db8::10', port: 20000, endpoint: '[2001:db8::10]:20000' })
  assert.deepEqual(connectionAddress({ gateway_endpoint: '127.0.0.1:20001' }), { host: '127.0.0.1', port: 20001, endpoint: '127.0.0.1:20001' })
  assert.equal(connectionAddress({ gateway_host: 'localhost', target_port: 3306 }), null)
  assert.equal(connectionAddress({ gateway_endpoint: 'localhost:65536' }), null)
})

test('closed, unavailable, non-owned and legacy sessions do not offer a native command', () => {
  for (const session of [{ status: 'closed' }, { status: 'provisioning' }, { can_connect: false }, { gateway_port: undefined }, { connection_mode: 'tunnel' }]) {
    assert.equal(connectionCommand(record('mysql', session)), null)
  }
})

test('connection examples never execute account or host content as shell syntax', () => {
  const command = connectionCommand(record('mysql', { target_account: "a'$(touch /tmp/should-not-run);b", gateway_host: 'host;echo unsafe' }))
  assert.match(command, /-h 'host;echo unsafe'/)
  assert.ok(command.includes("--user='a'\\''$(touch /tmp/should-not-run);b'"))
})

test('audited connections verify the agent identity using the downloaded public material', () => {
  const session = { id: 'session-id', connection_mode: 'audit', audit_trust: { ca_certificate: 'public-ca', ssh_host_public_key: 'public-host-key' } }
  assert.match(connectionCommand(record('mysql', session)), /--ssl-mode=VERIFY_IDENTITY --ssl-ca=.\/agent-session-id-ca.pem$/)
  assert.match(connectionCommand(record('postgresql', session)), /^PGSSLMODE=verify-full PGSSLROOTCERT=.\/agent-session-id-ca.pem /)
  assert.match(connectionCommand(record('redis', session)), /--cacert .\/agent-session-id-ca.pem --user readonly --askpass$/)
  assert.match(connectionCommand(record('mongodb', session)), /--tlsCAFile=.\/agent-session-id-ca.pem --username=readonly$/)
  assert.match(connectionCommand(record('https', session)), /^curl --cacert .\/agent-session-id-ca.pem /)
  assert.match(connectionCommand(record('ssh', session)), /^ssh -o UserKnownHostsFile=.\/agent-session-id.known_hosts -o StrictHostKeyChecking=yes /)
  assert.equal(connectionCommand(record('ssh', { ...session, audit_trust: undefined })), null)
})
