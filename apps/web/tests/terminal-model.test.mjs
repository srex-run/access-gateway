import assert from 'node:assert/strict'
import test from 'node:test'
import { terminalClients, terminalProtocol, validTerminalDatabase } from '../src/features/sessions/terminal-model.ts'

test('each supported asset exposes its native terminal and connection options', () => {
  for (const protocol of ['ssh', 'mysql', 'postgresql', 'redis', 'mongodb', 'http']) {
    assert.equal(terminalProtocol(protocol), protocol)
    assert.ok(terminalClients[protocol].client)
  }
  for (const value of [undefined, 'tcp', '__proto__', 'constructor']) assert.equal(terminalProtocol(value), undefined)
  assert.equal(terminalClients.postgresql.database, 'postgres')
  assert.equal(terminalClients.redis.database, '0')
  assert.equal(terminalClients.mongodb.database, 'test')
  assert.equal(terminalClients.http.database, undefined)
})

test('database options cannot replace connection parameters', () => {
  for (const value of ['name host=remote', 'mongodb://remote/db', '--host=remote', 'db\nother', 'x'.repeat(129)]) {
    assert.equal(validTerminalDatabase('postgresql', value, ''), false)
    assert.equal(validTerminalDatabase('mongodb', '', value), false)
  }
  for (const value of ['-1', '1.1', '2147483648']) assert.equal(validTerminalDatabase('redis', value, ''), false)
  assert.equal(validTerminalDatabase('redis', '0', ''), true)
  assert.equal(validTerminalDatabase('mongodb', 'application', 'admin'), true)
})
