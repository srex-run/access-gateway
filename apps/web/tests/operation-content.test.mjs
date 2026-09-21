import assert from 'node:assert/strict'
import { test } from 'node:test'
import { operationLabel, operationSummary, operationText, operationVisible } from '../src/features/audit/operation-content.ts'

test('terminal output is rendered as text and is not labelled as an executed command', () => {
  const terminal = { operation_type: 'terminal_output', metadata: { encoding: 'base64', data: Buffer.from('主机$ whoami\r\n\x1b[31mreader').toString('base64') } }
  assert.equal(operationLabel(terminal), '终端输出')
  assert.equal(operationText(terminal), '主机$ whoami\r\n␛[31mreader')
  assert.equal(operationLabel({ operation_type: 'exec' }), '命令请求')
  assert.equal(operationText({ ...terminal, metadata: { encoding: 'base64', data: '???' }, normalized_operation: 'safe preview' }), 'safe preview')
})

test('client initialization is hidden from command lists and retains its SQL evidence', () => {
  for (const [operation_type, normalized_operation] of [
    ['client_version_probe', 'select @@version_comment limit ?'],
    ['client_syntax_probe', 'select'],
  ]) {
    const event = { operation_type, normalized_operation }
    assert.equal(operationVisible(event), false)
    assert.equal(operationVisible({ ...event, operation_type: 'query' }), true)
    assert.match(operationSummary(event), /MySQL 客户端初始化/)
    assert.equal(operationText(event), normalized_operation)
    assert.equal(operationSummary({ ...event, operation_type: 'query' }), normalized_operation)
  }
})
