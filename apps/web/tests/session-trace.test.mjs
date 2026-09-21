import test from 'node:test'
import assert from 'node:assert/strict'
import { traceContent, traceReason, traceResult, traceTitle, traceVisible } from '../src/features/sessions/trace-model.ts'

test('a successful backend TCP connection is not an authenticated login', () => {
  const event = { stage: 'connection', event_type: 'backend_connected', result: 'success' }
  assert.equal(traceTitle(event), '目标 TCP 已连接')
  assert.deepEqual(traceResult(event), { label: 'TCP 已连接', tone: 'neutral' })
})

test('authentication and TLS failures remain visible with their original codes', () => {
  assert.deepEqual(traceResult({ stage: 'connection', event_type: 'backend_failed', result: 'failed' }), { label: '失败', tone: 'danger' })
  assert.deepEqual(traceResult({ stage: 'connection', event_type: 'disconnected', result: 'failure' }), { label: '失败', tone: 'danger' })
  assert.match(traceReason('application_identity_rejected'), /目标账号认证失败.*application_identity_rejected/)
  assert.match(traceReason('target_tls_verification_failed'), /证书校验失败.*target_tls_verification_failed/)
  assert.equal(traceReason('new_gateway_error'), 'new_gateway_error')
})

test('operation results retain failures, pending work and unknown results', () => {
  assert.equal(traceResult({ stage: 'operation', event_type: 'query', result: 'failed' }).tone, 'danger')
  assert.equal(traceResult({ stage: 'operation', event_type: 'query', result: 'success' }).tone, 'success')
  assert.equal(traceResult({ stage: 'operation', event_type: 'query', result: 'in_progress' }).tone, 'warning')
  assert.equal(traceResult({ stage: 'operation', event_type: 'query', result: 'unknown' }).tone, 'neutral')
})

test('SSH terminal output has observation semantics rather than execution success', () => {
  const event = { stage: 'operation', event_type: 'terminal_output', result: 'unknown' }
  assert.equal(traceTitle(event), '终端输出')
  assert.deepEqual(traceResult(event), { label: '已记录', tone: 'neutral' })
  assert.equal(traceTitle({ stage: 'operation', event_type: 'exec' }), '命令请求')
})

test('closed terminals show completion while client errors remain failures', () => {
  for (const event_type of ['client', 'shell', 'disconnected']) {
    assert.deepEqual(traceResult({ stage: 'operation', event_type, result: 'success' }), { label: '已结束', tone: 'neutral' })
    assert.equal(traceResult({ stage: 'operation', event_type, result: 'failure' }).tone, 'danger')
  }
  assert.match(traceReason('session_closed'), /会话已结束/)
  assert.match(traceReason('terminal_closed'), /用户关闭终端/)
})

test('startup probes are hidden from traces while identical user SQL remains visible', () => {
  for (const [event_type, operation, label] of [
    ['client_version_probe', 'select @@version_comment limit ?', '版本检查'],
    ['client_syntax_probe', 'select', '语法探测'],
  ]) {
    const event = { stage: 'operation', event_type, operation, protocol: 'mysql', result: 'failure' }
    assert.equal(traceVisible({ ...event, terminal_channel_id: 'terminal-recording' }), false)
    assert.equal(traceVisible({ ...event, result: 'success' }), false)
    assert.equal(traceVisible({ ...event, event_type: 'query' }), true)
    assert.match(traceContent(event), new RegExp(`客户端初始化.*${label}`))
    assert.equal(traceContent({ ...event, event_type: 'query' }), operation)
    assert.equal(traceResult({ ...event, event_type: 'query' }).tone, 'danger')
  }
})
