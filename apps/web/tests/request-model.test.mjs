import assert from 'node:assert/strict'
import { test } from 'node:test'
import { createSubmissionKey, requestApprovalLabel, requestDurationOptions, requestDurationStartLabel, requestRequiresApproval, requestTargetAccountRequired, resolveRequestPort, toRequestInput } from '../src/features/requests/model.ts'

const values = { region_id: 'region', asset_id: 'asset', target_port: 5432, source_ip: ' 192.0.2.1 ', target_account: ' reader ', reason: ' investigation ', emergency: false, ttl_seconds: 3600 }

test('web requests omit stale client source IPs and client access remains explicit', () => {
  assert.equal(toRequestInput({ ...values, client_access: false }).source_ip, undefined)
  assert.equal(toRequestInput({ ...values, client_access: true }).source_ip, '192.0.2.1')
  assert.equal(toRequestInput({ ...values, source_ip: undefined }).source_ip, undefined)
  const keyFor = createSubmissionKey()
  assert.notEqual(keyFor(toRequestInput({ ...values, client_access: false })), keyFor(toRequestInput({ ...values, client_access: true })))
})

test('selects the only available port and clears unavailable selections without guessing among multiple ports', () => {
  assert.equal(resolveRequestPort([{ port: 3306 }], undefined), 3306)
  assert.equal(resolveRequestPort([{ port: 5432 }], 3306), 5432)
  assert.equal(resolveRequestPort([{ port: 3306 }, { port: 3307 }], undefined), undefined)
  assert.equal(resolveRequestPort([{ port: 3306 }, { port: 3307 }], 3307), 3307)
  assert.equal(resolveRequestPort([{ port: 3306 }, { port: 3307 }], 5432), undefined)
  assert.equal(resolveRequestPort([], 3306), undefined)
})

test('account requirement follows the selected port, including automatic single-port selection', () => {
  const audited = { port: 60022, target_account_required: true }
  const native = { port: 22, target_account_required: false }
  assert.equal(requestTargetAccountRequired([audited], undefined), true)
  assert.equal(requestTargetAccountRequired([native], 60022), false)
  assert.equal(requestTargetAccountRequired([native, audited], 60022), true)
  assert.equal(requestTargetAccountRequired([native, audited], 22), false)
  assert.equal(requestTargetAccountRequired([native, audited], undefined), false)
  assert.equal(requestTargetAccountRequired([], 60022), false)
  assert.equal(requestTargetAccountRequired([{ port: 443, target_account_required: false }], 443), false)
})

test('normalizes request fields and preserves request semantics without tickets', () => {
  const input = toRequestInput(values)
  assert.equal(input.source_ip, '192.0.2.1')
  assert.equal(input.target_account, 'reader')
  assert.equal(input.reason, 'investigation')
  assert.equal(Object.hasOwn(input, 'ticket_no'), false)
  assert.equal(input.ttl_seconds, 3600)
  assert.equal(Object.hasOwn(toRequestInput({ ...values, requested_start_at: '2026-09-09T15:00:00+08:00' }), 'requested_start_at'), false)
  const urgent = toRequestInput({ ...values, emergency: true, reason: ' 处理生产故障 ' })
  assert.equal(urgent.emergency, true)
  assert.equal(urgent.reason, '处理生产故障')
  assert.equal(Object.hasOwn(urgent, 'ticket_no'), false)
})

test('duration presets include common lengths and respect the five-hour and asset limits', () => {
  assert.deepEqual(requestDurationOptions(86400), [300, 600, 1800, 3600, 7200, 10800, 14400, 18000])
  assert.deepEqual(requestDurationOptions(3600), [300, 600, 1800, 3600])
  assert.deepEqual(requestDurationOptions(600), [300, 600])
  assert.deepEqual(requestDurationOptions(120), [120])
  assert.deepEqual(requestDurationOptions(0), [])
})

test('demo submissions always last five minutes and clear stale emergency priority', () => {
  for (const ttl_seconds of [1, 120, 300, 600, 3600, 86400]) {
    const input = toRequestInput({ ...values, ttl_seconds, emergency: true, client_access: false }, true)
    assert.equal(input.ttl_seconds, 300)
    assert.equal(input.emergency, false)
    assert.equal(input.source_ip, undefined)
    assert.equal(input.target_account, 'reader')
  }
  const ordinary = toRequestInput({ ...values, ttl_seconds: 600, emergency: true }, false)
  assert.equal(ordinary.ttl_seconds, 600)
  assert.equal(ordinary.emergency, true)
})

test('demo requests open sessions and show automatic approval without a manual workflow', () => {
  assert.equal(requestRequiresApproval('demo'), false)
  assert.equal(requestRequiresApproval('admin_test'), false)
  assert.equal(requestRequiresApproval('required'), true)
  assert.equal(requestRequiresApproval(undefined), true)
  assert.equal(requestApprovalLabel('demo'), '演示自动审批')
  assert.equal(requestApprovalLabel('required'), '审批流程')
  assert.equal(requestDurationStartLabel('demo'), '自动审批通过后')
  assert.equal(requestDurationStartLabel('admin_test'), '创建后')
  assert.equal(requestDurationStartLabel(undefined), '审批通过后')
})

test('retries identical payloads using the same idempotency key; changed payloads get a new key', () => {
  const keyFor = createSubmissionKey()
  const input = toRequestInput(values)
  const first = keyFor(input)
  assert.match(first, /^[0-9a-f-]{36}$/)
  assert.equal(keyFor({ ...input }), first)
  assert.notEqual(keyFor({ ...input, target_port: 3306 }), first)
  const ordinary = keyFor(input)
  const testAccess = keyFor(input, 'admin_test')
  assert.notEqual(testAccess, ordinary)
  assert.equal(keyFor({ ...input }, 'admin_test'), testAccess)
})
