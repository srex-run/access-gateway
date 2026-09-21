import assert from 'node:assert/strict'
import { test } from 'node:test'
import { approvalSourceLabel, changeApprovalSource } from '../src/features/governance/workflow-step-model.ts'

test('switching the default owner node to admin changes its name and rule together', () => {
  const owner = { name: '资源负责人', kind: 'owners', mode: 'all', selector: '' }
  const admin = changeApprovalSource(owner, 'platform_admin')
  assert.deepEqual(admin, { name: '平台管理员', kind: 'role_selector', mode: 'all', selector: 'access-gateway.io/role=admin' })
  assert.deepEqual(changeApprovalSource(admin, 'owners'), owner)
  assert.equal(owner.name, '资源负责人')
})

test('changing the source preserves custom node names and does not infer routing from names', () => {
  const custom = changeApprovalSource({ name: '业务负责人', kind: 'owners', mode: 'any', selector: '' }, 'platform_admin')
  assert.equal(custom.name, '业务负责人')
  assert.equal(approvalSourceLabel(custom), '平台管理员（admin）')
  assert.equal(approvalSourceLabel({ ...custom, kind: 'owners', selector: '' }), '资源负责人（owner）')
  assert.equal(approvalSourceLabel({ name: '平台管理员' }), '—')
})

test('legacy platform nodes and new unnamed nodes receive a name for the selected source', () => {
  const legacy = { name: '平台运维', kind: 'role_selector', mode: 'any', selector: 'access-gateway.io/approval=platform' }
  assert.equal(changeApprovalSource(legacy, 'platform_admin').name, '平台管理员')
  assert.equal(changeApprovalSource({ ...legacy, name: '变更审核' }, 'platform_admin').name, '变更审核')
  assert.equal(changeApprovalSource({ name: '', kind: 'owners', mode: 'any', selector: '' }, 'platform_admin').name, '平台管理员')
})
