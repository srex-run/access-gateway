import assert from 'node:assert/strict'
import { test } from 'node:test'
import { applyAuditCertificate, assetAuditInput, auditRule, changeTargetTrust, normalizeAssetProtocol, protocolPorts, targetTrustMode } from '../src/features/admin/asset-form-model.ts'

test('resource protocol defaults and aliases share the connection protocol contract', () => {
  for (const [alias, canonical] of [['PostgreSQL', 'postgresql'], ['postgres', 'postgresql'], ['https', 'http'], ['sshd', 'ssh'], ['mongo', 'mongodb']]) assert.equal(normalizeAssetProtocol(alias), canonical)
  for (const [protocol, port] of Object.entries(protocolPorts)) {
    const rule = auditRule(protocol)
    assert.equal(rule.profile.port, port)
    assert.equal(rule.profile.protocol, protocol)
    assert.equal(Object.hasOwn(rule, 'gateway_hosts'), false)
  }
})

test('editing a legacy asset clears its authentication material without mutating the draft', () => {
  const rule = auditRule('mysql')
  rule.profile.name = 'asset.11111111-1111-4111-8111-111111111111.3306'
  Object.assign(rule.profile, {
    certificate: 'legacy-certificate', gateway_ca: 'legacy-gateway-ca', target_ca: 'legacy-target-ca',
    target_server_name: 'legacy-target', target_certificate_sha256: 'legacy-pin', ssh_host_public_key: 'legacy-host-key',
    target_host_keys: ['legacy-target-key'], authorized_keys: ['legacy-client-key'],
  })
  const previous = structuredClone(rule)
  const input = assetAuditInput([rule], 5)
  assert.equal(input.revision, 5)
  assert.deepEqual(input.keys[rule.profile.name], {})
  assert.equal(input.profiles[0].name, rule.profile.name)
  assert.equal(input.profiles[0].port, 3306)
  assert.equal(JSON.stringify(input).includes('legacy-'), false)
  assert.deepEqual(rule, previous)
})

test('asset audit input normalizes protocol aliases without adding authentication material', () => {
  const rule = auditRule('ssh')
  rule.profile.protocol = 'sshd'
  rule.profile.target_server_name = 'stale.example.com'
  const [profile] = assetAuditInput([rule], 0).profiles
  assert.equal(profile.protocol, 'ssh')
  assert.equal(profile.target_server_name, '')
})

test('all protocols enable agent auditing without sending a generated private key', () => {
  for (const protocol of Object.keys(protocolPorts)) {
    const rule = auditRule(protocol)
    rule.profile.audit_enabled = true
    rule.profile.target_ca = 'public-target-ca'
    rule.target_host_keys = 'ssh-ed25519 target-key\n'
    const input = assetAuditInput([rule], 2)
    assert.equal(input.profiles[0].audit_enabled, true)
    assert.equal(input.profiles[0].target_ca, 'public-target-ca')
    assert.equal(input.keys[rule.profile.name]?.ssh_host_key, undefined)
    assert.equal(input.keys[rule.profile.name]?.private_key, undefined)
    if (protocol === 'ssh') assert.deepEqual(input.profiles[0].target_host_keys, ['ssh-ed25519 target-key'])
  }
})

test('SSH audit retains omitted login keys and clears them when public key login is removed', () => {
  const rule = auditRule('ssh')
  rule.profile.audit_enabled = true
  rule.authorized_keys = 'ssh-ed25519 allowed-client'
  rule.has_target_ssh_key = true
  assert.equal(assetAuditInput([rule], 1).keys[rule.profile.name], undefined)
  rule.target_ssh_key = ' new-private-key '
  assert.deepEqual(assetAuditInput([rule], 1).keys[rule.profile.name], { target_ssh_key: 'new-private-key' })
  rule.authorized_keys = ''
  rule.target_ssh_key = ''
  assert.deepEqual(assetAuditInput([rule], 1).keys[rule.profile.name], { target_ssh_key: '' })
  rule.profile.audit_enabled = false
  const input = assetAuditInput([rule], 1)
  assert.deepEqual(input.keys[rule.profile.name], {})
  assert.deepEqual(input.profiles[0].authorized_keys, [])
})

test('one-click TLS generation submits the matching private key and preserves target trust', () => {
  for (const protocol of ['mysql', 'postgresql', 'redis', 'mongodb', 'http']) {
    const rule = auditRule(protocol)
    Object.assign(rule.profile, { audit_enabled: true, target_ca: 'existing-target-ca', target_server_name: 'db.internal' })
    const previous = structuredClone(rule)
    const generated = applyAuditCertificate(rule, 'gateway', { certificate: 'new-certificate', ca: 'new-ca', private_key: 'new-private-key' })
    const input = assetAuditInput([generated], 2)
    assert.deepEqual(input.keys[rule.profile.name], { private_key: 'new-private-key' })
    assert.equal(input.profiles[0].certificate, 'new-certificate')
    assert.equal(input.profiles[0].gateway_ca, 'new-ca')
    assert.equal(input.profiles[0].target_ca, 'existing-target-ca')
    assert.equal(input.profiles[0].target_server_name, 'db.internal')
    assert.deepEqual(rule, previous)
    generated.profile.audit_enabled = false
    assert.equal(JSON.stringify(assetAuditInput([generated], 2)).includes('new-'), false)
  }
})

test('one-click SSH generation preserves target host pins and target login credentials', () => {
  const rule = auditRule('ssh')
  rule.profile.audit_enabled = true
  rule.target_host_keys = 'ssh-ed25519 target-host'
  rule.authorized_keys = 'ssh-ed25519 client'
  rule.target_ssh_key = 'target-login-key'
  const generated = applyAuditCertificate(rule, 'ssh', { ssh_host_key: 'new-host-private-key', ssh_public_key: 'ssh-ed25519 new-host-key' })
  const input = assetAuditInput([generated], 1)
  assert.equal(input.profiles[0].ssh_host_public_key, 'ssh-ed25519 new-host-key')
  assert.deepEqual(input.profiles[0].target_host_keys, ['ssh-ed25519 target-host'])
  assert.deepEqual(input.keys[rule.profile.name], { ssh_host_key: 'new-host-private-key', target_ssh_key: 'target-login-key' })
})

test('MySQL one-click setup replaces target trust with the inspected fingerprint', () => {
  const rule = auditRule('mysql')
  Object.assign(rule.profile, { audit_enabled: true, target_ca: 'old-ca', target_server_name: 'old-name', target_certificate_sha256: 'old-pin' })
  const generated = applyAuditCertificate(rule, 'mysql', { certificate: 'new-certificate', ca: 'new-ca', private_key: 'new-private-key', target_certificate_sha256: 'inspected-pin' })
  const input = assetAuditInput([generated], 2)
  assert.equal(input.profiles[0].target_ca, '')
  assert.equal(input.profiles[0].target_server_name, '')
  assert.equal(input.profiles[0].target_certificate_sha256, 'inspected-pin')
  assert.deepEqual(input.keys[rule.profile.name], { private_key: 'new-private-key' })
  assert.equal(targetTrustMode(generated), 'pin')
})

test('target trust selects the mode of the saved CA or fingerprint', () => {
  const rule = auditRule('mysql')
  assert.equal(targetTrustMode(rule), 'system')
  rule.profile.target_ca = 'saved-target-ca'
  assert.equal(targetTrustMode(rule), 'ca')
  rule.profile.target_ca = ''
  rule.profile.target_certificate_sha256 = 'a'.repeat(64)
  assert.equal(targetTrustMode(rule), 'pin')
})

test('changing target trust clears incompatible credentials without changing gateway identity', () => {
  const rule = auditRule('mysql')
  Object.assign(rule.profile, { audit_enabled: true, certificate: 'gateway-certificate', gateway_ca: 'gateway-ca', target_ca: 'target-ca', target_server_name: 'mysql.internal' })
  const pin = changeTargetTrust(rule, 'pin')
  assert.equal(targetTrustMode(pin), 'pin')
  assert.equal(pin.profile.target_ca, '')
  assert.equal(rule.profile.target_ca, 'target-ca')
  pin.profile.target_certificate_sha256 = 'a'.repeat(64)
  const ca = changeTargetTrust(pin, 'ca')
  assert.equal(targetTrustMode(ca), 'ca')
  assert.equal(ca.profile.target_certificate_sha256, '')
  ca.profile.target_ca = 'new-target-ca'
  const system = changeTargetTrust(ca, 'system')
  const input = assetAuditInput([system], 1)
  assert.equal(input.profiles[0].target_ca, '')
  assert.equal(input.profiles[0].target_certificate_sha256, '')
  assert.equal(input.profiles[0].certificate, 'gateway-certificate')
  assert.equal(input.profiles[0].gateway_ca, 'gateway-ca')
  assert.equal(input.profiles[0].target_server_name, 'mysql.internal')
  assert.equal(JSON.stringify(input).includes('target_trust'), false)
})

test('one-click setup fills every required TLS field for all database and HTTPS protocols', () => {
  for (const protocol of ['mysql', 'postgresql', 'redis', 'mongodb', 'http']) {
    const rule = auditRule(protocol)
    Object.assign(rule.profile, { audit_enabled: true, target_ca: 'old-ca', target_server_name: 'old-name' })
    const bundle = { certificate: 'new-certificate', private_key: 'new-private-key', ca: 'new-ca', target_certificate_sha256: 'a'.repeat(64) }
    const prepared = applyAuditCertificate(rule, 'setup', bundle)
    assert.equal(targetTrustMode(prepared), 'pin')
    const input = assetAuditInput([prepared], 0)
    assert.equal(input.profiles[0].target_certificate_sha256, bundle.target_certificate_sha256)
    assert.equal(input.profiles[0].target_ca, '')
    assert.equal(input.profiles[0].target_server_name, '')
    assert.deepEqual(input.keys[rule.profile.name], { private_key: bundle.private_key })
    assert.throws(() => applyAuditCertificate(rule, 'setup', { ...bundle, target_certificate_sha256: '' }), /incomplete/)
    assert.equal(rule.profile.target_ca, 'old-ca')
  }
})

test('one-click SSH setup fills the target host key without manual input', () => {
  const rule = auditRule('ssh')
  rule.profile.audit_enabled = true
  const bundle = { ssh_host_key: 'gateway-private-key', ssh_public_key: 'ssh-ed25519 gateway', target_host_keys: ['ssh-ed25519 target'] }
  const prepared = applyAuditCertificate(rule, 'setup', bundle)
  assert.equal(prepared.target_host_keys, 'ssh-ed25519 target')
  const input = assetAuditInput([prepared], 0)
  assert.deepEqual(input.profiles[0].target_host_keys, ['ssh-ed25519 target'])
  assert.equal(input.keys[rule.profile.name].ssh_host_key, bundle.ssh_host_key)
  assert.throws(() => applyAuditCertificate(rule, 'setup', { ...bundle, target_host_keys: [] }), /incomplete/)
  assert.equal(rule.target_host_keys, '')
})
