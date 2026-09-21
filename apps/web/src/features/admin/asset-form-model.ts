import type { AuditKey, AuditProfile, AuditProtocol, AuditKeyStatus, CertificateBundle } from './audit-types'
import type { AssetInput } from './types'

export interface AssetAuditView { revision: number; profiles: AuditProfile[]; has_secrets: Record<string, AuditKeyStatus> }
export interface AssetAuditInput { revision: number; profiles: AuditProfile[]; keys: Record<string, Partial<Record<AuditKey, string>>> }
export type TargetTrustMode = 'system' | 'ca' | 'pin'
export interface AssetAuditRule {
  profile: AuditProfile
  target_trust?: TargetTrustMode
  target_host_keys: string
  authorized_keys: string
  private_key?: string
  ssh_host_key?: string
  target_ssh_key?: string
  has_private_key?: boolean
  has_ssh_host_key?: boolean
  has_target_ssh_key?: boolean
}
export type AssetFormValues = Omit<AssetInput, 'audit'> & { rules: AssetAuditRule[] }

export const protocolPorts: Record<AuditProtocol, number> = { mysql: 3306, postgresql: 5432, redis: 6379, mongodb: 27017, http: 443, ssh: 22 }
export function normalizeAssetProtocol(value: string): string {
  const normalized = value.toLowerCase().trim()
  return ({ postgres: 'postgresql', mongo: 'mongodb', https: 'http', sshd: 'ssh' } as Record<string, string>)[normalized] ?? normalized
}

export function isAuditProtocol(value: string): value is AuditProtocol { return Object.hasOwn(protocolPorts, value) }

export function auditRule(protocol: AuditProtocol, profile?: AuditProfile, status?: AuditKeyStatus): AssetAuditRule {
  const p = profile ?? { name: `port-${crypto.randomUUID()}`, selector: '', protocol, port: protocolPorts[protocol], certificate: '', gateway_ca: '', target_ca: '', target_server_name: '', target_certificate_sha256: '', ssh_host_public_key: '', target_host_keys: [], authorized_keys: [] }
  return { profile: p, target_host_keys: (p.target_host_keys ?? []).join('\n'), authorized_keys: (p.authorized_keys ?? []).join('\n'),
    has_private_key: status?.private_key, has_ssh_host_key: status?.ssh_host_key, has_target_ssh_key: status?.target_ssh_key }
}

export type AssetCertificatePurpose = 'gateway' | 'ssh' | 'mysql' | 'setup'

export function targetTrustMode(rule: AssetAuditRule): TargetTrustMode {
  return rule.target_trust ?? (rule.profile.target_certificate_sha256 ? 'pin' : rule.profile.target_ca ? 'ca' : 'system')
}

export function changeTargetTrust(rule: AssetAuditRule, mode: TargetTrustMode): AssetAuditRule {
  return { ...rule, target_trust: mode, profile: { ...rule.profile,
    target_ca: mode === 'ca' ? rule.profile.target_ca : '',
    target_certificate_sha256: mode === 'pin' ? rule.profile.target_certificate_sha256 : '',
  } }
}

export function applyAuditCertificate(rule: AssetAuditRule, purpose: AssetCertificatePurpose, bundle: CertificateBundle): AssetAuditRule {
  if (purpose === 'setup') {
    if (rule.profile.protocol === 'ssh') {
      if (!bundle.ssh_host_key || !bundle.ssh_public_key || !bundle.target_host_keys?.length) throw new Error('incomplete SSH setup')
      return { ...rule, ssh_host_key: bundle.ssh_host_key, target_host_keys: bundle.target_host_keys.join('\n'),
        profile: { ...rule.profile, ssh_host_public_key: bundle.ssh_public_key, target_host_keys: bundle.target_host_keys } }
    }
    if (!bundle.private_key || !bundle.certificate || !bundle.ca || !/^[a-fA-F0-9]{64}$/.test(bundle.target_certificate_sha256 ?? '')) throw new Error('incomplete TLS setup')
    return { ...rule, target_trust: 'pin', private_key: bundle.private_key,
      profile: { ...rule.profile, certificate: bundle.certificate, gateway_ca: bundle.ca, target_ca: '', target_server_name: '', target_certificate_sha256: bundle.target_certificate_sha256! } }
  }
  if (purpose === 'ssh') return { ...rule, profile: { ...rule.profile, ssh_host_public_key: bundle.ssh_public_key }, ssh_host_key: bundle.ssh_host_key }
  return { ...rule, ...(purpose === 'mysql' ? { target_trust: 'pin' as const } : {}), private_key: bundle.private_key, profile: { ...rule.profile, certificate: bundle.certificate, gateway_ca: bundle.ca,
    ...(purpose === 'mysql' ? { target_ca: '', target_server_name: '', target_certificate_sha256: bundle.target_certificate_sha256 ?? '' } : {}) } }
}

export function assetAuditInput(rules: AssetAuditRule[], revision: number): AssetAuditInput {
  const keys: AssetAuditInput['keys'] = {}
  const profiles = rules.map(rule => {
    const profile = { ...rule.profile, selector: '', protocol: normalizeAssetProtocol(rule.profile.protocol) as AuditProtocol }
    if (profile.audit_enabled) {
      if (profile.protocol === 'ssh') {
        profile.target_host_keys = rule.target_host_keys.split('\n').map(value => value.trim()).filter(Boolean)
        profile.authorized_keys = rule.authorized_keys.split('\n').map(value => value.trim()).filter(Boolean)
        const changes: Partial<Record<AuditKey, string>> = {}
        if (rule.ssh_host_key?.trim()) changes.ssh_host_key = rule.ssh_host_key.trim()
        if (rule.target_ssh_key?.trim()) changes.target_ssh_key = rule.target_ssh_key.trim()
        else if (!profile.authorized_keys.length) changes.target_ssh_key = ''
        if (Object.keys(changes).length) keys[profile.name] = changes
      } else if (rule.private_key?.trim()) keys[profile.name] = { private_key: rule.private_key.trim() }
      return profile
    }
    // An explicit empty entry tells the service to discard any legacy
    // credential material while keeping the request limited to port/protocol
    // data. No credential value is sent by the native tunnel form.
    keys[profile.name] = {}
    profile.certificate = profile.gateway_ca = profile.target_ca = profile.target_server_name = profile.target_certificate_sha256 = ''
    profile.ssh_host_public_key = ''
    profile.target_host_keys = profile.authorized_keys = []
    return profile
  })
  return { revision, profiles, keys }
}
