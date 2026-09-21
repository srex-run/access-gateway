export type AuditProtocol = 'mysql' | 'postgresql' | 'redis' | 'mongodb' | 'http' | 'ssh'
export type AuditKey = 'private_key' | 'ssh_host_key' | 'target_ssh_key'
export interface AuditProfile {
  audit_enabled?: boolean
  name: string
  selector: string
  port: number
  protocol: AuditProtocol
  certificate: string
  gateway_ca: string
  target_ca: string
  target_server_name: string
  target_certificate_sha256: string
  ssh_host_public_key: string
  target_host_keys: string[]
  authorized_keys: string[]
}
export type AuditKeyStatus = Record<AuditKey, boolean>
export interface CertificateBundle {
  certificate: string
  private_key: string
  ca: string
  certificate_sha256: string
  target_certificate_sha256?: string
  target_host_keys?: string[]
  ssh_host_key: string
  ssh_public_key: string
  archive: string
}
