import type { AuditProfile, AuditKeyStatus } from './audit-types'

export type Provider = 'oidc' | 'oauth2' | 'github' | 'ldap'
export type Secret = Provider | 'feishu_app' | 'feishu_callback' | 'smtp_password'
interface OIDC { enabled: boolean; name: string; issuer: string; client_id: string; scopes: string[] }
interface OAuth2 { enabled: boolean; name: string; client_id: string; authorize_url: string; token_url: string; user_info_url: string; scopes: string[]; subject_claim: string; username_claim: string; name_claim: string; email_claim: string }
interface GitHub { enabled: boolean; name: string; client_id: string }
interface LDAP { enabled: boolean; name: string; url: string; bind_dn: string; base_dn: string; user_filter: string; id_attribute: string; username_attribute: string; name_attribute: string; email_attribute: string; root_ca_pem: string }
interface Feishu { app_id: string; tenant_key: string; login_enabled: boolean; binding_enabled: boolean; notifications_enabled: boolean; callbacks_enabled: boolean }
export interface SMTPConfig { enabled: boolean; host: string; port: number; username: string; from: string; tls_mode: 'starttls' | 'tls' }
export interface MFAConfig { mode: 'off' | 'optional' | 'admin' | 'all'; issuer: string }
export interface Config { client_access_enabled?: boolean; client_access_host?: string; base_url: string; timeout_seconds: number; auth: { /** Legacy response field; local login is always enabled. */ local_enabled: boolean; allow_http: boolean; oidc: OIDC; oauth2: OAuth2; github: GitHub; ldap: LDAP }; feishu: Feishu; audit_profiles?: AuditProfile[] | null; smtp?: SMTPConfig; mfa?: MFAConfig; invitation_ttl_hours?: number }
export interface SettingsView { config: Config; has_secrets: Record<Secret, boolean> & { audit_profiles?: Record<string, AuditKeyStatus> }; revision: number; updated_at: string | null }
export interface SecretFields { secrets?: Partial<Record<Secret, string>>; clear?: Partial<Record<Secret, boolean>> }
