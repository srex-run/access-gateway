export type SessionStatus = 'provisioning' | 'running' | 'revoking' | 'expired' | 'closed' | 'failed' | 'revoke_failed' | 'manual_intervention'
export interface Session {
  id: string
  request_id: string
  gateway_id: string
  status: SessionStatus
  can_connect: boolean
  can_web_connect?: boolean
  connection_mode: 'native' | 'audit' | 'direct' | 'tunnel'
  audit_policy?: { profile: string; protocol: string; revision: string }
  audit_trust?: { ca_certificate?: string; ssh_host_public_key?: string }
  source_ip?: string
  target_account?: string
  started_at?: string
  expires_at?: string
  closed_at?: string
  failure_reason?: string
  gateway_endpoint?: string
  gateway_host?: string
  gateway_port?: number
  target_port?: number
  created_at: string
  updated_at: string
}
export interface SessionEvent { id: string; session_id: string; event_type: string; actor_type: string; actor_id?: string; metadata: Record<string, unknown>; created_at: string }

export interface SessionRecord {
  id: string
  request_id: string
  applicant_id: string
  applicant_name: string
  asset_id: string
  asset_name: string
  asset_type?: string
  target_account: string
  target_port: number
  status: SessionStatus
  created_at: string
  started_at?: string
  expires_at?: string
}
export interface SessionRecordDetail extends SessionRecord {
  session: Session
  request: AccessRequest
  workflow: WorkflowView
  evidence: { verified_accounts: string[]; operation_count: number; connection_count: number; failed_connections: number; context?: { accounts: { name: string; verified: boolean }[]; protocols: string[]; backend_sources: { ip: string; port?: number }[]; client_sources: string[] } }
  can_close: boolean
}
export type TraceStage = 'request' | 'approval' | 'session' | 'connection' | 'operation'
export interface SessionTraceEvent {
  id: string
  stage: TraceStage
  event_type: string
  occurred_at: string
  actor_id?: string
  actor_name?: string
  result?: string
  reason?: string
  actual_account?: string
  account_verified: boolean
  connection_id?: string
  source_ip?: string
  backend_source_ip?: string
  backend_source_port?: number
  duration_ms?: number
  operation?: string
  object_name?: string
  protocol?: string
  terminal_channel_id?: string
  terminal_cols?: number
}

export interface TerminalRecordingFrame {
  id: string
  occurred_at: string
  stream: string
  data: string
}
import type { AccessRequest } from '@/features/requests'
import type { WorkflowView } from '@/features/governance'
