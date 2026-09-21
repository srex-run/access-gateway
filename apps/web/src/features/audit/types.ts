export const operationProtocols = [
  { value: 'ssh', label: 'SSH' },
  { value: 'mysql', label: 'MySQL' },
  { value: 'redis', label: 'Redis' },
  { value: 'mongodb', label: 'MongoDB' },
  { value: 'postgresql', label: 'PostgreSQL' },
  { value: 'http', label: 'HTTP / HTTPS' },
]

export const auditCategories = [
  { value: 'access', label: '访问审批' },
  { value: 'resources', label: '资源管理' },
  { value: 'permissions', label: '角色权限' },
  { value: 'users', label: '用户管理' },
  { value: 'settings', label: '系统设置' },
]
export const auditActions = [
  { value: 'create', label: '新增' },
  { value: 'update', label: '修改' },
  { value: 'delete', label: '删除' },
]

export interface AuditEvent {
  category: string
  action: string
  label: string
  id: string
  event_type: string
  actor_type: string
  actor_id?: string
  actor_name?: string
  actor_username?: string
  subject_user_id?: string
  request_id?: string
  session_id?: string
  asset_id?: string
  result?: string
  source_ip?: string
  reason?: string
  metadata: Record<string, unknown>
  created_at: string
}
export interface OperationEvent {
  metadata?: { source?: string; phase?: string; operation_id?: string; profile?: string; account_verified?: boolean; evidence?: string; channel_id?: string; stream?: string; sequence?: number; encoding?: string; data?: string }
  event_id: string
  session_id?: string
  connection_id?: string
  asset_id: string
  protocol: string
  target_port: number
  actual_account: string
  operation_type: string
  normalized_operation?: string
  object_name?: string
  result: string
  correlation_status: string
  duration_ms?: number
  occurred_at: string
}

export interface OperationSession extends SessionRecord {
  command_count: number
  success_command_count: number
  failed_command_count: number
  actual_accounts: string[]
  protocols: string[]
  last_occurred_at: string
}
import type { SessionRecord } from '@/features/sessions'
