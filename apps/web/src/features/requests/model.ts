import type { AccessRequest, CreateRequestInput, RequestFormValues } from './types'

export const MAX_REQUEST_TTL_SECONDS = 5 * 60 * 60
export const DEMO_SESSION_TTL_SECONDS = 5 * 60

export function requestRequiresApproval(mode: AccessRequest['approval_mode']): boolean {
  return mode !== 'admin_test' && mode !== 'demo'
}

export function requestApprovalLabel(mode: AccessRequest['approval_mode']): string {
  if (mode === 'demo') return '演示自动审批'
  return mode === 'admin_test' ? '管理员测试（免审批）' : '审批流程'
}

export function requestDurationStartLabel(mode: AccessRequest['approval_mode']): string {
  if (mode === 'demo') return '自动审批通过后'
  return mode === 'admin_test' ? '创建后' : '审批通过后'
}

export function resolveRequestPort(ports: readonly { port: number }[], selected: unknown): number | undefined {
  if (typeof selected === 'number' && ports.some(value => value.port === selected)) return selected
  return ports.length === 1 ? ports[0]?.port : undefined
}

export function requestTargetAccountRequired(ports: readonly { port: number; target_account_required?: boolean }[], selected: unknown): boolean {
  const port = resolveRequestPort(ports, selected)
  return ports.find(value => value.port === port)?.target_account_required === true
}

export function requestDurationOptions(maxTTL: number): number[] {
  const limit = Math.min(maxTTL, MAX_REQUEST_TTL_SECONDS)
  return [...new Set([300, 600, 1800, 3600, 7200, 10800, 14400, limit].filter(value => value > 0 && value <= limit))].sort((left, right) => left - right)
}

export function toRequestInput(values: RequestFormValues, demoMode = false): CreateRequestInput {
  return {
    region_id: values.region_id, asset_id: values.asset_id, target_port: values.target_port,
    source_ip: values.client_access === false ? undefined : values.source_ip?.trim() || undefined, target_account: values.target_account?.trim() || undefined,
    reason: values.reason.trim(),
    emergency: demoMode ? false : values.emergency ?? false, ttl_seconds: demoMode ? DEMO_SESSION_TTL_SECONDS : values.ttl_seconds,
  }
}

export function createSubmissionKey() {
  let previousPayload = ''
  let previousKey = ''
  return (input: CreateRequestInput, mode = 'required'): string => {
    const payload = JSON.stringify([mode, input])
    if (payload !== previousPayload) { previousKey = crypto.randomUUID(); previousPayload = payload }
    return previousKey
  }
}
