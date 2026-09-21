import type { Step } from './types'

export type ApprovalSource = Step['kind'] | 'platform_admin'
type ApprovalRule = Partial<Pick<Step, 'kind' | 'selector'>>
const platformAdminSelector = 'access-gateway.io/role=admin'
const defaultNames: Record<ApprovalSource, string> = {
  owners: '资源负责人', platform_admin: '平台管理员', user_selector: '用户审批', role_selector: '角色审批',
}

export const isPlatformAdminStep = (step: ApprovalRule) => step.kind === 'role_selector' && step.selector?.trim() === platformAdminSelector

export function approvalSourceLabel(step?: ApprovalRule): string {
  if (step && isPlatformAdminStep(step)) return '平台管理员（admin）'
  if (step?.kind === 'owners') return '资源负责人（owner）'
  if (step?.kind === 'user_selector') return '匹配用户标签'
  if (step?.kind === 'role_selector') return '匹配角色标签'
  return '—'
}

export function changeApprovalSource(step: Step, source: ApprovalSource): Step {
  const previous = isPlatformAdminStep(step) ? 'platform_admin' : step.kind
  const name = step.name.trim()
  const legacyDefault = step.kind === 'role_selector' && step.selector.trim() === 'access-gateway.io/approval=platform' && name === '平台运维'
  return {
    ...step,
    name: !name || name === defaultNames[previous] || legacyDefault ? defaultNames[source] : step.name,
    kind: source === 'platform_admin' ? 'role_selector' : source,
    selector: source === 'platform_admin' ? platformAdminSelector : '',
  }
}
