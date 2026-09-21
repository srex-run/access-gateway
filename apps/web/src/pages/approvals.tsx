import { ApprovalList } from '@/features/approvals'
import { useIdentity } from '@/features/auth'
import { RequestList } from '@/features/requests'
import { SessionList } from '@/features/sessions'
import { PageBody, PageHeader } from '@/shared/ui/page'
import { RouteTabs } from '@/shared/ui/route-tabs'
export default function ApprovalsPage() {
  const identity = useIdentity()
  const permissions = identity.data?.permissions ?? []
  const items = [
    ...(permissions.includes('approval:manage') ? [{ key: 'pending', title: '待审批', content: <ApprovalList /> }] : []),
    ...(permissions.some(value => ['session:manage', 'approval:manage', 'audit:read'].includes(value)) ? [{ key: 'sessions', title: '会话记录', content: <SessionList /> }] : []),
    ...(permissions.includes('request:manage') ? [{ key: 'requests', title: '我的申请', content: <RequestList /> }] : []),
  ]
  return <><PageHeader title="访问审批" breadcrumb="访问管理" /><PageBody><RouteTabs items={items} /></PageBody></>
}
