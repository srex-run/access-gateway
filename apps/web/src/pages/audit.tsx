import { AuditWorkspace } from '@/features/audit'
import { PageBody, PageHeader } from '@/shared/ui/page'
export default function AuditPage() {
  return <><PageHeader title="审计日志" breadcrumb="安全管理" /><PageBody><AuditWorkspace /></PageBody></>
}
