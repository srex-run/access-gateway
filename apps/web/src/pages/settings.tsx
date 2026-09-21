import { SystemSettings } from '@/features/admin'
import { PageBody, PageHeader } from '@/shared/ui/page'

export default function SettingsPage() {
  return <><PageHeader title="系统设置" breadcrumb="平台管理" /><PageBody><SystemSettings /></PageBody></>
}
