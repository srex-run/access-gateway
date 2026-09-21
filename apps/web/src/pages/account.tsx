import { AccountSettings } from '@/features/auth'
import { PageBody, PageHeader } from '@/shared/ui/page'

export default function AccountPage() {
  return <><PageHeader title="账号设置" /><PageBody narrow><AccountSettings /></PageBody></>
}
