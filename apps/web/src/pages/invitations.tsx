import { Link } from 'react-router-dom'
import { InvitationCreateForm } from '@/features/invitations'
import { ResourceFormPage } from '@/shared/ui/resource-form-page'

export default function InvitationCreatePage() {
  return <ResourceFormPage title="邀请用户" breadcrumb={<Link to="/admin/users?tab=invitations">账户管理</Link>}><InvitationCreateForm /></ResourceFormPage>
}
