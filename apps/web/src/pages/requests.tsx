import { ResourceFormPage } from '@/shared/ui/resource-form-page'
import { Link, Navigate, useLocation, useParams } from 'react-router-dom'
import { RequestDetails, RequestForm } from '@/features/requests'
import { EmptyResult, PageBody, PageHeader } from '@/shared/ui/page'

export function RequestsPage() {
  const location = useLocation()
  const params = new URLSearchParams(location.search)
  params.set('tab', 'requests')
  return <Navigate replace to={`/approvals?${params}`} />
}
export function RequestCreatePage() {
  return <ResourceFormPage title="新建访问申请" breadcrumb={<Link to="/approvals?tab=requests">访问审批 / 我的申请</Link>}><RequestForm /></ResourceFormPage>
}
export function RequestDetailPage() {
  const { id } = useParams()
  return <><PageHeader title="申请详情" breadcrumb={<Link to="/approvals?tab=requests">访问审批 / 我的申请</Link>} /><PageBody narrow>{id ? <RequestDetails id={id} /> : <EmptyResult title="申请不存在" />}</PageBody></>
}
