import { Link, Navigate, useLocation, useParams } from 'react-router-dom'
import { SessionDetails } from '@/features/sessions'
import { EmptyResult, PageBody, PageHeader } from '@/shared/ui/page'

export function SessionsPage() {
  const location = useLocation()
  const params = new URLSearchParams(location.search)
  params.set('tab', 'sessions')
  return <Navigate replace to={`/approvals?${params}`} />
}
export function SessionDetailPage({ byRequest = false }: { byRequest?: boolean }) {
  const { id } = useParams()
  return <><PageHeader title="会话详情" breadcrumb={<Link to="/approvals?tab=sessions">访问审批 / 会话记录</Link>} /><PageBody>{id ? <SessionDetails id={id} byRequest={byRequest} /> : <EmptyResult title="会话不存在" />}</PageBody></>
}
