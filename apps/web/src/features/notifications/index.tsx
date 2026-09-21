import { Badge, Button, Drawer, Empty, Space, Spin } from '@arco-design/web-react'
import { IconNotification, IconRefresh } from '@arco-design/web-react/icon'
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { request } from '@/shared/api/client'
import { formatTime } from '@/shared/lib/format'
import { IconButton } from '@/shared/ui/icon-button'
import { ErrorNotice } from '@/shared/ui/page'
import './notifications.css'

interface Notification {
  id: string
  event_type: 'approval_requested' | 'request_result' | 'session_ready' | 'session_closed'
  title: string
  content: string
  request_id: string
  session_id?: string
  read_at?: string
  created_at: string
}
interface NotificationPage { items: Notification[]; unread_count: number; has_more: boolean }

export function NotificationBell({ userID }: { userID: string }) {
  const [open, setOpen] = useState(false)
  const [page, setPage] = useState(0)
  const client = useQueryClient()
  const queryKey = ['notifications', userID] as const
  const query = useQuery({
    queryKey: [...queryKey, page],
    queryFn: ({ signal }) => request<NotificationPage>('/notifications', { signal, query: { limit: 20, offset: page * 20 } }),
    refetchOnWindowFocus: true,
    placeholderData: keepPreviousData,
  })
  const read = useMutation({
    mutationFn: (id?: string) => request<void>(id ? `/notifications/${encodeURIComponent(id)}/read` : '/notifications/read', { method: 'POST' }),
    onSuccess: () => client.invalidateQueries({ queryKey }),
  })
  const unread = query.data?.unread_count ?? 0
  const items = query.data?.items ?? []
  const close = () => setOpen(false)
  return <>
    <Badge count={unread} maxCount={99} offset={[-4, 4]}>
      <IconButton label={unread ? `站内通知，${unread} 条未读` : '站内通知'} icon={<IconNotification />} onClick={() => { setPage(0); setOpen(true); void query.refetch() }} />
    </Badge>
    <Drawer title="站内通知" visible={open} width="min(440px, 100vw)" onCancel={close} footer={null}>
      <div className="notification-toolbar">
        <span>{unread} 条未读</span>
        <Space><Button type="text" disabled={!unread || read.isPending} onClick={() => read.mutate(undefined)}>全部标为已读</Button><IconButton label="刷新通知" icon={<IconRefresh />} loading={query.isFetching} onClick={() => void query.refetch()} /></Space>
      </div>
      <ErrorNotice error={query.error} retry={() => void query.refetch()} />
      <ErrorNotice error={read.error} />
      {query.isPending ? <Spin /> : !query.error && !items.length ? <Empty description="暂无站内通知" /> : <ul className="notification-list">
        {items.map(item => <li key={item.id} className={item.read_at ? 'notification-item' : 'notification-item notification-item--unread'}>
          <div className="notification-title"><strong>{item.title}</strong>{!item.read_at && <span className="notification-unread" aria-label="未读" />}</div>
          <p>{item.content}</p>
          <time dateTime={item.created_at}>{formatTime(item.created_at)}</time>
          <div className="notification-actions">
            <Link to={item.session_id ? `/sessions/${encodeURIComponent(item.session_id)}` : `/requests/${encodeURIComponent(item.request_id)}`} onClick={() => { if (!item.read_at) read.mutate(item.id); close() }}>查看详情</Link>
            {item.event_type === 'approval_requested' && <Link to="/approvals?tab=pending" onClick={() => { if (!item.read_at) read.mutate(item.id); close() }}>前往审批</Link>}
            {!item.read_at && <Button type="text" size="small" disabled={read.isPending} onClick={() => read.mutate(item.id)}>标为已读</Button>}
          </div>
        </li>)}
      </ul>}
      {(page > 0 || query.data?.has_more) && <div className="notification-pagination"><Button disabled={!page || query.isFetching} onClick={() => setPage(value => value - 1)}>上一页</Button><span>第 {page + 1} 页</span><Button disabled={!query.data?.has_more || query.isFetching} onClick={() => setPage(value => value + 1)}>下一页</Button></div>}
    </Drawer>
  </>
}
