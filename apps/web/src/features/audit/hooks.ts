import { useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { useIdentity } from '@/features/auth'
import { request } from '@/shared/api/client'
import { usePagination } from '@/shared/hooks/use-pagination'
import type { AuditEvent } from './types'

export interface AuditFilters { category: string; action: string; actor_id: string; event_type: string; session_id: string; result: string }
export function useAudit() {
  const identity = useIdentity()
  const canReadAll = identity.data?.permissions.includes('audit:read') ?? false
  const [params, setParams] = useSearchParams()
  const pagination = usePagination()
  const filter = { category: params.get('category') ?? '', action: params.get('action') ?? '', actor_id: params.get('actor_id') ?? '', event_type: params.get('event_type') ?? '', session_id: params.get('session_id') ?? '', result: params.get('result') ?? '' }
  const query = useQuery({
    queryKey: ['audit', identity.data?.user_id, canReadAll, 'access', filter, pagination.page, pagination.pageSize],
    enabled: canReadAll,
    queryFn: ({ signal }) => request<AuditEvent[]>('/audit-events', { signal, query: { ...filter, limit: pagination.pageSize + 1, offset: pagination.offset } }),
  })
  const apply = (values: AuditFilters) => setParams(previous => {
    const next = new URLSearchParams(previous)
    for (const [key, value] of Object.entries(values)) { if (value?.trim()) next.set(key, value.trim()); else next.delete(key) }
    next.delete('page')
    return next
  })
  const refresh = () => void query.refetch()
  return { query, filter, pagination, apply, refresh, data: (query.data ?? []).slice(0, pagination.pageSize) }
}
