import { Message } from '@arco-design/web-react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { usePagination } from '@/shared/hooks/use-pagination'
import { closeSession, forceCloseSession, recordsQuery, sessionKeys } from './api'

export function useSessionList() {
  const pagination = usePagination('records')
  const [params, setParams] = useSearchParams()
  const search = params.get('search') ?? ''
  const status = params.get('status') ?? ''
  const query = useQuery(recordsQuery(pagination.page, pagination.pageSize, search, status))
  const filter = (key: string, value: string) => setParams(previous => {
    const next = new URLSearchParams(previous)
    if (value) next.set(key, value)
    else next.delete(key)
    next.delete('records_page')
    return next
  })
  return { pagination, search, status, filter, query, data: (query.data ?? []).slice(0, pagination.pageSize), retry: () => void query.refetch() }
}

export function useSessionActions() {
  const client = useQueryClient()
  const refresh = async () => { await client.invalidateQueries({ queryKey: sessionKeys.all }); Message.success('回收请求已提交') }
  const close = useMutation({ mutationFn: closeSession, onSuccess: refresh })
  const forceClose = useMutation({ mutationFn: ({ id, reason }: { id: string; reason: string }) => forceCloseSession(id, reason), onSuccess: refresh })
  return { close, forceClose }
}
