import { infiniteQueryOptions, queryOptions } from '@tanstack/react-query'
import { ApiError, request, resourcePath } from '@/shared/api/client'
import type { Session, SessionEvent, SessionRecord, SessionRecordDetail, SessionTraceEvent, TerminalRecordingFrame } from './types'

export const sessionKeys = { all: ['sessions'] as const, detail: (id: string) => ['sessions', 'detail', id] as const, byRequest: (id: string) => ['sessions', 'request', id] as const }
export const sessionQuery = (id: string, byRequest = false) => queryOptions({
  queryKey: byRequest ? sessionKeys.byRequest(id) : sessionKeys.detail(id),
  queryFn: ({ signal }) => request<Session>(resourcePath(byRequest ? 'access-requests' : 'sessions', id, byRequest ? '/session' : ''), { signal }),
  enabled: !!id,
})
export const eventQuery = (id: string, page: number, size: number) => queryOptions({ queryKey: ['sessions', 'events', id, page, size], queryFn: ({ signal }) => request<SessionEvent[]>(resourcePath('sessions', id, '/events'), { signal, query: { limit: size + 1, offset: (page - 1) * size } }), enabled: !!id })
export const closeSession = (id: string) => request<Session>(resourcePath('sessions', id, '/close'), { method: 'POST' })
export const forceCloseSession = (id: string, reason: string) => request<Session>(resourcePath('admin/sessions', id, '/force-close'), { method: 'POST', body: { reason }, validationMessages: true })

export const recordsQuery = (page: number, size: number, search: string, status: string) => queryOptions({
  queryKey: ['sessions', 'records', page, size, search, status],
  queryFn: ({ signal }) => request<SessionRecord[]>('/session-records', { signal, query: { limit: size + 1, offset: (page - 1) * size, search, status } }),
})
export const openRecordsQuery = (search: string) => infiniteQueryOptions({
  queryKey: ['sessions', 'open-records', search],
  initialPageParam: 0,
  queryFn: async ({ signal, pageParam }) => {
    const size = 50
    try {
      const records = await request<SessionRecord[]>('/session-records', { signal, query: { limit: size + 1, offset: pageParam, search, status: 'open' }, validationMessages: true })
      return { records: records.slice(0, size), nextOffset: records.length > size ? pageParam + size : undefined }
    } catch (error) {
      if (error instanceof ApiError && error.status === 400) throw new ApiError(400, `加载开放会话失败：${error.message}`)
      throw error
    }
  },
  getNextPageParam: page => page.nextOffset,
})
export const recordQuery = (id: string, byRequest: boolean) => queryOptions({
  queryKey: ['sessions', 'record', id, byRequest],
  queryFn: ({ signal }) => request<SessionRecordDetail>(resourcePath(byRequest ? 'access-requests' : 'session-records', id, byRequest ? '/record' : ''), { signal }),
  enabled: !!id,
})
export const traceQuery = (id: string, page: number, size: number, stage: string) => queryOptions({
  queryKey: ['sessions', 'trace', id, page, size, stage],
  queryFn: ({ signal }) => request<SessionTraceEvent[]>(resourcePath('session-records', id, '/trace'), { signal, query: { limit: size + 1, offset: (page - 1) * size, stage } }),
  enabled: !!id,
})

export const terminalRecordingQuery = (sessionId: string, channelId: string) => infiniteQueryOptions({
  queryKey: ['sessions', 'terminal-recording', sessionId, channelId],
  initialPageParam: 0,
  queryFn: async ({ signal, pageParam }) => {
    const size = 100
    const frames = await request<TerminalRecordingFrame[]>(resourcePath('session-records', sessionId, `/terminal-recordings/${encodeURIComponent(channelId)}`), { signal, query: { limit: size + 1, offset: pageParam } })
    return { frames: frames.slice(0, size), nextOffset: frames.length > size ? pageParam + size : undefined }
  },
  getNextPageParam: page => page.nextOffset,
})
