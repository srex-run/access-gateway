import { queryOptions } from '@tanstack/react-query'
import { request, resourcePath } from '@/shared/api/client'
import type { AccessOptions, AccessRequest, CreateRequestInput } from './types'

export const accessOptionsQuery = queryOptions({ queryKey: ['access-options'], queryFn: ({ signal }) => request<AccessOptions>('/access-options', { signal }) })

export const requestKeys = { all: ['requests'] as const, list: (page: number, size: number) => ['requests', 'list', page, size] as const, detail: (id: string) => ['requests', 'detail', id] as const }
export const requestsQuery = (page: number, size: number) => queryOptions({
  queryKey: requestKeys.list(page, size),
  queryFn: ({ signal }) => request<AccessRequest[]>('/access-requests', { signal, query: { limit: size + 1, offset: (page - 1) * size } }),
})
export const requestQuery = (id: string) => queryOptions({ queryKey: requestKeys.detail(id), queryFn: ({ signal }) => request<AccessRequest>(resourcePath('access-requests', id), { signal }), enabled: !!id })
export const createRequest = (body: CreateRequestInput, idempotencyKey: string) => request<AccessRequest>('/access-requests', { method: 'POST', body, idempotencyKey, validationMessages: true })
export const createTestAccess = (body: CreateRequestInput, idempotencyKey: string) => request<AccessRequest>('/admin/access-tests', { method: 'POST', body, idempotencyKey, validationMessages: true })
interface RequestApprover { id: string; user_id: string; name: string; username: string; status: string; approval_level: number }
export const approversQuery = (asset: string) => queryOptions({ queryKey: ['catalog', 'request-approvers', asset], queryFn: ({ signal }) => request<RequestApprover[]>(resourcePath('assets', asset, '/approvers'), { signal }), enabled: !!asset })
export const cancelRequest = (id: string) => request<AccessRequest>(resourcePath('access-requests', id, '/cancel'), { method: 'POST' })
