import { queryOptions } from '@tanstack/react-query'
import { request, resourcePath } from '@/shared/api/client'
import type { Ownership, RoleBinding, RoleDefinition, Workflow, WorkflowView } from './types'

export const rolesQuery = queryOptions({ queryKey: ['governance', 'roles'], queryFn: ({ signal }) => request<RoleDefinition[]>('/admin/roles', { signal }) })
export const bindingsQuery = queryOptions({ queryKey: ['governance', 'bindings'], queryFn: ({ signal }) => request<RoleBinding[]>('/admin/role-bindings', { signal }) })
export const workflowsQuery = queryOptions({ queryKey: ['governance', 'workflows'], queryFn: ({ signal }) => request<Workflow[]>('/admin/workflows', { signal }) })
export const ownersQuery = queryOptions({ queryKey: ['governance', 'ownerships'], queryFn: ({ signal }) => request<Ownership[]>('/admin/ownerships', { signal }) })
export const workflowQuery = (requestID?: string, assetID?: string) => queryOptions({
  // Asset saves invalidate catalog data, including the approval preview. Existing
  // requests use their own immutable workflow snapshot and separate cache entry.
  queryKey: requestID ? ['workflow-progress', requestID, assetID] : ['catalog', 'workflow-preview', assetID],
  enabled: !!(requestID || assetID),
  queryFn: ({ signal }) => request<WorkflowView>(requestID ? resourcePath('access-requests', requestID, '/workflow') : resourcePath('assets', assetID!, '/workflow'), { signal, validationMessages: true }),
  staleTime: 0,
  refetchOnMount: 'always',
  refetchOnWindowFocus: true,
})
