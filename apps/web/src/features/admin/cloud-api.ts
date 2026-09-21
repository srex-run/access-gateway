import { queryOptions } from '@tanstack/react-query'
import { request, resourcePath } from '@/shared/api/client'
import type { RiskLevel } from '@/features/catalog'

export const cloudProviders = [{ value: 'aliyun', label: '阿里云 ECS' }, { value: 'aws', label: 'AWS EC2' }, { value: 'huaweicloud', label: '华为云 ECS' }]
export interface CloudAccount { id: string; name: string; provider: string; enabled: boolean; revision: number; updated_at: string }
export interface CloudAccountInput { name: string; provider: string; enabled: boolean; access_key?: string; secret_key?: string; session_token?: string; revision?: number }
export interface CloudSyncInput {
  region_id?: string; cloud_region: string; instance_ids: string[]
  ports: number[]; approver_id: string; risk_level: RiskLevel; max_ttl_seconds: number
}
export interface CloudSyncJob {
  id: string; account_id: string; actor_id: string; input: CloudSyncInput
  status: 'queued' | 'running' | 'success' | 'failed'; error: string
  result: { discovered: number; created: number; updated: number; skipped: number; missing_ids: string[] | null }
  created_at: string; started_at: string | null; finished_at: string | null
}
export const cloudAccountQuery = queryOptions({ queryKey: ['admin', 'cloud-accounts'], queryFn: ({ signal }) => request<CloudAccount[]>('/admin/cloud-accounts', { signal }) })
export const cloudJobsKey = ['admin', 'cloud-sync-jobs'] as const
export const cloudJobQuery = (region = '') => queryOptions({ queryKey: [...cloudJobsKey, region], queryFn: ({ signal }) => request<CloudSyncJob[]>('/admin/cloud-sync-jobs', { signal, query: { region_id: region || undefined } }) })
export const saveCloudAccount = (id: string | undefined, body: CloudAccountInput) => request<CloudAccount>(id ? resourcePath('admin/cloud-accounts', id) : '/admin/cloud-accounts', { method: id ? 'PATCH' : 'POST', body, validationMessages: true })
export const queueCloudSync = (account: string, body: CloudSyncInput) => request<CloudSyncJob>(resourcePath('admin/cloud-accounts', account, '/sync'), { method: 'POST', body, validationMessages: true })
