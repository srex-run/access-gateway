import { request, resourcePath } from '@/shared/api/client'
import { queryOptions } from '@tanstack/react-query'
import type { Asset } from '@/features/catalog'
import type { AssetInput, AssetUpdateInput, CreatedResource } from './types'
import type { AssetAuditView } from './asset-form-model'
export const createAsset = (body: AssetInput) => request<CreatedResource>('/admin/assets', { method: 'POST', body, validationMessages: true })
export const assetAuditQuery = (id: string) => queryOptions({ queryKey: ['catalog', 'asset-audit', id], queryFn: ({ signal }) => request<AssetAuditView>(resourcePath('admin/assets', id, '/audit'), { signal, validationMessages: true }), refetchOnWindowFocus: false })
export const updateAsset = (id: string, body: AssetUpdateInput) => request<Asset>(resourcePath('admin/assets', id), { method: 'PATCH', body, validationMessages: true })
export const updateStatus = (type: 'assets', id: string, status: string) => request<CreatedResource>(resourcePath(`admin/${type}`, id, '/status'), { method: 'PATCH', body: { status } })
export const managedAssetsQuery = queryOptions({ queryKey: ['catalog', 'managed-assets'], queryFn: ({ signal }) => request<Asset[]>('/admin/assets', { signal }) })
