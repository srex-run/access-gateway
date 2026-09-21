import { queryOptions } from '@tanstack/react-query'
import { request, resourcePath } from '@/shared/api/client'
import type { Asset, AssetPort, Region } from './types'

export const catalogKeys = {
  all: ['catalog'] as const,
  regions: ['catalog', 'regions'] as const,
  assets: (region: string) => ['catalog', 'assets', region] as const,
  ports: (asset: string) => ['catalog', 'ports', asset] as const,
}

export const regionQuery = queryOptions({ queryKey: catalogKeys.regions, queryFn: ({ signal }) => request<Region[]>('/regions', { signal }) })
export const assetQuery = (region: string) => queryOptions({ queryKey: catalogKeys.assets(region), queryFn: ({ signal }) => request<Asset[]>(resourcePath('regions', region, '/assets'), { signal }), enabled: !!region })
export const portQuery = (asset: string) => queryOptions({ queryKey: catalogKeys.ports(asset), queryFn: ({ signal }) => request<AssetPort[]>(resourcePath('assets', asset, '/ports'), { signal }), enabled: !!asset })
