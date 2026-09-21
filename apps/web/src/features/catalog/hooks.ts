import { useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { assetQuery, regionQuery } from './api'

export function useCatalog() {
  const [params, setParams] = useSearchParams()
  const regions = useQuery(regionQuery)
  const region = params.get('region') ?? regions.data?.[0]?.id ?? ''
  const assets = useQuery(assetQuery(region))
  const search = params.get('q') ?? ''
  const setFilter = (key: string, value: string) => setParams(previous => {
    const next = new URLSearchParams(previous)
    if (value) next.set(key, value); else next.delete(key)
    return next
  }, { replace: true })
  const data = (assets.data ?? []).filter(asset => `${asset.name} ${asset.asset_type} ${asset.id}`.toLowerCase().includes(search.toLowerCase()))
  return { regions, assets, region, search, setFilter, data }
}
