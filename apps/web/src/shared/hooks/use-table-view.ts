import { useSearchParams } from 'react-router-dom'
import { usePagination } from './use-pagination'

// These catalog endpoints return complete lists. Keep filtering and pagination
// in the URL so separate form pages can return to the same list position.
export function useTableView<T>(scope: string, rows: T[] | undefined, searchText: (row: T) => string) {
  const [params, setParams] = useSearchParams()
  const paging = usePagination(scope)
  const search = params.get(`${scope}_search`) ?? ''
  const term = search.trim().toLocaleLowerCase()
  const filtered = (rows ?? []).filter(row => !term || searchText(row).toLocaleLowerCase().includes(term))
  const page = Math.min(paging.page, Math.max(1, Math.ceil(filtered.length / paging.pageSize)))
  const data = filtered.slice((page - 1) * paging.pageSize, page * paging.pageSize)
  const setSearch = (value: string) => setParams(previous => {
    const next = new URLSearchParams(previous)
    if (value) next.set(`${scope}_search`, value)
    else next.delete(`${scope}_search`)
    next.set(`${scope}_page`, '1')
    return next
  }, { replace: true })
  return { data, search, setSearch, pagination: {
    page, pageSize: paging.pageSize, hasNext: page * paging.pageSize < filtered.length,
    count: data.length, total: filtered.length, onChange: paging.change,
  } }
}
