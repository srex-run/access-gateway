import { useSearchParams } from 'react-router-dom'
import { DEFAULT_PAGE_SIZE, PAGE_SIZE_OPTIONS } from '@/shared/lib/pagination'
import type { PageSize } from '@/shared/lib/pagination'

export function usePagination(scope = '', defaultPageSize: PageSize = DEFAULT_PAGE_SIZE) {
  const [params, setParams] = useSearchParams()
  const pageKey = scope ? `${scope}_page` : 'page'
  const sizeKey = scope ? `${scope}_size` : 'size'
  const rawPage = Number(params.get(pageKey))
  const rawSize = Number(params.get(sizeKey))
  const page = Number.isSafeInteger(rawPage) && rawPage > 0 ? Math.min(rawPage, 10000) : 1
  const pageSize = PAGE_SIZE_OPTIONS.some(value => value === rawSize) ? rawSize : defaultPageSize
  const change = (nextPage: number, nextSize = pageSize) => {
    setParams(previous => {
      const next = new URLSearchParams(previous)
      next.set(pageKey, String(nextSize === pageSize ? nextPage : 1))
      next.set(sizeKey, String(nextSize))
      return next
    })
  }
  return { page, pageSize, offset: (page - 1) * pageSize, change }
}
