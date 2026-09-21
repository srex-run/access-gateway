export const PAGE_SIZE_OPTIONS = [10, 20, 50] as const
export type PageSize = typeof PAGE_SIZE_OPTIONS[number]
export const DEFAULT_PAGE_SIZE: PageSize = 10
