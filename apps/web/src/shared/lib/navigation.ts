export function queryPath(path: string, search: string | URLSearchParams, changes: Record<string, string | null> = {}) {
  const params = new URLSearchParams(search)
  for (const [key, value] of Object.entries(changes)) {
    if (value === null) params.delete(key)
    else params.set(key, value)
  }
  const query = params.toString()
  return query ? `${path}?${query}` : path
}
