import { encryptedFetch, TransportError } from './transport.mjs'
export { sealTerminalStart } from './transport.mjs'

export type QueryParams = Record<string, string | number | boolean | null | undefined>

interface RequestOptions {
  method?: 'GET' | 'POST' | 'PATCH' | 'DELETE'
  body?: unknown
  query?: QueryParams
  signal?: AbortSignal
  idempotencyKey?: string
  validationMessages?: boolean
}

const messages: Record<number, string> = {
  400: '提交内容不符合要求，请检查后重试。',
  401: '登录已过期，请重新登录。',
  403: '当前账号没有此操作权限。',
  404: '记录不存在或已不可用。',
  409: '记录状态已变化，请刷新后重试。',
  429: '请求过于频繁，请稍后重试。',
  502: '暂时无法连接服务，请稍后重试。',
  503: '服务暂时不可用，请稍后重试。',
}

export class ApiError extends Error {
  readonly status: number
  constructor(status: number, message?: string) {
    super(message ?? messages[status] ?? '请求失败，请稍后重试。')
    this.name = 'ApiError'
    this.status = status
  }
}

export function describeError(error: unknown): string {
  return error instanceof ApiError || error instanceof TransportError ? error.message : '操作未完成，请检查网络后重试。'
}

export async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  if (!path.startsWith('/') || path.startsWith('//') || path.includes('..')) {
    throw new Error('API paths must be relative to /api/v1')
  }
  const params = new URLSearchParams()
  for (const [key, value] of Object.entries(options.query ?? {})) {
    if (value !== undefined && value !== null && value !== '') params.set(key, String(value))
  }
  const headers = new Headers({ Accept: 'application/json' })
  if (options.body !== undefined) headers.set('Content-Type', 'application/json')
  if (options.idempotencyKey) headers.set('Idempotency-Key', options.idempotencyKey)
  const query = params.toString()
  const response = await encryptedFetch(`/api/v1${path}${query ? `?${query}` : ''}`, {
    method: options.method ?? 'GET',
    credentials: 'same-origin',
    cache: 'no-store',
    headers,
    signal: options.signal,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  })
  if (!response.ok) {
    if (response.status === 403) {
      const body: unknown = await response.json().catch(() => null)
      if (body && typeof body === 'object' && 'code' in body && body.code === 'origin_mismatch') {
        throw new ApiError(403, '当前访问地址与系统配置不一致，请使用系统配置的访问地址重新打开页面。')
      }
      if (body && typeof body === 'object' && 'code' in body && body.code === 'terminal_unavailable') {
        throw new ApiError(403, '当前会话不可连接，请确认会话仍在有效期内，并使用申请账号登录。')
      }
    }
    if (options.validationMessages && response.status === 400) {
      const body: unknown = await response.json().catch(() => null)
      if (body && typeof body === 'object' && 'error' in body && typeof body.error === 'string' && body.error.length <= 512) {
        if (body.error === 'bad request') throw new ApiError(400, '提交未通过校验，服务未返回具体原因。请检查必填项和字段格式；若刚更新服务，请重新启动服务后重试。')
        throw new ApiError(400, body.error)
      }
    }
    throw new ApiError(response.status)
  }
  if (response.status === 204) return undefined as T
  if (!response.headers.get('content-type')?.includes('application/json')) throw new ApiError(502)
  // The generic assertion is restricted to the transport boundary. Features own DTOs.
  return await response.json() as T
}

export function resourcePath(collection: string, id: string, suffix = ''): string {
  return `/${collection}/${encodeURIComponent(id)}${suffix}`
}
