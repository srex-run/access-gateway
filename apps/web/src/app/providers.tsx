import { ConfigProvider } from '@arco-design/web-react'
import zhCN from '@arco-design/web-react/es/locale/zh-CN'
import { MutationCache, QueryCache, QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { useState } from 'react'
import type { ReactNode } from 'react'
import { ApiError } from '@/shared/api/client'

function handleUnauthorized(error: unknown): void {
  if (error instanceof ApiError && error.status === 401 && window.location.pathname !== '/login') window.location.replace('/login')
}

export function Providers({ children }: { children: ReactNode }) {
  const [client] = useState(() => new QueryClient({
    queryCache: new QueryCache({ onError: handleUnauthorized }),
    mutationCache: new MutationCache({ onError: handleUnauthorized }),
    defaultOptions: {
      queries: { staleTime: 30_000, refetchOnWindowFocus: false, retry: (failures, error) => !(error instanceof ApiError && error.status < 500) && failures < 1 },
      mutations: { retry: false },
    },
  }))
  return <QueryClientProvider client={client}><ConfigProvider locale={zhCN} size="default">{children}</ConfigProvider></QueryClientProvider>
}
