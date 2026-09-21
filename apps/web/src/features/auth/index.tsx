import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { request } from '@/shared/api/client'
import { hasPermission } from '@/shared/lib/permissions'
import type { Permission } from '@/shared/lib/permissions'

export type { Permission } from '@/shared/lib/permissions'
export interface Identity { user_id: string; permissions: Permission[] }
export const identityKey = ['identity'] as const

export interface LoginProvider { id: 'local' | 'oidc' | 'ldap' | 'oauth2' | 'github' | 'feishu'; name: string; kind: 'password' | 'redirect' }
export interface LoginResult { user_id?: string; stage?: 'mfa-enroll' | 'mfa-verify'; expires_at?: string }
export { MFAChallengePage, UserMFAStatus } from './mfa'

export function useLoginProviders() {
  return useQuery({ queryKey: ['login-providers'], queryFn: ({ signal }) => request<LoginProvider[]>('/auth/providers', { signal }), staleTime: 30_000, retry: false })
}

export function usePasswordLogin(provider: string) {
  return useMutation({
    mutationFn: (body: { username: string; password: string }) => request<LoginResult>(`/auth/${provider}/login`, { method: 'POST', body }),
    onSuccess: value => window.location.assign(value.stage ? '/mfa' : '/catalog'),
  })
}

export { AccountSettings } from './account'

export function useIdentity() {
  return useQuery({ queryKey: identityKey, queryFn: ({ signal }) => request<Identity>('/auth/me', { signal }), staleTime: 30_000, retry: false, refetchOnWindowFocus: true })
}

interface PermissionGateProps { permission: Permission | Permission[]; children: ReactNode; fallback?: ReactNode }
export function PermissionGate({ permission, children, fallback = null }: PermissionGateProps) {
  const { data } = useIdentity()
  return <>{hasPermission(data?.permissions ?? [], permission) ? children : fallback}</>
}

export function useLogout() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: () => request<void>('/auth/logout', { method: 'POST' }),
    onSuccess: async () => {
      await client.cancelQueries()
      client.clear()
      window.location.assign('/login')
    },
  })
}
