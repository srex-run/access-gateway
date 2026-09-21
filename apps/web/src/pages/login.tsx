import { Alert, Button, Form, Input, Radio, Space } from '@arco-design/web-react'
import { IconArrowRight, IconGithub } from '@arco-design/web-react/icon'
import { useState } from 'react'
import { Navigate, useSearchParams } from 'react-router-dom'
import { useIdentity, useLoginProviders, usePasswordLogin } from '@/features/auth'
import type { LoginProvider } from '@/features/auth'
import { ApiError } from '@/shared/api/client'
import { ErrorNotice, QueryState } from '@/shared/ui/page'

function PasswordLogin({ provider }: { provider: LoginProvider }) {
  const login = usePasswordLogin(provider.id)
  return <Form layout="vertical" onSubmit={value => login.mutate(value)} disabled={login.isPending}>
    <Form.Item label="账号" field="username" rules={[{ required: true, message: '请输入账号' }]}><Input autoComplete="username" maxLength={256} /></Form.Item>
    <Form.Item label="密码" field="password" rules={[{ required: true, message: '请输入密码' }]}><Input.Password autoComplete="current-password" maxLength={1024} /></Form.Item>
    {login.error instanceof ApiError && login.error.status === 401 ? <Alert type="error" content="账号或密码错误，或账号已停用。" /> : <ErrorNotice error={login.error} />}
    <Button type="primary" htmlType="submit" long size="large" icon={<IconArrowRight />} loading={login.isPending}>登录</Button>
  </Form>
}

export default function LoginPage() {
  const identity = useIdentity()
  const providers = useLoginProviders()
  const [selected, setSelected] = useState('')
  const [params] = useSearchParams()
  const passwords = providers.data?.filter(provider => provider.kind === 'password') ?? []
  const passwordProvider = passwords.find(provider => provider.id === selected) ?? passwords[0]
  if (identity.data) return <Navigate to="/catalog" replace />
  const error = identity.error instanceof ApiError && identity.error.status === 401 ? null : identity.error
  return <main className="login-page"><div className="login-brand"><img src="/favicon.svg" alt="" width={44} height={44} /><h1>Access Gateway</h1></div>
    <div className="login-content"><h2>登录工作台</h2><ErrorNotice error={error} retry={() => void identity.refetch()} />
      {params.has('error') && <Alert type="error" content="身份验证未完成，请重新登录。" />}
      {params.get('password') === 'changed' && <Alert type="success" content="密码已更新，请重新登录。" />}
      <QueryState loading={providers.isPending} error={providers.error} retry={() => void providers.refetch()}>
        {passwords.length > 1 && <Radio.Group className="login-modes" type="button" value={passwordProvider?.id} onChange={setSelected} options={passwords.map(provider => ({ label: provider.name, value: provider.id }))} />}
        {passwordProvider && <PasswordLogin key={passwordProvider.id} provider={passwordProvider} />}
        <Space direction="vertical" className="full-width login-providers">{providers.data?.filter(provider => provider.kind === 'redirect').map(provider => <Button className="login-provider" key={provider.id} type={passwordProvider ? 'secondary' : 'primary'} long size="large" icon={provider.id === 'github' ? <IconGithub /> : <IconArrowRight />} href={`/api/v1/auth/${provider.id}/login`}>{provider.name}登录</Button>)}</Space>
        {providers.data?.length === 0 && <Alert type="warning" content="暂无可用的登录方式，请联系管理员。" />}
      </QueryState>
    </div><footer className="login-footer">Access Gateway · 企业访问控制</footer>
  </main>
}
