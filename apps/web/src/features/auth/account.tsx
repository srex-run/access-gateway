import { Alert, Button, Form, Input, Popconfirm } from '@arco-design/web-react'
import { IconDelete, IconLink, IconLock } from '@arco-design/web-react/icon'
import { useMutation, useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { ApiError, request } from '@/shared/api/client'
import { CopyableText } from '@/shared/ui/copyable-text'
import { DetailList, ErrorNotice, QueryState, SectionTitle } from '@/shared/ui/page'
import { MFASettings } from './mfa'

interface Account {
  user_id: string
  nickname: string
  username: string
  providers: string[]
  feishu_bound: boolean
  feishu_configured: boolean
  feishu_binding_enabled: boolean
}

const providerNames: Record<string, string> = { local: '本地账号', oidc: 'OIDC', oauth2: 'OAuth2', github: 'GitHub', ldap: 'LDAP', feishu: '飞书' }

export function AccountSettings() {
  const [form] = Form.useForm()
  const [params] = useSearchParams()
  const account = useQuery({ queryKey: ['account'], queryFn: ({ signal }) => request<Account>('/auth/account', { signal }) })
  const bind = useMutation({ mutationFn: () => request<{ url: string }>('/auth/feishu/bind', { method: 'POST' }), onSuccess: value => window.location.assign(value.url) })
  const unbind = useMutation({ mutationFn: () => request('/auth/feishu/bind', { method: 'DELETE' }), onSuccess: () => window.location.assign('/login') })
  const password = useMutation({ mutationFn: (body: { current_password: string; new_password: string }) => request('/auth/password', { method: 'POST', body }), onSuccess: () => window.location.assign('/login?password=changed') })
  return <QueryState loading={account.isPending} error={account.error} retry={() => void account.refetch()}>
    {account.data && <>
      <MFASettings />
      <DetailList items={[{ label: '用户名', value: account.data.username }, { label: '昵称', value: account.data.nickname }, { label: '用户 ID', value: <CopyableText value={account.data.user_id} /> }, { label: '登录身份', value: account.data.providers.map(provider => providerNames[provider] ?? provider).join('、') }]} />
      {account.data.feishu_configured && <><SectionTitle>飞书账号</SectionTitle>
      {params.has('error') && <Alert type="error" content="飞书账号绑定失败，账号可能已被其他用户绑定。" />}
      {params.get('feishu') === 'bound' && <Alert type="success" content="飞书账号已绑定。" />}
      <ErrorNotice error={bind.error} />
      {unbind.error instanceof ApiError && unbind.error.status === 409 ? <Alert type="error" content="需要保留至少一种可用的登录方式。" /> : <ErrorNotice error={unbind.error} />}
      <div className="account-binding"><span>{account.data.feishu_bound ? '已绑定' : '未绑定'}</span>
        {account.data.feishu_bound ? <Popconfirm title="解除飞书绑定并退出登录？" onOk={() => unbind.mutateAsync().then(() => undefined)}><Button status="danger" icon={<IconDelete />} loading={unbind.isPending}>解除绑定</Button></Popconfirm> : <Button icon={<IconLink />} disabled={!account.data.feishu_binding_enabled} loading={bind.isPending} onClick={() => bind.mutate()}>绑定飞书</Button>}
      </div>
      </>}
      {account.data.providers.includes('local') && <><SectionTitle>修改密码</SectionTitle>
        <Form form={form} layout="vertical" disabled={password.isPending} onSubmit={value => password.mutate({ current_password: value.current_password, new_password: value.new_password })}>
          <Form.Item label="账号"><Input value={account.data.username} readOnly autoComplete="username" /></Form.Item>
          <Form.Item label="当前密码" field="current_password" rules={[{ required: true, message: '请输入当前密码' }]}><Input.Password autoComplete="current-password" maxLength={72} /></Form.Item>
          <Form.Item label="新密码" field="new_password" rules={[{ required: true, message: '请输入新密码' }, { validator: (value, callback) => { const length = new TextEncoder().encode(value ?? '').length; if (length < 12 || length > 72) callback('密码长度须为 12 至 72 字节') } }]}><Input.Password autoComplete="new-password" maxLength={72} /></Form.Item>
          <Form.Item label="确认新密码" field="confirm_password" dependencies={['new_password']} rules={[{ required: true, message: '请确认新密码' }, { validator: (value, callback) => { if (value !== form.getFieldValue('new_password')) callback('两次输入的密码不一致') } }]}><Input.Password autoComplete="new-password" maxLength={72} /></Form.Item>
          {password.error instanceof ApiError && password.error.status === 401 ? <Alert type="error" content="当前密码不正确。" /> : <ErrorNotice error={password.error} />}
          <Button type="primary" htmlType="submit" icon={<IconLock />} loading={password.isPending}>更新密码</Button>
        </Form>
      </>}
    </>}
  </QueryState>
}
