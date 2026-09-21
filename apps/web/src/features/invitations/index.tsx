import { Alert, Button, Form, Input, Popconfirm, Space, Tag } from '@arco-design/web-react'
import { IconPlus, IconRefresh } from '@arco-design/web-react/icon'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { PermissionGate } from '@/features/auth'
import type { LoginResult } from '@/features/auth'
import { request } from '@/shared/api/client'
import { usePagination } from '@/shared/hooks/use-pagination'
import { formatTime } from '@/shared/lib/format'
import { CopyableText } from '@/shared/ui/copyable-text'
import { DataTable } from '@/shared/ui/data-table'
import { DetailList, ErrorNotice, QueryState } from '@/shared/ui/page'
import { HelpPopover } from '@/shared/ui/help-popover'
import { ResourceForm } from '@/shared/ui/resource-form'
import { TabToolbar } from '@/shared/ui/route-tabs'

interface Invitation { id: string; user_id: string; username: string; nickname: string; inviter_name: string; status: 'pending' | 'accepted' | 'expired' | 'revoked'; expires_at: string; sent_at?: string; created_at: string }
interface CreatedInvitation { id: string; username: string; expires_at: string; sent: boolean; delivery: 'sent' | 'not_configured' | 'failed'; accept_url?: string }
interface CreateInput { username: string; nickname: string; email: string }
interface Preview { username: string; nickname: string; inviter_name: string; expires_at: string }

function InvitationResult({ value, onDone }: { value: CreatedInvitation; onDone: () => void }) {
  return <section className="invitation-result">
    <Alert type={value.sent ? 'success' : 'warning'} content={value.sent ? '邀请邮件已发送，用户可通过邮件设置自己的密码。' : value.delivery === 'failed' ? '邮件发送失败，请复制邀请链接交给受邀用户，或检查邮件设置后重发。' : '邮件服务尚未启用，请复制邀请链接交给受邀用户。'} />
    <DetailList items={[{ label: '用户名', value: value.username }, { label: '邀请有效至', value: formatTime(value.expires_at) }]} />
    {value.accept_url && <><Form.Item label={<>邀请链接<HelpPopover title="一次性邀请链接">此链接仅在本次结果中显示，可用于激活这个账户。请直接提供给受邀用户并妥善保管；重发邀请后旧链接失效。</HelpPopover></>}><CopyableText value={value.accept_url} /></Form.Item></>}
    <Button type="primary" onClick={onDone}>完成</Button>
  </section>
}

export function InvitationCreateForm() {
  const [form] = Form.useForm<CreateInput>()
  const [dirty, setDirty] = useState(false)
  const mutation = useMutation({ gcTime: 0, mutationFn: (body: CreateInput) => request<CreatedInvitation>('/admin/invitations', { method: 'POST', body, validationMessages: true }), onSuccess: () => setDirty(false) })
  if (mutation.data) return <InvitationResult value={mutation.data} onDone={() => { mutation.reset(); window.location.assign('/admin/users?tab=invitations') }} />
  return <ResourceForm form={form} onSubmit={values => mutation.mutate(values)} onChange={() => setDirty(true)} dirty={dirty} submitting={mutation.isPending} error={mutation.error} submitText="创建邀请" backTo="/admin/users?tab=invitations">
    <Form.Item label="用户名" field="username" rules={[{ required: true, match: /^[a-zA-Z0-9][a-zA-Z0-9._-]{2,63}$/, message: '请输入 3–64 位字母、数字、点、下划线或连字符' }]}><Input autoComplete="off" maxLength={64} /></Form.Item>
    <Form.Item label="昵称" field="nickname"><Input maxLength={128} placeholder="默认使用用户名" /></Form.Item>
    <Form.Item label={<>邮箱<HelpPopover title="邮箱邀请">用户收到邀请后自行设置密码。启用 SMTP 时自动发送邮件；未启用或发送失败时可复制邀请链接。默认创建普通用户，角色可在用户详情中分配。</HelpPopover></>} field="email" rules={[{ required: true, type: 'email', message: '请输入有效邮箱' }]}><Input aria-label="邮箱" type="email" maxLength={254} autoComplete="off" /></Form.Item>
  </ResourceForm>
}

const statusNames = { pending: '待接受', accepted: '已接受', expired: '已过期', revoked: '已撤销' }
const statusColors = { pending: 'orange', accepted: 'green', expired: 'gray', revoked: 'gray' }

export function InvitationsWorkspace() {
  const pagination = usePagination()
  const client = useQueryClient()
  const [result, setResult] = useState<CreatedInvitation>()
  const list = useQuery({ queryKey: ['invitations', pagination.offset, pagination.pageSize], queryFn: ({ signal }) => request<Invitation[]>('/admin/invitations', { signal, query: { limit: pagination.pageSize + 1, offset: pagination.offset } }) })
  const refresh = async () => { await client.invalidateQueries({ queryKey: ['invitations'] }); await client.invalidateQueries({ queryKey: ['users'] }) }
  const resend = useMutation({ gcTime: 0, mutationFn: (id: string) => request<CreatedInvitation>(`/admin/invitations/${id}/resend`, { method: 'POST', body: {}, validationMessages: true }), onSuccess: async value => { setResult(value); resend.reset(); await refresh() } })
  const revoke = useMutation({ mutationFn: (id: string) => request(`/admin/invitations/${id}`, { method: 'DELETE' }), onSuccess: refresh })
  const values = (list.data ?? []).slice(0, pagination.pageSize)
  return <>{result && <InvitationResult value={result} onDone={() => setResult(undefined)} />}
    <TabToolbar title="邮箱邀请">
      <Space><Button aria-label="刷新邀请" icon={<IconRefresh />} loading={list.isFetching} onClick={() => void list.refetch()} /><PermissionGate permission="user:manage"><Link to="/admin/users/invite"><Button type="primary" icon={<IconPlus />}>邀请用户</Button></Link></PermissionGate></Space>
    </TabToolbar>
    <ErrorNotice error={resend.error ?? revoke.error} />
    <DataTable data={values} loading={list.isPending} error={list.error} onRetry={() => void list.refetch()} pagination={{ ...pagination, count: values.length, hasNext: (list.data?.length ?? 0) > pagination.pageSize, onChange: pagination.change }} empty="暂无邀请" columns={[
      { title: '用户名', dataIndex: 'username', width: 150 }, { title: '昵称', dataIndex: 'nickname', width: 140 },
      { title: '邀请人', dataIndex: 'inviter_name', width: 130 },
      { title: '状态', width: 100, render: (_, value) => <Tag color={statusColors[value.status]}>{statusNames[value.status]}</Tag> },
      { title: '邮件', width: 110, render: (_, value) => value.sent_at ? '已发送' : '未发送' },
      { title: '有效至', width: 180, render: (_, value) => formatTime(value.expires_at) },
      { title: '创建时间', width: 180, render: (_, value) => formatTime(value.created_at) },
      { title: '操作', width: 160, fixed: 'right', render: (_, value) => <PermissionGate permission="user:manage"><Space>
        <Popconfirm title="重发邀请并使旧链接失效？" onOk={() => resend.mutateAsync(value.id).then(() => undefined)}><Button type="text" size="small" disabled={value.status === 'accepted'} loading={resend.isPending && resend.variables === value.id}>重发</Button></Popconfirm>
        <Popconfirm title="撤销此邀请？" onOk={() => revoke.mutateAsync(value.id).then(() => undefined)}><Button type="text" status="danger" size="small" disabled={value.status !== 'pending'}>撤销</Button></Popconfirm>
      </Space></PermissionGate> },
    ]} />
  </>
}

export function InviteAcceptPage() {
  const [token] = useState(() => window.location.hash.slice(1))
  const [form] = Form.useForm<{ password: string; confirm: string }>()
  useEffect(() => { window.history.replaceState(window.history.state, '', window.location.pathname + window.location.search) }, [])
  // The token remains only in this component; never use it as a query key or persist it.
  const preview = useQuery({ queryKey: ['invitation-preview'], queryFn: () => request<Preview>('/auth/invitation/preview', { method: 'POST', body: { token }, validationMessages: true }), enabled: token.length === 43, retry: false, refetchOnWindowFocus: false, staleTime: Infinity, gcTime: 0 })
  const accept = useMutation({ gcTime: 0, mutationFn: (values: { password: string }) => request<LoginResult>('/auth/invitation/accept', { method: 'POST', body: { token, password: values.password }, validationMessages: true }), onSuccess: value => window.location.assign(value.stage ? '/mfa' : '/catalog') })
  return <main className="login-page"><div className="login-brand"><img src="/favicon.svg" alt="" width={44} height={44} /><h1>Access Gateway</h1></div><div className="login-content"><h2>接受账户邀请</h2>
    {token.length !== 43 ? <Alert type="warning" content="请从邀请邮件或邀请人提供的完整链接重新打开此页面。" /> : <QueryState loading={preview.isPending} error={preview.error}>
      {preview.data && <><DetailList items={[{ label: '昵称', value: preview.data.nickname }, { label: '用户名', value: preview.data.username }, { label: '邀请人', value: preview.data.inviter_name }, { label: '有效至', value: formatTime(preview.data.expires_at) }]} />
        <Form form={form} layout="vertical" disabled={accept.isPending} onSubmit={value => accept.mutate(value)}>
          <Form.Item label="设置密码" field="password" rules={[{ required: true, message: '请设置密码' }, { validator: (value, callback) => { const length = new TextEncoder().encode(value ?? '').length; if (length < 12 || length > 72) callback('密码长度须为 12 至 72 字节') } }]}><Input.Password autoComplete="new-password" maxLength={72} /></Form.Item>
          <Form.Item label="确认密码" field="confirm" dependencies={['password']} rules={[{ required: true, message: '请确认密码' }, { validator: (value, callback) => { if (value !== form.getFieldValue('password')) callback('两次输入的密码不一致') } }]}><Input.Password autoComplete="new-password" maxLength={72} /></Form.Item>
          <ErrorNotice error={accept.error} /><Button type="primary" htmlType="submit" long loading={accept.isPending}>激活账户</Button>
        </Form>
      </>}
    </QueryState>}
    <Link className="mfa-back" to="/login">返回登录</Link>
  </div></main>
}
