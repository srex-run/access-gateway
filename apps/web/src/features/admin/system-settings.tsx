import { Button, Checkbox, Form, Input, InputNumber, Message, Select, Space, Switch, Tag } from '@arco-design/web-react'
import { IconCopy, IconRefresh } from '@arco-design/web-react/icon'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { useState } from 'react'
import { request } from '@/shared/api/client'
import { QueryState, SectionTitle } from '@/shared/ui/page'
import { ResourceForm } from '@/shared/ui/resource-form'
import { RouteTabs } from '@/shared/ui/route-tabs'
import type { Provider, Secret, Config, SettingsView, SecretFields } from './settings-types'
import { CloudAccounts } from './cloud-accounts'
import { HelpPopover } from '@/shared/ui/help-popover'
import { CopyableText } from '@/shared/ui/copyable-text'
import { ClientAccessHelp } from '@/shared/ui/client-access-help'

const queryKey = ['admin', 'settings'] as const
const required = [{ required: true, match: /\S/, message: '此项不能为空' }]

function TextField({ field, label, required: needed = false, children }: { field: string; label: string; required?: boolean; children?: ReactNode }) {
  return <Form.Item field={field} label={label} rules={needed ? required : undefined}>{children ?? <Input maxLength={2048} />}</Form.Item>
}
function Toggle({ field, label }: { field: string; label: string }) {
  return <Form.Item field={field} label={label} triggerPropName="checked"><Switch /></Form.Item>
}
function SecretField({ name, label, view }: { name: Secret; label: string; view: SettingsView }) {
  return <div className="settings-secret">
    <Form.Item field={`secrets.${name}`} label={<Space>{label}<Tag size="small" color={view.has_secrets[name] ? 'green' : undefined}>{view.has_secrets[name] ? '已配置' : '未配置'}</Tag></Space>}>
      <Input.Password autoComplete="new-password" maxLength={8192} />
    </Form.Item>
    {view.has_secrets[name] && <Form.Item field={`clear.${name}`} triggerPropName="checked" noStyle><Checkbox>清除密钥</Checkbox></Form.Item>}
  </div>
}
function CopyURLButton({ value, label = '复制回调地址' }: { value: string; label?: string }) {
  const copy = async () => {
    try { await navigator.clipboard.writeText(value); Message.success('已复制') }
    catch { Message.error('复制失败') }
  }
  return <Button type="text" icon={<IconCopy />} disabled={!value} title={value} onClick={() => void copy()}>{label}</Button>
}
function CallbackAction({ view, provider }: { view: SettingsView; provider: string }) {
  return <CopyURLButton value={view.config.base_url ? `${view.config.base_url}/api/v1/auth/${provider}/callback` : ''} />
}

function SettingsForm<T extends object>({ view, initial, apply, children }: { view: SettingsView; initial: T; apply: (value: T) => Config; children: ReactNode }) {
  const [form] = Form.useForm<T & SecretFields>()
  const [dirty, setDirty] = useState(false)
  const client = useQueryClient()
  const mutation = useMutation({
    mutationFn: (value: T & SecretFields) => {
      const secrets: Partial<Record<Secret, string>> = {}
      for (const key of ['oidc', 'oauth2', 'github', 'ldap', 'feishu_app', 'feishu_callback', 'smtp_password'] as const) {
        if (value.clear?.[key]) secrets[key] = ''
        else if (value.secrets?.[key]) secrets[key] = value.secrets[key]
      }
      return request<SettingsView>('/admin/settings', { method: 'PATCH', body: { revision: view.revision, config: apply(value), secrets }, validationMessages: true })
    },
    onSuccess: async saved => {
      setDirty(false)
      form.resetFields()
      client.setQueryData(queryKey, saved)
      await client.invalidateQueries({ queryKey: ['login-providers'] })
      await client.invalidateQueries({ queryKey: ['account'] })
      await client.invalidateQueries({ queryKey: ['account-mfa'] })
      await client.invalidateQueries({ queryKey: ['access-options'] })
      Message.success('设置已保存')
    },
  })
  return <ResourceForm form={form} initialValues={initial} dirty={dirty} submitting={mutation.isPending} error={mutation.error} onChange={() => setDirty(true)} onSubmit={value => mutation.mutate(value)}>{children}</ResourceForm>
}

function PlatformForm({ view }: { view: SettingsView }) {
  return <SettingsForm view={view} initial={{ timeout_seconds: view.config.timeout_seconds, allow_http: view.config.auth.allow_http, client_access_enabled: view.config.client_access_enabled ?? false, client_access_host: view.config.client_access_host ?? '' }} apply={value => ({ ...view.config, client_access_enabled: value.client_access_enabled, client_access_host: value.client_access_host, timeout_seconds: value.timeout_seconds, auth: { ...view.config.auth, allow_http: value.allow_http } })}>
    <Form.Item label={<>平台访问地址<HelpPopover title="平台访问地址">由部署配置 PUBLIC_URL 提供，登录回调和邀请链接自动使用此地址。修改 PUBLIC_URL 后需重启服务。</HelpPopover></>}><CopyableText value={view.config.base_url} /></Form.Item>
    <Form.Item field="client_access_enabled" label={<>本地客户端访问<ClientAccessHelp /></>} triggerPropName="checked"><Switch aria-label="启用本地客户端访问" /></Form.Item>
    <Form.Item noStyle shouldUpdate>{values => values.client_access_enabled && <Form.Item field="client_access_host" label={<>本地客户端访问地址<HelpPopover title="本地客户端访问地址">
      <p>填写本机 SSH、数据库等客户端能够通过 TCP 连接的 access-gateway 服务器 IP 或域名。同一内网或通过 VPN 连接时可使用内网地址，跨公网访问时需要公网 IP。</p>
      <p>这里只填写 IP 或域名，不加 tcp://、http://、https://、端口或路径。连接时使用会话详情分配的 TCP 端口，例如 gateway.example.com:20000；需放行端口范围，默认 20000–20999。域名应直连网关，Cloudflare 普通代理无法转发这些 TCP 会话。</p>
      <p>此地址可独立于网站访问地址。更换后请更新资产端口的网关证书并重新申请会话，使证书包含新的访问地址。</p>
    </HelpPopover></>} rules={required}><Input aria-label="本地客户端访问地址" placeholder="客户端可达的网关 IP 或域名" maxLength={253} /></Form.Item>}</Form.Item>
    <Form.Item field="timeout_seconds" label="认证请求超时（秒）" rules={[{ required: true, type: 'number', min: 1, max: 60 }]}><InputNumber min={1} max={60} precision={0} /></Form.Item>
    <Toggle field="allow_http" label="允许认证源使用 HTTP" />
  </SettingsForm>
}
function ProviderForm({ view, provider }: { view: SettingsView; provider: Provider }) {
  const initial = { provider: view.config.auth[provider] }
  return <SettingsForm view={view} initial={initial} apply={value => ({ ...view.config, auth: { ...view.config.auth, [provider]: value.provider } })}>
    {provider === 'github' && <SectionTitle extra={<HelpPopover title="配置 GitHub 登录">回调地址由平台访问地址自动生成。点击“复制回调地址”，在 GitHub OAuth App 的 Authorization callback URL 中粘贴，再填写 Client ID 和 Client Secret。仅申请用户资料和邮箱权限；首次登录创建普通账户，资产访问仍受平台授权控制。</HelpPopover>}>GitHub OAuth App<Button type="text" href="https://github.com/settings/applications/new" target="_blank" rel="noopener noreferrer">创建应用</Button></SectionTitle>}
    <Toggle field="provider.enabled" label="启用登录" />
    <TextField field="provider.name" label="显示名称" required />
    {provider === 'ldap' ? <>
      <TextField field="provider.url" label="LDAP 服务器地址" />
      <div className="form-grid"><TextField field="provider.bind_dn" label="绑定 DN" /><TextField field="provider.base_dn" label="搜索基准 DN" /></div>
      <SecretField name="ldap" label="绑定密码" view={view} />
      <TextField field="provider.user_filter" label="用户过滤器" />
      <div className="form-grid"><TextField field="provider.id_attribute" label="唯一标识属性" /><TextField field="provider.username_attribute" label="用户名属性" /><TextField field="provider.name_attribute" label="昵称属性" /><TextField field="provider.email_attribute" label="邮箱属性" /></div>
      <TextField field="provider.root_ca_pem" label="根证书（PEM）"><Input.TextArea autoSize={{ minRows: 4, maxRows: 10 }} maxLength={32768} /></TextField>
    </> : <>
      {provider === 'oidc' && <TextField field="provider.issuer" label="Issuer 地址" />}
      <TextField field="provider.client_id" label="Client ID" />
      <SecretField name={provider} label="Client Secret" view={view} />
      {provider === 'oauth2' && <>
        <TextField field="provider.authorize_url" label="授权地址" />
        <TextField field="provider.token_url" label="令牌地址" />
        <TextField field="provider.user_info_url" label="用户信息地址" />
        <div className="form-grid"><TextField field="provider.subject_claim" label="唯一标识字段" /><TextField field="provider.username_claim" label="用户名字段" /><TextField field="provider.name_claim" label="昵称字段" /><TextField field="provider.email_claim" label="邮箱字段" /></div>
      </>}
      {provider !== 'github' && <Form.Item field="provider.scopes" label="授权范围"><Select mode="multiple" allowCreate options={['openid', 'profile', 'email']} /></Form.Item>}
      <CallbackAction view={view} provider={provider} />
    </>}
  </SettingsForm>
}
function FeishuForm({ view }: { view: SettingsView }) {
  return <SettingsForm view={view} initial={{ feishu: view.config.feishu }} apply={value => ({ ...view.config, feishu: value.feishu })}>
    <SectionTitle>飞书应用</SectionTitle>
    <TextField field="feishu.app_id" label="App ID" />
    <SecretField name="feishu_app" label="App Secret" view={view} />
    <TextField field="feishu.tenant_key" label="租户标识" />
    <SectionTitle>登录与账号绑定</SectionTitle>
    <div className="form-grid"><Toggle field="feishu.login_enabled" label="飞书登录" /><Toggle field="feishu.binding_enabled" label="账号绑定" /></div>
    <CallbackAction view={view} provider="feishu" />
    <SectionTitle>通知与审批回调</SectionTitle>
    <div className="form-grid"><Toggle field="feishu.notifications_enabled" label="飞书通知" /><Toggle field="feishu.callbacks_enabled" label="飞书审批回调" /></div>
    <SecretField name="feishu_callback" label="回调密钥" view={view} />
    <CopyURLButton value={view.config.base_url ? `${view.config.base_url}/callbacks/feishu` : ''} label="复制审批回调地址" />
  </SettingsForm>
}

function SMTPForm({ view }: { view: SettingsView }) {
  const smtp = view.config.smtp ?? { enabled: false, host: '', port: 587, username: '', from: '', tls_mode: 'starttls' as const }
  return <SettingsForm view={view} initial={{ smtp, invitation_ttl_hours: view.config.invitation_ttl_hours ?? 72 }} apply={value => ({ ...view.config, smtp: value.smtp, invitation_ttl_hours: value.invitation_ttl_hours })}>
    <SectionTitle extra={<HelpPopover title="邀请邮件">启用 SMTP 后，创建邀请会自动发送邮件，邀请链接使用平台访问地址。未启用或发送失败时，可在邀请结果中复制一次性链接。</HelpPopover>}>邮件发送</SectionTitle>
    <Toggle field="smtp.enabled" label="启用邀请邮件" />
    <div className="form-grid"><TextField field="smtp.host" label="SMTP 服务器" /><Form.Item field="smtp.port" label="端口" rules={[{ required: true, type: 'number', min: 1, max: 65535 }]}><InputNumber min={1} max={65535} precision={0} /></Form.Item></div>
    <Form.Item field="smtp.tls_mode" label={<>连接加密<HelpPopover title="SMTP 加密">STARTTLS 通常使用 587 端口，TLS 通常使用 465 端口。始终验证邮件服务器证书。</HelpPopover></>}><Select options={[{ value: 'starttls', label: 'STARTTLS' }, { value: 'tls', label: 'TLS' }]} /></Form.Item>
    <TextField field="smtp.username" label="SMTP 用户名" />
    <SecretField name="smtp_password" label="SMTP 密码 / 授权码" view={view} />
    <TextField field="smtp.from" label="发件邮箱" />
    <Form.Item field="invitation_ttl_hours" label={<>邀请有效期（小时）<HelpPopover title="邀请有效期">仅影响之后创建或重发的邀请，范围为 1 小时至 14 天。</HelpPopover></>} rules={[{ required: true, type: 'number', min: 1, max: 336 }]}><InputNumber min={1} max={336} precision={0} /></Form.Item>
  </SettingsForm>
}

function MFAForm({ view }: { view: SettingsView }) {
  return <SettingsForm view={view} initial={{ mfa: view.config.mfa ?? { mode: 'off' as const, issuer: 'Access Gateway' } }} apply={value => ({ ...view.config, mfa: value.mfa })}>
    <Form.Item field="mfa.mode" label={<>MFA 策略<HelpPopover title="多因素认证">自愿绑定允许用户在账号设置中启用。强制策略下，未绑定用户需在登录时先绑定验证器。管理员指拥有角色管理权限的账户。已有绑定的用户即使关闭策略也仍需验证。</HelpPopover></>}><Select options={[{ value: 'off', label: '关闭自助绑定' }, { value: 'optional', label: '自愿绑定' }, { value: 'admin', label: '管理员必须绑定' }, { value: 'all', label: '所有用户必须绑定' }]} /></Form.Item>
    <Form.Item field="mfa.issuer" label={<>验证器显示名称<HelpPopover title="显示名称">在验证器应用中区分此平台的账户，不包含冒号。</HelpPopover></>} rules={required}><Input maxLength={64} /></Form.Item>
  </SettingsForm>
}

export function SystemSettings() {
  const query = useQuery({ queryKey, queryFn: ({ signal }) => request<SettingsView>('/admin/settings', { signal }), refetchOnWindowFocus: false })
  const view = query.data
  return <QueryState loading={query.isPending} error={query.error} retry={() => void query.refetch()}>{view && <>
    <div className="detail-actions"><Space><Tag>版本 {view.revision}</Tag>{view.updated_at && <span>{new Date(view.updated_at).toLocaleString()}</span>}</Space><Button icon={<IconRefresh />} aria-label="重新加载设置" title="重新加载设置" onClick={() => void query.refetch()} /></div>
    <RouteTabs items={[
      { key: 'platform', title: '基础设置', content: <PlatformForm key={view.revision} view={view} /> },
      { key: 'smtp', title: '邀请邮件', content: <SMTPForm key={view.revision} view={view} /> },
      { key: 'mfa', title: 'MFA', content: <MFAForm key={view.revision} view={view} /> },
      ...(['github', 'oidc', 'ldap', 'oauth2'] as const).map(provider => ({ key: provider, title: provider === 'github' ? 'GitHub' : provider === 'oauth2' ? 'OAuth2' : provider.toUpperCase(), content: <ProviderForm key={`${provider}-${view.revision}`} view={view} provider={provider} /> })),
      { key: 'feishu', title: '飞书集成', content: <FeishuForm key={view.revision} view={view} /> },
      { key: 'cloud', title: '云账号', content: <CloudAccounts /> },
    ]} />
  </>}</QueryState>
}
