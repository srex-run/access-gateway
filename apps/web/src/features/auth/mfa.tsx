import { Alert, Button, Checkbox, Form, Input, Message, Popconfirm, Space, Tag } from '@arco-design/web-react'
import { IconCopy } from '@arco-design/web-react/icon'
import { useMutation, useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { request } from '@/shared/api/client'
import { DetailList, ErrorNotice, QueryState, SectionTitle } from '@/shared/ui/page'
import { HelpPopover } from '@/shared/ui/help-popover'
import { IconButton } from '@/shared/ui/icon-button'
import { QRCodeSVG } from '@/shared/ui/qr-code'

interface PendingMFA { stage: 'mfa-enroll' | 'mfa-verify'; expires_at: string }
interface Enrollment { secret: string; uri: string }
interface Status { bound: boolean; recovery_codes_left: number; can_enroll: boolean; can_unbind: boolean }
interface RecoveryCodes { codes: string[] }

async function copyEnrollmentSecret(secret: string) {
  try { await navigator.clipboard.writeText(secret); Message.success('密钥已复制') }
  catch { Message.error('复制失败，请手动选择并复制密钥') }
}

function RecoveryCodeDisplay({ codes, onDone }: { codes: string[]; onDone: () => void }) {
  const [saved, setSaved] = useState(false)
  const download = () => {
    const url = URL.createObjectURL(new Blob([`Access Gateway MFA 恢复码\n每个恢复码只能使用一次，请妥善离线保存。\n\n${codes.join('\n')}\n`], { type: 'text/plain;charset=utf-8' }))
    const link = document.createElement('a')
    link.href = url; link.download = 'access-gateway-recovery-codes.txt'; link.click()
    URL.revokeObjectURL(url)
  }
  return <section className="mfa-recovery">
    <Alert type="success" content="恢复码已生成，仅展示这一次。每个恢复码可在无法使用验证器时替代验证码使用一次。" />
    <div className="mfa-recovery-codes">{codes.map(code => <code key={code}>{code}</code>)}</div>
    <Button onClick={download}>下载恢复码</Button>
    <Checkbox checked={saved} onChange={setSaved}>我已妥善保存恢复码</Checkbox>
    <Button type="primary" disabled={!saved} onClick={onDone}>完成</Button>
  </section>
}

export function MFAChallengePage() {
  const navigate = useNavigate()
  const pending = useQuery({ queryKey: ['mfa-challenge'], queryFn: () => request<PendingMFA>('/auth/mfa'), retry: false, refetchOnWindowFocus: false, staleTime: Infinity, gcTime: 0 })
  const [enrollment, setEnrollment] = useState<Enrollment>()
  const [codes, setCodes] = useState<string[]>()
  const enroll = useMutation({ gcTime: 0, mutationFn: () => request<Enrollment>('/auth/mfa/enroll', { method: 'POST', body: {}, validationMessages: true }), onSuccess: value => { setEnrollment(value); enroll.reset() } })
  const confirm = useMutation({
    gcTime: 0,
    mutationFn: (value: { code: string }) => request<RecoveryCodes>(pending.data?.stage === 'mfa-enroll' ? '/auth/mfa/confirm' : '/auth/mfa/verify', { method: 'POST', body: value, validationMessages: true }),
    onSuccess: value => {
      setEnrollment(undefined)
      if (value.codes?.length) { setCodes(value.codes); confirm.reset() }
      else window.location.assign('/catalog')
    },
  })
  return <main className="login-page"><div className="login-brand"><img src="/favicon.svg" alt="" width={44} height={44} /><h1>Access Gateway</h1></div>
    <div className="login-content mfa-content"><h2>{codes ? '保存恢复码' : pending.data?.stage === 'mfa-enroll' ? '绑定身份验证器' : '二次验证'}</h2>
      {codes ? <RecoveryCodeDisplay codes={codes} onDone={() => { setCodes(undefined); window.location.assign('/catalog') }} /> : <QueryState loading={pending.isPending} error={pending.error}>
        {pending.data && <>
          {pending.data.stage === 'mfa-enroll' && <>
            <p>使用 Google Authenticator、Microsoft Authenticator 等验证器扫码，再输入生成的 6 位验证码。</p>
            {enrollment ? <div className="mfa-enrollment"><QRCodeSVG value={enrollment.uri} size={192} level="M" marginSize={2} />
              <div className="mfa-manual-binding">
                <div className="mfa-manual-label"><label htmlFor="mfa-enrollment-secret">手动绑定密钥</label><HelpPopover title="手动绑定">无法扫码时，可在验证器中选择手动输入密钥，类型为“基于时间”。请勿向他人提供此密钥。</HelpPopover></div>
                <Input id="mfa-enrollment-secret" value={enrollment.secret} readOnly aria-label="手动绑定密钥" suffix={<IconButton label="复制手动绑定密钥" icon={<IconCopy />} onClick={() => void copyEnrollmentSecret(enrollment.secret)} />} />
              </div>
            </div> : <Button type="primary" long loading={enroll.isPending} onClick={() => enroll.mutate()}>生成绑定二维码</Button>}
            <ErrorNotice error={enroll.error} />
          </>}
          {(pending.data.stage === 'mfa-verify' || enrollment) && <Form layout="vertical" disabled={confirm.isPending} onSubmit={value => confirm.mutate(value)}>
            <Form.Item label={pending.data.stage === 'mfa-enroll' ? '验证码' : '验证码或恢复码'} field="code" rules={[{ required: true, match: /\S/, message: '请输入验证码' }]}><Input autoComplete="one-time-code" aria-label={pending.data.stage === 'mfa-enroll' ? '验证码' : '验证码或恢复码'} maxLength={64} /></Form.Item>
            <ErrorNotice error={confirm.error} />
            <Button type="primary" htmlType="submit" long loading={confirm.isPending}>{pending.data.stage === 'mfa-enroll' ? '确认绑定' : '验证并登录'}</Button>
          </Form>}
        </>}
      </QueryState>}
      {!codes && <Button className="mfa-back" type="primary" long onClick={() => navigate('/login')}>返回登录</Button>}
    </div>
  </main>
}

export function MFASettings() {
  const [form] = Form.useForm<{ code: string }>()
  const status = useQuery({ queryKey: ['account-mfa'], queryFn: ({ signal }) => request<Status>('/auth/account/mfa', { signal }) })
  const [codes, setCodes] = useState<string[]>()
  const enroll = useMutation({ mutationFn: () => request('/auth/account/mfa/enroll', { method: 'POST', body: {}, validationMessages: true }), onSuccess: () => window.location.assign('/mfa') })
  const update = useMutation({
    gcTime: 0,
    mutationFn: async (remove: boolean) => {
      const values = await form.validate()
      const value = await request<RecoveryCodes>(remove ? '/auth/account/mfa/unbind' : '/auth/account/mfa/recovery-codes', { method: 'POST', body: { code: values.code }, validationMessages: true })
      if (remove) window.location.assign('/login')
      return value
    },
    onSuccess: value => { if (value?.codes) setCodes(value.codes); form.resetFields(); update.reset(); void status.refetch() },
  })
  return <><SectionTitle extra={<HelpPopover title="多因素认证">密码验证后再使用手机验证器确认身份。恢复码可在手机丢失时使用，每个只能用一次。更新恢复码或解绑时需要再次验证。</HelpPopover>}>多因素认证（MFA）</SectionTitle>
    {codes ? <RecoveryCodeDisplay codes={codes} onDone={() => setCodes(undefined)} /> : <QueryState loading={status.isPending} error={status.error} retry={() => void status.refetch()}>
      {status.data && <>
        <DetailList items={[{ label: '身份验证器', value: <Tag color={status.data.bound ? 'green' : 'gray'}>{status.data.bound ? '已绑定' : '未绑定'}</Tag> }, ...(status.data.bound ? [{ label: '剩余恢复码', value: `${status.data.recovery_codes_left} 个` }] : [])]} />
        {status.data.bound ? <Form form={form} layout="vertical" onSubmit={() => update.mutate(false)} disabled={update.isPending}>
          <Form.Item label={<>验证码或恢复码<HelpPopover title="验证当前身份">填写当前验证码或一个未使用的恢复码。重新生成后旧恢复码全部失效；解绑会退出当前登录。被平台策略要求启用 MFA 的账户不能自行解绑。</HelpPopover></>} field="code" rules={[{ required: true, match: /\S/, message: '请输入验证码或恢复码' }]}><Input autoComplete="one-time-code" maxLength={64} /></Form.Item>
          <Space><Button htmlType="submit" loading={update.isPending}>重新生成恢复码</Button>
            <Popconfirm title="解绑验证器并退出登录？" onOk={() => update.mutateAsync(true).then(() => undefined)}><Button status="danger" disabled={!status.data.can_unbind}>解除绑定</Button></Popconfirm>
          </Space>
        </Form> : <Space><Button type="primary" disabled={!status.data.can_enroll} loading={enroll.isPending} onClick={() => enroll.mutate()}>绑定身份验证器</Button>{!status.data.can_enroll && <HelpPopover title="功能未启用">管理员可在系统设置的 MFA 页面启用自愿绑定或强制绑定策略。</HelpPopover>}</Space>}
        <ErrorNotice error={enroll.error ?? update.error} />
      </>}
    </QueryState>}
  </>
}

export function UserMFAStatus({ userID, canReset }: { userID: string; canReset: boolean }) {
  const status = useQuery({ queryKey: ['user-mfa', userID], queryFn: ({ signal }) => request<{ bound: boolean }>(`/admin/users/${userID}/mfa`, { signal }) })
  const reset = useMutation({ mutationFn: () => request(`/admin/users/${userID}/mfa`, { method: 'DELETE', validationMessages: true }), onSuccess: () => status.refetch() })
  return <><SectionTitle>多因素认证</SectionTitle><QueryState loading={status.isPending} error={status.error} retry={() => void status.refetch()}>
    <Space><Tag color={status.data?.bound ? 'green' : 'gray'}>{status.data?.bound ? '已绑定' : '未绑定'}</Tag>
      {canReset && <Popconfirm title="重置此用户的 MFA？" content="验证器和恢复码将失效，已有登录会话会退出；用户下次登录需按平台策略重新绑定。" onOk={() => reset.mutateAsync().then(() => undefined)}><Button status="danger" disabled={!status.data?.bound} loading={reset.isPending}>重置 MFA</Button></Popconfirm>}
    </Space><ErrorNotice error={reset.error} />
  </QueryState></>
}
