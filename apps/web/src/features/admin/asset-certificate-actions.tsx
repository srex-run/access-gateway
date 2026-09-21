import { Button, Form, Input, Message, Tag } from '@arco-design/web-react'
import { useEffect, useRef, useState } from 'react'
import { PermissionGate } from '@/features/auth'
import { request } from '@/shared/api/client'
import { downloadText } from '@/shared/lib/download'
import { HelpPopover } from '@/shared/ui/help-popover'
import { ErrorNotice } from '@/shared/ui/page'
import type { AssetAuditRule, AssetCertificatePurpose } from './asset-form-model'
import type { CertificateBundle } from './audit-types'

export function AssetCertificateActions({ rule, assetID, target, busy, onBusy, onGenerated }: {
  rule: AssetAuditRule; assetID?: string; target: string; busy: boolean; onBusy: (busy: boolean) => void
  onGenerated: (purpose: AssetCertificatePurpose, bundle: CertificateBundle) => void
}) {
  const [pending, setPending] = useState<AssetCertificatePurpose | null>(null)
  const [error, setError] = useState<unknown>(null)
  const controller = useRef<AbortController | null>(null)
  useEffect(() => () => { controller.current?.abort(); onBusy(false) }, [onBusy])
  const generate = async () => {
    if (busy || controller.current) return
    const abort = new AbortController()
    controller.current = abort
    setPending('setup')
    setError(null)
    onBusy(true)
    try {
      // Keep returned private keys in this form only, outside the query cache.
      const bundle = await request<CertificateBundle>('/admin/assets/audit/certificates', {
        method: 'POST', validationMessages: true, signal: abort.signal,
        body: { purpose: 'setup', protocol: rule.profile.protocol, hosts: [], valid_days: 365,
          asset_id: assetID, target: target.trim() || undefined, target_port: rule.profile.port },
      })
      if (abort.signal.aborted) return
      onGenerated('setup', bundle)
      Message.success('网关与目标服务配置已全部就绪，保存资产后生效')
    } catch (failure) {
      if (!abort.signal.aborted) setError(failure)
    } finally {
      if (!abort.signal.aborted) { controller.current = null; setPending(null); onBusy(false) }
    }
  }
  const profile = rule.profile
  const isSSH = profile.protocol === 'ssh'
  const generated = !!(isSSH ? rule.ssh_host_key : rule.private_key)
  const saved = isSSH ? rule.has_ssh_host_key : rule.has_private_key
  const hasIdentity = isSSH ? !!profile.ssh_host_public_key : !!profile.certificate
  return <>
    <div className="table-actions">
      <PermissionGate permission="role:manage"><Button size="small" disabled={busy || (!assetID && !target.trim())} loading={pending === 'setup'} onClick={() => void generate()}>一键生成全部</Button></PermissionGate>
      <HelpPopover title="一键生成全部">
        <p>填写资产地址与端口后，一次生成网关证书或 SSH 主机密钥，并自动读取目标服务的 TLS 证书指纹或 SSH 主机公钥。配置会全部回填，保存资产后生效，无需手动填写 CA、证书域名或公钥。</p>
        <p>初次配置会以当前地址返回的目标身份建立信任，后续会话严格校验。目标更换证书或主机密钥后，可再次生成并保存。目标数据库需已启用 TLS，HTTP 服务需提供 HTTPS。</p>
        <p>此操作需要角色管理权限。SSH 登录时仍使用目标账号密码或自己的登录私钥。</p>
      </HelpPopover>
      {profile.protocol === 'ssh' ? <>
        {profile.ssh_host_public_key && <Button size="small" disabled={busy} onClick={() => downloadText(profile.ssh_host_public_key, `agent-${profile.port}.pub`)}>下载网关 SSH 公钥</Button>}
      </> : <>
        {profile.gateway_ca && <Button size="small" disabled={busy} onClick={() => downloadText(profile.gateway_ca, `agent-${profile.port}-ca.pem`)}>下载客户端信任证书</Button>}
      </>}
    </div>
    {hasIdentity && <section className="pem-input" aria-label="网关身份">
      <Form.Item label={<>网关身份 {generated ? <Tag size="small" color="orange">已生成，待保存</Tag> : saved ? <Tag size="small" color="green">已保存</Tag> : null}</>}>
        {isSSH ? <Input.TextArea aria-label="网关 SSH 公钥" value={profile.ssh_host_public_key} readOnly autoSize={{ minRows: 2, maxRows: 4 }} /> : <div className="form-grid">
          <Form.Item label="网关证书"><Input.TextArea aria-label="网关证书" value={profile.certificate} readOnly autoSize={{ minRows: 3, maxRows: 5 }} /></Form.Item>
          <Form.Item label="客户端信任 CA"><Input.TextArea aria-label="客户端信任 CA" value={profile.gateway_ca} readOnly autoSize={{ minRows: 3, maxRows: 5 }} /></Form.Item>
        </div>}
      </Form.Item>
    </section>}
    {(isSSH ? rule.target_host_keys.trim() : profile.target_certificate_sha256) && <Form.Item label="目标服务身份">
      <Input.TextArea aria-label="目标服务身份" value={isSSH ? rule.target_host_keys : profile.target_certificate_sha256} readOnly autoSize={{ minRows: 1, maxRows: 3 }} />
    </Form.Item>}
    <ErrorNotice error={error} />
  </>
}
