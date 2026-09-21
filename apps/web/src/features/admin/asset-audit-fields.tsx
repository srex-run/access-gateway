import { Button, Form, Input, InputNumber, Select, Space, Switch } from '@arco-design/web-react'
import type { FormInstance } from '@arco-design/web-react'
import { IconDelete } from '@arco-design/web-react/icon'
import { HelpPopover } from '@/shared/ui/help-popover'
import { applyAuditCertificate, auditRule } from './asset-form-model'
import { AssetCertificateActions } from './asset-certificate-actions'
import { AssetTargetTrustFields } from './asset-target-trust-fields'
import type { AssetAuditRule, AssetFormValues } from './asset-form-model'
import type { AuditProtocol } from './audit-types'
import { assetProtocolOptions } from './fields'

export function AssetAuditFields({ form, field, index, assetID, fixedProtocol, onRemove, busy, onChange, onBusy }: {
  form: FormInstance<AssetFormValues>; field: string; index: number; fixedProtocol: boolean; onRemove?: () => void; busy: boolean
  assetID?: string; onChange: () => void; onBusy: (busy: boolean) => void
}) {
  const rules = () => (form.getFieldValue('rules') ?? []) as AssetAuditRule[]
  const setRule = (rule: AssetAuditRule) => { form.setFieldValue('rules', rules().map((current, position) => position === index ? rule : current)); onChange() }
  return <div className="asset-audit-rule">
    <div className="asset-audit-rule-header">
      <Form.Item field={`${field}.profile.port`} label={<>TCP 端口<HelpPopover title="TCP 端口">填写目标服务实际监听的端口，例如 MySQL 3306、SSH 22 或自定义 SSH 端口。</HelpPopover></>} rules={[{ required: true, type: 'number', min: 1, max: 65535 }]}><InputNumber aria-label="TCP 端口" min={1} max={65535} precision={0} /></Form.Item>
      {!fixedProtocol && <Form.Item field={`${field}.profile.protocol`} label="协议" rules={[{ required: true, message: '请选择协议' }]}><Select options={assetProtocolOptions} onChange={(value: AuditProtocol) => setRule(auditRule(value))} /></Form.Item>}
      <Form.Item field={`${field}.profile.audit_enabled`} triggerPropName="checked" label={<>操作审计<HelpPopover title="操作审计">开启后，由会话 agent 解析协议并记录操作，隧道和审计同步启动、结束。两段连接保持加密，数据库和 SSH 申请需填写目标账号；HTTP 应用身份标为未验证。关闭时只记录连接与流量。修改仅用于新申请的会话。</HelpPopover></>}><Switch aria-label="操作审计" disabled={busy} /></Form.Item>
      {onRemove && <Button size="small" disabled={busy} type="text" status="danger" icon={<IconDelete />} aria-label="移除此隧道端口" onClick={onRemove} />}
    </div>
    <Form.Item noStyle shouldUpdate>{() => {
      const rule = rules()[index]
      if (!rule?.profile.audit_enabled) return <div className="asset-audit-identity"><Space><span>原生加密隧道</span><HelpPopover title="原生加密隧道">客户端与目标服务直接协商 SSH 或 TLS，网关检查加密握手并记录连接。业务内容保持加密，无法由 agent 记录命令。</HelpPopover></Space></div>
      const profile = rule.profile
      const target = form.getFieldValue('target')
      return <>
        <AssetCertificateActions rule={rule} assetID={assetID} target={typeof target === 'string' ? target : ''} busy={busy} onBusy={onBusy}
          onGenerated={(purpose, bundle) => setRule(applyAuditCertificate(rules()[index]!, purpose, bundle))} />
        <details><summary>高级配置（手动调整）</summary>
        {profile.protocol === 'ssh' ? <>
        <Form.Item field={`${field}.target_host_keys`} label={<>资产 SSH 主机公钥<HelpPopover title="资产 SSH 主机公钥">一键生成全部会自动读取。也可从目标服务器 /etc/ssh/ssh_host_ed25519_key.pub 获取并手动调整，填写完整的 OpenSSH 公钥，每行一个。</HelpPopover></>} rules={[{ required: true, message: '请点击一键生成全部以读取目标 SSH 主机公钥，或在高级配置中填写' }]}><Input.TextArea aria-label="资产 SSH 主机公钥" autoSize={{ minRows: 2, maxRows: 5 }} maxLength={32768} /></Form.Item>
        <Form.Item field={`${field}.authorized_keys`} label={<>允许的客户端公钥<HelpPopover title="SSH 登录方式">留空使用目标账号密码登录。使用公钥登录时，填写允许的客户端公钥，并配置 agent 登录目标的私钥；客户端私钥不会被转发。SSH exec 记录脱敏命令和返回结果，交互终端记录服务端输出与回显，不记录隐藏密码输入。终端输出不等于实际执行证明。</HelpPopover></>}><Input.TextArea aria-label="允许的客户端公钥" autoSize={{ minRows: 2, maxRows: 5 }} maxLength={32768} /></Form.Item>
        {!!rule.authorized_keys.trim() && <Form.Item field={`${field}.target_ssh_key`} label="资产登录私钥" rules={[{ required: !rule.has_target_ssh_key, message: '公钥登录需要资产登录私钥' }]}><Input.TextArea aria-label="资产登录私钥" autoComplete="off" placeholder={rule.has_target_ssh_key ? '已配置，留空保留' : '无口令 OpenSSH 或 PEM 私钥'} autoSize={{ minRows: 3, maxRows: 6 }} maxLength={32768} /></Form.Item>}
      </> : <AssetTargetTrustFields rule={rule} field={field} busy={busy} onChange={setRule} />}
        </details>
      </>
    }}</Form.Item>
  </div>
}
