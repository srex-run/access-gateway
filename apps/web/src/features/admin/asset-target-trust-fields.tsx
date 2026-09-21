import { Form, Input, Select } from '@arco-design/web-react'
import { useState } from 'react'
import { HelpPopover } from '@/shared/ui/help-popover'
import { changeTargetTrust, targetTrustMode } from './asset-form-model'
import type { AssetAuditRule, TargetTrustMode } from './asset-form-model'

export function AssetTargetTrustFields({ rule, field, busy, onChange }: {
  rule: AssetAuditRule; field: string; busy: boolean; onChange: (rule: AssetAuditRule) => void
}) {
  const mode = targetTrustMode(rule)
  const [nameExpanded, setNameExpanded] = useState(!!rule.profile.target_server_name)
  return <>
    <Form.Item label={<>目标服务身份校验<HelpPopover title="目标服务身份校验">
      <p>会话网关连接目标数据库或 HTTPS 服务时，需要验证目标服务的 TLS 证书。上方网关证书用于客户端连接网关，这里配置网关连接目标服务时的信任依据。</p>
      <p>一键生成全部会自动获取目标证书指纹。需要自定义时，目标使用公共 CA 证书可选择系统信任库；使用内部 CA 时填入签发目标证书的 CA；也可手动设置证书指纹。</p>
      <p>目标服务必须已启用 TLS。一键生成全部不会修改目标数据库的 TLS 配置。</p>
    </HelpPopover></>}>
      <Select aria-label="目标服务身份校验" value={mode} disabled={busy} onChange={(value: TargetTrustMode) => onChange(changeTargetTrust(rule, value))}
        options={[{ value: 'system', label: '系统信任库（公共 CA）' }, { value: 'ca', label: '自定义 CA' }, { value: 'pin', label: '证书指纹（SHA-256）' }]} />
    </Form.Item>
    {mode === 'ca' && <Form.Item field={`${field}.profile.target_ca`} label={<>目标服务 CA<HelpPopover title="目标服务 CA">填写签发目标数据库或 HTTPS 服务证书的 CA，PEM 格式。由目标服务管理员提供，例如 MySQL TLS 配置中的 CA 文件。</HelpPopover></>} rules={[{ required: true, message: '请填写目标服务 CA' }]}>
      <Input.TextArea aria-label="目标服务 CA" placeholder="-----BEGIN CERTIFICATE-----" autoSize={{ minRows: 3, maxRows: 6 }} maxLength={32768} />
    </Form.Item>}
    {mode === 'pin' && <Form.Item field={`${field}.profile.target_certificate_sha256`} label={<>目标证书 SHA-256<HelpPopover title="目标证书指纹">填写目标服务当前叶证书的 SHA-256，64 位十六进制。请通过可信渠道核对；目标更换证书后需更新指纹。</HelpPopover></>} rules={[{ required: true, match: /^[a-fA-F0-9]{64}$/, message: '请填写 64 位十六进制证书指纹' }]}>
      <Input aria-label="目标证书 SHA-256" maxLength={64} />
    </Form.Item>}
    <details open={nameExpanded} onToggle={event => setNameExpanded(event.currentTarget.open)}>
      <summary>证书域名（可选）</summary>
      <Form.Item field={`${field}.profile.target_server_name`} label={<>目标证书域名<HelpPopover title="目标证书域名">默认使用资产目标地址。通过 IP 连接而证书签给域名时，填写证书中的域名，用于 TLS SNI 和系统信任库／CA 模式的名称校验。</HelpPopover></>}>
        <Input aria-label="目标证书域名" placeholder="留空使用资产目标地址" maxLength={253} />
      </Form.Item>
    </details>
  </>
}
