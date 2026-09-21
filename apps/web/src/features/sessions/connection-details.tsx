import { Alert, Button } from '@arco-design/web-react'
import { downloadText } from '@/shared/lib/download'
import { CopyableText } from '@/shared/ui/copyable-text'
import { HelpPopover } from '@/shared/ui/help-popover'
import { DetailList, SectionTitle } from '@/shared/ui/page'
import { connectionAddress, connectionCommand } from './connection-model'
import type { SessionRecordDetail } from './types'

export function ClientConnection({ value }: { value: SessionRecordDetail }) {
  const address = connectionAddress(value.session)
  const command = connectionCommand(value)
  const trust = value.session.audit_trust
  return <section className="session-client-connection" aria-label="客户端连接">
    <SectionTitle>客户端连接 <HelpPopover title="连接主机与端口">在本地终端或数据库工具中填写这里的主机和客户端连接端口。端口为每个会话单独分配，以当前页面为准；目标服务端口用于网关连接内网资产。只有网关运行在本机时，连接主机才是 127.0.0.1 或 localhost。会话结束后入口失效。</HelpPopover></SectionTitle>
    {address ? <DetailList items={[
      { label: '连接主机', value: <CopyableText value={address.host} /> },
      { label: '客户端连接端口', value: <CopyableText value={String(address.port)} /> },
      { label: '网关入口', value: <CopyableText value={address.endpoint} /> },
      { label: '目标服务端口', value: String(value.target_port || value.session.target_port || '-') },
    ]} /> : <Alert type={value.session.status === 'provisioning' ? 'info' : 'warning'} content={value.session.status === 'provisioning' ? '正在分配连接端口，请稍后刷新会话。' : '当前会话没有可用的连接入口。'} />}
    {address && trust && <div className="table-actions">
      {trust.ca_certificate && <Button size="small" onClick={() => downloadText(trust.ca_certificate!, `agent-${value.session.id}-ca.pem`)}>下载 agent CA</Button>}
      {trust.ssh_host_public_key && <Button size="small" onClick={() => downloadText(`[${address.host}]:${address.port} ${trust.ssh_host_public_key}`, `agent-${value.session.id}.known_hosts`)}>下载 SSH 主机校验文件</Button>}
      <HelpPopover title="客户端信任材料">将文件保存到执行连接命令的目录。文件只包含公开证书或主机公钥，用于验证本次会话 agent 的身份；agent 会校验资产身份。审计配置变更后请创建新会话，使用对应文件。</HelpPopover>
    </div>}
    {value.session.connection_mode === 'audit' && !trust && value.session.can_connect && <Alert type="warning" content="审计配置已变更或当前校验材料不可用，请重新申请会话以获取匹配的客户端信任材料。" />}
    {command && <div className="session-connect-command">
      <span>连接命令 <HelpPopover title="使用连接命令">在本地终端执行，使用目标服务自己的账号、密码或 SSH 密钥。将 YOUR_USERNAME、YOUR_DATABASE 替换为实际值，并按目标服务要求配置身份认证和可信 CA。MySQL 客户端和目标服务都必须启用 TLS；--ssl-mode=REQUIRED 不会替服务端开启 TLS。HTTPS 的目标域名、证书名称和 Host/SNI 应按目标服务配置。</HelpPopover></span>
      <CopyableText value={command} />
    </div>}
    {address && value.session.status !== 'running' && value.session.status !== 'provisioning' && <Alert type="info" content="当前会话已不可连接；重新申请后请使用新会话分配的端口。" />}
  </section>
}
