import { HelpPopover } from './help-popover'

export function ClientAccessHelp() {
  return <HelpPopover title="本地客户端访问部署要求">
    <p>开启后可在本机使用 SSH、数据库等客户端，通过 TCP 连接 access-gateway 分配的会话端口，站内访问仍然可用。</p>
    <p>配置的网关 IP 或域名必须从本地客户端所在网络可达。同一内网或通过 VPN 连接时可使用内网地址，跨公网访问时需要公网 IP。安全组和防火墙需放行 TCP 20000–20999（自定义范围以部署配置为准）。域名须直连网关，Cloudflare 普通代理无法转发这些 TCP 会话；网站 HTTPS 可继续使用代理。</p>
    <p>连接时会校验申请中填写的来源 IP。开关仅影响新申请和新建会话，已有会话请在会话管理中结束。</p>
  </HelpPopover>
}
