import type { SessionTraceEvent } from './types.ts'

export const traceStages = { request: '申请', approval: '审批', session: '会话', connection: '连接', operation: '操作' }

const eventLabels: Record<string, string> = {
  'request.created': '提交访问申请', 'access_request.cancelled': '取消申请', 'access_request.admin_test_started': '管理员测试访问',
  'approval.approved': '审批通过', 'approval.rejected': '审批拒绝',
  'session.provisioning': '准备会话', 'session.started': '会话入口已就绪', 'session.closed': '会话已关闭',
  'session.provision_failed': '会话创建失败', 'session.revoke_requested': '请求回收会话', 'session.revoke_failed': '会话回收失败',
  'session.force_close_requested': '请求强制回收', 'session.manual_intervention': '待人工处理',
  'session.cancelled_before_start': '启动前已取消', 'session.force_closed_before_start': '启动前强制关闭',
  connect_attempt: '发起连接', backend_connected: '目标 TCP 已连接', backend_failed: '目标连接失败',
  auth_rejected: '加密握手被拒绝', source_rejected: '来源 IP 被拒绝', capacity_rejected: '连接数已达上限', disconnected: '连接断开',
  exec: '命令请求', shell: '交互终端', terminal_output: '终端输出',
  client: '交互终端',
  client_version_probe: 'MySQL 客户端初始化（版本检查）',
  client_syntax_probe: 'MySQL 客户端初始化（语法探测）',
}
const reasonLabels: Record<string, string> = {
  application_identity_rejected: '目标账号认证失败', target_tls_verification_failed: '目标 TLS 证书校验失败',
  target_certificate_untrusted: '目标证书的签发机构不受信任', target_certificate_name_mismatch: '目标证书名称不匹配',
  target_certificate_expired_or_not_yet_valid: '目标证书已过期或尚未生效', target_certificate_pin_rejected: '目标证书指纹不匹配',
  terminal_client_unavailable: '原生客户端或隔离环境不可用', terminal_client_exited: '原生客户端异常退出',
  target_tls_failed: '目标 TLS 连接失败', source_ip_mismatch: '来源 IP 与申请不符',
  client_tls_handshake_failed: '客户端 TLS 握手失败', backend_unavailable: '目标服务无法连接',
  client_tls_ca_unreadable: '客户端无法读取会话 CA', client_tls_ca_invalid: '客户端会话 CA 格式无效',
  client_tls_identity_unreadable: '客户端无法读取会话证书或密钥', client_tls_identity_invalid: '客户端会话证书与密钥无效或不匹配',
  client_tls_material_invalid: '客户端 TLS 证书准备失败',
  native_handshake_timeout: '加密握手超时', native_handshake_closed: '加密握手提前关闭', native_encryption_required: '必须使用原生加密连接',
  mysql_client_tls_required: 'MySQL 客户端必须启用 TLS', mysql_target_tls_unavailable: '目标 MySQL 未启用 TLS',
  mysql_server_rejected_connection: '目标 MySQL 在发送初始握手前拒绝了连接', mysql_invalid_server_greeting: '目标端口未返回有效的 MySQL 握手',
  mysql_protocol41_required: '目标 MySQL 的握手协议版本过旧', mysql_invalid_ssl_request: 'MySQL 客户端的 TLS 协商请求无效',
  postgresql_client_tls_required: 'PostgreSQL 客户端必须启用 TLS', postgresql_target_tls_unavailable: '目标 PostgreSQL 未启用 TLS',
  postgresql_invalid_ssl_response: '目标 PostgreSQL TLS 协商响应无效',
  mysql_target_greeting_unavailable: '未收到 MySQL 初始握手', operation_audit_unavailable: '操作审计暂不可用',
  unsupported_application_protocol: '应用协议不受支持', application_proxy_failed: '应用代理连接失败',
  ssh_handshake_failed: 'SSH 握手或账号认证失败', ssh_session_failed: '创建 SSH 会话失败',
  ssh_pty_failed: '分配 SSH 交互终端失败', ssh_shell_failed: '启动 SSH shell 失败',
  ssh_terminal_ready_failed: '无法通知浏览器 SSH 已就绪', ssh_terminal_input_failed: 'SSH 输入或窗口尺寸转发失败',
  ssh_terminal_output_failed: 'SSH 输出转发失败', ssh_shell_wait_failed: 'SSH shell 异常结束',
  ssh_shell_exited: 'SSH shell 异常退出', ssh_connection_closed: 'SSH 连接提前关闭',
  user_closed: '用户结束会话', expired: '会话已到期', request_cancelled: '申请已取消',
  terminal_closed: '用户关闭终端', session_closed: '会话已结束', agent_stopped: '会话服务已停止',
}
export function traceTitle(event: Pick<SessionTraceEvent, 'stage' | 'event_type'>) {
  return eventLabels[event.event_type] ?? (event.stage === 'operation' ? event.event_type.toUpperCase() : event.event_type)
}
export function traceVisible(event: Pick<SessionTraceEvent, 'event_type'>) {
  return !['client_version_probe', 'client_syntax_probe'].includes(event.event_type)
}
export function traceContent(event: Pick<SessionTraceEvent, 'stage' | 'event_type' | 'protocol' | 'operation'>) {
  if (['client', 'shell'].includes(event.event_type)) return `${event.protocol?.toUpperCase() ?? ''} 交互终端`
  if (['client_version_probe', 'client_syntax_probe'].includes(event.event_type)) return traceTitle(event)
  return event.operation || traceTitle(event)
}
export function traceReason(reason: string) {
  return reasonLabels[reason] ? `${reasonLabels[reason]} (${reason})` : reason
}
export function traceResult(event: Pick<SessionTraceEvent, 'stage' | 'event_type' | 'result'>): { label: string; tone: 'success' | 'danger' | 'warning' | 'neutral' } {
  if (event.event_type === 'terminal_output') return { label: '已记录', tone: 'neutral' }
  if (['failed', 'failure', 'error', 'denied', 'rejected'].includes(event.result ?? '') || ['backend_failed', 'auth_rejected', 'source_rejected', 'capacity_rejected', 'session.provision_failed', 'session.revoke_failed'].includes(event.event_type)) return { label: '失败', tone: 'danger' }
  if (['client', 'shell', 'disconnected'].includes(event.event_type) && event.result === 'success') return { label: '已结束', tone: 'neutral' }
  if (event.event_type === 'backend_connected') return { label: 'TCP 已连接', tone: 'neutral' }
  if (['approved', 'success', 'ok', 'succeeded'].includes(event.result ?? '')) return { label: event.stage === 'approval' ? '已通过' : '成功', tone: 'success' }
  if (['started', 'pending', 'in_progress', 'queued'].includes(event.result ?? '')) return { label: '处理中', tone: 'warning' }
  if (event.result === 'unknown') return { label: '结果未知', tone: 'neutral' }
  return { label: event.result ?? '', tone: 'neutral' }
}
