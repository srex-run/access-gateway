import { Alert, Button, Input, Popconfirm, Select, Space } from '@arco-design/web-react'
import { IconRefresh } from '@arco-design/web-react/icon'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useSearchParams } from 'react-router-dom'
import { RequestStatusTag, requestApprovalLabel, requestDurationStartLabel, requestRequiresApproval } from '@/features/requests'
import { usePagination } from '@/shared/hooks/use-pagination'
import { formatDuration, formatTime } from '@/shared/lib/format'
import { CopyableText } from '@/shared/ui/copyable-text'
import { DataTable, TableDetail, TableText } from '@/shared/ui/data-table'
import type { DataColumn } from '@/shared/ui/data-table'
import { RouteTabs, TabToolbar } from '@/shared/ui/route-tabs'
import { IconButton } from '@/shared/ui/icon-button'
import { HelpPopover } from '@/shared/ui/help-popover'
import { DetailList, ErrorNotice, QueryState, SectionTitle } from '@/shared/ui/page'
import { StatusTag } from '@/shared/ui/status-tag'
import { recordQuery, traceQuery } from './api'
import { useSessionActions, useSessionList } from './hooks'
import { ClientConnection } from './connection-details'
import { WebTerminal } from './web-terminal'
import { TerminalRecordingButton } from './terminal-recording'
import { traceContent, traceReason, traceResult, traceStages, traceVisible } from './trace-model'
import type { Session, SessionRecord, SessionRecordDetail, SessionStatus, SessionTraceEvent } from './types'

const labels: Record<SessionStatus, string> = { provisioning: '准备中', running: '运行中', revoking: '回收中', expired: '已到期', closed: '已关闭', failed: '创建失败', revoke_failed: '回收失败', manual_intervention: '待人工处理' }
export function SessionStatusTag({ status }: { status: SessionStatus }) {
  return <StatusTag label={labels[status] ?? status} tone={status === 'running' ? 'success' : ['failed', 'revoke_failed', 'manual_intervention'].includes(status) ? 'danger' : ['provisioning', 'revoking'].includes(status) ? 'warning' : 'neutral'} />
}

export function SessionList() {
  const state = useSessionList()
  const columns: DataColumn<SessionRecord>[] = [
    { title: '会话编号', width: 170, render: (_, value) => <CopyableText value={value.id} abbreviated to={`/sessions/${value.id}`} /> },
    { title: '申请人', dataIndex: 'applicant_name', width: 140 },
    { title: '访问资产', dataIndex: 'asset_name', width: 200 },
    { title: '申请账号', dataIndex: 'target_account', width: 140 },
    { title: '目标端口', dataIndex: 'target_port', width: 100 },
    { title: '会话状态', width: 120, render: (_, value) => <SessionStatusTag status={value.status} /> },
    { title: '创建时间', width: 180, render: (_, value) => formatTime(value.created_at) },
    { title: '到期时间', width: 180, render: (_, value) => formatTime(value.expires_at) },
  ]
  return <>
    <TabToolbar title="会话记录">
      <Input.Search key={state.search} aria-label="搜索会话" className="filter-search" placeholder="申请人、资产、账号或编号" defaultValue={state.search} allowClear onSearch={value => state.filter('search', value.trim())} onClear={() => state.filter('search', '')} />
      <Select aria-label="会话状态" className="filter-select" placeholder="全部状态" allowClear value={state.status || undefined} onChange={value => state.filter('status', value ?? '')} options={Object.entries(labels).map(([value, label]) => ({ value, label }))} />
      <IconButton label="刷新会话" icon={<IconRefresh />} loading={state.query.isFetching} onClick={state.retry} />
    </TabToolbar>
    <DataTable columns={columns} data={state.data} loading={state.query.isPending} error={state.query.error} onRetry={state.retry} empty="暂无符合条件的会话记录" pagination={{ ...state.pagination, count: state.data.length, hasNext: (state.query.data?.length ?? 0) > state.pagination.pageSize, onChange: state.pagination.change }} />
  </>
}

function TraceContent({ event, sessionId }: { event: SessionTraceEvent; sessionId: string }) {
  const content = traceContent(event)
  return <div className="session-trace-content"><TableDetail title="轨迹详情" summary={content}>
    <pre className="session-trace-operation">{content}</pre>
    <DetailList items={[
      { label: '记录编号', value: <CopyableText value={event.id} /> },
      ...(event.connection_id ? [{ label: '连接编号', value: <CopyableText value={event.connection_id} /> }] : []),
      ...(event.actual_account ? [{ label: '目标账号', value: `${event.actual_account} · ${event.account_verified ? '已验证' : '未验证'}` }] : []),
      ...(event.protocol ? [{ label: '协议', value: event.protocol }] : []),
      ...(event.source_ip ? [{ label: '客户端来源', value: event.source_ip }] : []),
      ...(event.backend_source_ip ? [{ label: '目标侧来源', value: sourceAddress(event.backend_source_ip, event.backend_source_port) }] : []),
      ...(event.object_name && event.object_name !== content ? [{ label: '对象', value: event.object_name }] : []),
    ]} />
  </TableDetail>{event.terminal_channel_id && <TerminalRecordingButton sessionId={sessionId} channelId={event.terminal_channel_id} cols={event.terminal_cols} />}</div>
}

function SessionTrace({ id, mode }: { id: string; mode: Session['connection_mode'] }) {
  const client = useQueryClient()
  const pagination = usePagination('trace')
  const [params, setParams] = useSearchParams()
  const rawStage = params.get('stage') ?? ''
  const stage = Object.hasOwn(traceStages, rawStage) ? rawStage : ''
  const query = useQuery(traceQuery(id, pagination.page, pagination.pageSize, stage))
  const values = (query.data ?? []).slice(0, pagination.pageSize).filter(traceVisible)
  const columns: DataColumn<SessionTraceEvent>[] = [
    { title: '时间', width: 170, render: (_, event) => formatTime(event.occurred_at) },
    { title: '阶段', width: 70, render: (_, event) => traceStages[event.stage] },
    { title: '事件 / 命令', width: 360, render: (_, event) => <TraceContent event={event} sessionId={id} /> },
    { title: '操作人', width: 120, render: (_, event) => event.actor_name === 'system' ? '系统' : event.actor_name === 'user' ? '用户' : event.actor_name || '-' },
    { title: '说明', width: 260, render: (_, event) => <span className={traceResult(event).tone === 'danger' ? 'session-trace-error' : undefined}><TableText>{event.reason ? traceReason(event.reason) : null}</TableText></span> },
    { title: '耗时', width: 90, render: (_, event) => event.duration_ms == null ? '-' : `${event.duration_ms} ms` },
    { title: '结果', width: 110, fixed: 'right', render: (_, event) => { const result = traceResult(event); return result.label ? <StatusTag {...result} /> : '-' } },
  ]
  return <>
    <TabToolbar title="访问轨迹">
      <Select size="small" className="trace-stage-select" aria-label="轨迹阶段" value={stage} onChange={value => setParams(previous => {
        const next = new URLSearchParams(previous)
        if (value) next.set('stage', value); else next.delete('stage')
        next.delete('trace_page')
        return next
      })} options={[{ value: '', label: '全部阶段' }, ...Object.entries(traceStages).map(([value, label]) => ({ value, label }))]} />
      <HelpPopover title="访问轨迹">按时间倒序展示，每条事件一行。账号、协议和来源汇总在上方；耗时属于当前事件。点击事件或命令可查看完整内容及关联编号。</HelpPopover>
      <IconButton label="刷新轨迹" icon={<IconRefresh />} loading={query.isFetching} onClick={() => void client.invalidateQueries({ queryKey: ['sessions'] })} />
    </TabToolbar>
    <section className="session-trace" aria-label="访问轨迹记录">
      <DataTable columns={columns} data={values} loading={query.isPending} error={query.error} onRetry={() => void query.refetch()}
        empty={stage === 'operation' && mode !== 'audit' ? '暂无关联操作证据' : '暂无此阶段的记录'}
        pagination={{ ...pagination, count: values.length, hasNext: (query.data?.length ?? 0) > pagination.pageSize, onChange: pagination.change }} />
    </section>
  </>
}

function EvidenceValues({ title, values }: { title: string; values: string[] }) {
  const unique = [...new Set(values)]
  if (unique.length < 2) return <TableText>{unique[0]}</TableText>
  return <TableDetail title={title} summary={`${unique[0]} +${unique.length - 1}`}><ul className="session-evidence-values">{unique.map(value => <li key={value}>{value}</li>)}</ul></TableDetail>
}

function sourceAddress(ip: string, port?: number) {
  return port ? `${ip.includes(':') ? `[${ip}]` : ip}:${port}` : ip
}

function RecordSummary({ value }: { value: SessionRecordDetail }) {
  const { evidence } = value
  const accounts = evidence.context?.accounts ?? evidence.verified_accounts.map(name => ({ name, verified: true }))
  const accountLabels = accounts.map(account => `${account.name} · ${account.verified ? '已验证' : '未验证'}`)
  const columns: DataColumn<SessionRecordDetail>[] = [
    { title: <span>目标账号 <HelpPopover title="目标账号上下文">申请中的目标账号为可选上下文。原生加密隧道由访问者和目标服务完成认证，网关不会验证或代填账号；历史审计会话可能显示实际认证证据。</HelpPopover></span>, width: 220, render: () => <EvidenceValues title="目标账号" values={accountLabels.length ? accountLabels : [value.session.connection_mode === 'native' ? '未由网关验证' : '暂无已验证账号']} /> },
    { title: '协议', width: 110, render: () => <EvidenceValues title="协议" values={evidence.context?.protocols.length ? evidence.context.protocols : value.session.audit_policy?.protocol ? [value.session.audit_policy.protocol] : []} /> },
    { title: '目标侧来源', width: 240, render: () => <EvidenceValues title="目标侧来源" values={(evidence.context?.backend_sources ?? []).map(source => sourceAddress(source.ip, source.port))} /> },
    { title: '客户端来源', width: 160, render: () => <EvidenceValues title="客户端来源" values={evidence.context?.client_sources ?? []} /> },
    { title: '连接 / 失败', width: 120, render: () => <span className={evidence.failed_connections ? 'session-trace-error' : undefined}>{evidence.connection_count} / {evidence.failed_connections}</span> },
    { title: '操作', width: 80, render: () => evidence.operation_count },
  ]
  return <section className="session-record-context" aria-label="会话摘要"><DataTable columns={columns} data={[value]} /></section>
}

function RequestEvidence({ value }: { value: SessionRecordDetail }) {
  const request = value.request
  return <>
    <DetailList items={[
      { label: '申请人', value: <TableDetail title="申请人" summary={value.applicant_name}><CopyableText value={value.applicant_id} /></TableDetail> }, { label: '申请状态', value: <RequestStatusTag status={request.status} /> },
      { label: '申请 ID', value: <CopyableText value={value.request_id} /> },
      { label: '申请账号 / 端口', value: `${value.target_account || '-'} / ${value.target_port}` },
      { label: '申请原因', value: request.reason },
      ...(request.ticket_no?.trim() ? [{ label: '关联工单', value: request.ticket_no }] : []),
      { label: '紧急申请', value: request.emergency ? '是' : '否' },
      { label: '审批方式', value: requestApprovalLabel(request.approval_mode) },
      { label: '提交时间', value: formatTime(request.created_at) }, { label: '会话有效期', value: `${formatDuration(request.ttl_seconds)}（${requestDurationStartLabel(request.approval_mode)}开始计时）` },
    ]} />
    <SectionTitle>{value.workflow.snapshot?.name || '审批记录'}</SectionTitle>
    {!requestRequiresApproval(request.approval_mode) ? <p className="muted">{request.approval_mode === 'demo' ? '演示模式已自动审批，会话有效期为 5 分钟。' : '管理员测试访问，免审批'}</p> : <DataTable data={value.workflow.approvals} columns={[
      { title: '审批节点', width: 180, render: (_, item) => `${item.level}. ${item.step_name || '审批'}` },
      { title: '审批人', dataIndex: 'name', width: 160 },
      { title: '结果', width: 120, render: (_, item) => item.decision === 'approved' ? <StatusTag label="已通过" tone="success" /> : item.decision === 'rejected' ? <StatusTag label="已拒绝" tone="danger" /> : '未参与决定' },
      { title: '审批意见', dataIndex: 'comment', width: 260 },
      { title: '处理时间', width: 180, render: (_, item) => formatTime(item.decided_at) },
    ]} />}
  </>
}

function ConnectionDetails({ value }: { value: Session }) {
  return <DetailList items={[
    { label: '连接方式', value: value.connection_mode === 'audit' ? '操作审计代理' : value.connection_mode === 'native' ? '原生加密通道' : value.connection_mode === 'direct' ? '旧版 TCP 直连' : '旧版隧道' },
    ...(value.audit_policy?.profile ? [{ label: '审计配置', value: value.audit_policy.profile }] : []),
    { label: '访问入口', value: value.source_ip ? '站内 / 客户端（按协议支持）' : '站内终端' },
    ...(value.source_ip ? [{ label: '客户端来源 IP', value: <CopyableText value={value.source_ip} /> }] : []),
    { label: '加密策略', value: value.connection_mode === 'audit' ? '两段独立 SSH / TLS 1.2+' : value.connection_mode === 'native' ? '端到端 SSH / TLS 1.2+（必需）' : '旧版策略' },
    { label: '开始时间', value: formatTime(value.started_at) }, { label: '到期时间', value: formatTime(value.expires_at) }, { label: '关闭时间', value: formatTime(value.closed_at) },
  ]} />
}

export function SessionDetails({ id, byRequest = false }: { id: string; byRequest?: boolean }) {
  const client = useQueryClient()
  const query = useQuery(recordQuery(id, byRequest))
  const { close } = useSessionActions()
  const value = query.data
  return <QueryState loading={query.isPending} error={query.error} retry={() => void query.refetch()}>{value && <div className="session-details">
    <div className="detail-actions"><div className="session-record-heading"><strong>{value.asset_name}</strong><SessionStatusTag status={value.session.status} /><CopyableText value={value.id} abbreviated /></div><Space wrap>
      <Link to="/approvals?tab=sessions"><Button>返回会话记录</Button></Link>
      <IconButton label="刷新会话详情" icon={<IconRefresh />} loading={query.isFetching} onClick={() => void client.invalidateQueries({ queryKey: ['sessions'] })} />
      {value.can_close && <Popconfirm title="结束会话并回收访问权限？" onOk={() => close.mutateAsync(value.id).then(() => undefined)}><Button status="danger" loading={close.isPending}>结束会话</Button></Popconfirm>}
    </Space></div>
    <ErrorNotice error={close.error} />
    {value.session.failure_reason && <Alert type="error" content={traceReason(value.session.failure_reason)} />}
    {value.session.status === 'running' && ['direct', 'tunnel'].includes(value.session.connection_mode) && <Alert type="warning" content="旧版会话；结束并重新申请后使用当前连接策略。" />}
    {value.session.status === 'running' && value.session.can_web_connect && <WebTerminal value={value} />}
    {(value.request.source_ip || value.session.source_ip) && <ClientConnection value={value} />}
    <RecordSummary value={value} />
    <RouteTabs param="detail" items={[
      { key: 'trace', title: '访问轨迹', content: <SessionTrace id={value.id} mode={value.session.connection_mode} /> },
      { key: 'request', title: '申请与审批', content: <RequestEvidence value={value} /> },
      { key: 'connection', title: '连接配置', content: <ConnectionDetails value={value.session} /> },
    ]} />
  </div>}</QueryState>
}
