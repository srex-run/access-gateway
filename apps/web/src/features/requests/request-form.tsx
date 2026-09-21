import { Checkbox, Form, Input, Select } from '@arco-design/web-react'
import { ResourceForm } from '@/shared/ui/resource-form'
import { ErrorNotice, SectionTitle } from '@/shared/ui/page'
import { formatDuration } from '@/shared/lib/format'
import { HelpPopover } from '@/shared/ui/help-popover'
import { ClientAccessHelp } from '@/shared/ui/client-access-help'
import { useRequestForm } from './hooks'
import { DEMO_SESSION_TTL_SECONDS, requestDurationOptions, requestRequiresApproval } from './model'
import type { RequestFormValues } from './types'
import { WorkflowProgress } from '@/features/governance'

export function RequestForm() {
  const state = useRequestForm()
  return <ResourceForm<RequestFormValues> form={state.form} initialValues={{ region_id: state.region, asset_id: state.assetID, ttl_seconds: state.demoMode ? DEMO_SESSION_TTL_SECONDS : state.testAccess ? 600 : 3600, emergency: false }} onSubmit={values => state.create.mutate(values)} onChange={() => state.setDirty(true)} submitting={state.create.isPending} dirty={state.dirty} saved={state.create.isSuccess} backTo={state.create.data ? requestRequiresApproval(state.create.data.approval_mode) ? `/requests/${state.create.data.id}` : `/sessions/by-request/${state.create.data.id}` : '/requests'} error={state.create.error} submitText={state.demoMode ? '创建演示会话' : state.testAccess ? '创建测试会话' : '提交申请'}>
    <SectionTitle extra={<HelpPopover title={state.demoMode ? '演示自动审批' : '访问申请'}>{state.demoMode ? '演示模式下，访问申请自动审批并创建 5 分钟会话，到期自动断开并回收。请选择已配置访问端口的资产。' : '资产需配置 TCP 端口并关联审批流程，普通申请按所关联流程的节点依次审批。审批支持网页和飞书卡片；飞书需要启用通知、回调及账号绑定。'}</HelpPopover>}>访问目标{state.demoMode && ' · 演示自动审批'}</SectionTitle>
    {state.canTest && <Form.Item label={<>连接测试<HelpPopover title="管理员测试">跳过审批直接建立最长 10 分钟的测试会话，保留加密、来源 IP 校验、自动回收和审计。网关 Agent 随会话自动启动。</HelpPopover></>}><Checkbox checked={state.testAccess} onChange={state.changeTestAccess}>管理员测试（免审批）</Checkbox></Form.Item>}
    <Form.Item label={<>访问方式<HelpPopover title="站内访问">默认在网站内打开对应资产的客户端终端，支持 SSH、MySQL、PostgreSQL、Redis、MongoDB 和 HTTP。无需填写来源 IP 或直连公网会话端口；目标端口需开启操作审计并完成连接配置。登录时可填写密码和数据库名，资产、端口及账号以本次申请为准。</HelpPopover></>}>站内访问{state.accessOptions.data?.client_access_enabled && <><Checkbox checked={state.clientAccess} onChange={value => { state.setClientAccess(value); state.setDirty(true) }}>同时启用本地客户端访问</Checkbox><ClientAccessHelp /></>}</Form.Item>
    <ErrorNotice error={state.accessOptions.error ?? state.regions.error ?? state.assets.error ?? state.ports.error} retry={() => { void state.accessOptions.refetch(); void state.regions.refetch(); if (state.region) void state.assets.refetch(); if (state.asset) void state.ports.refetch() }} />
    <div className="form-grid">
      <Form.Item label="区域" field="region_id" rules={[{ required: true, message: '请选择区域' }]}><Select placeholder="选择区域" loading={state.regions.isPending} onChange={state.changeRegion} options={(state.regions.data ?? []).filter(value => value.status === 'enabled').map(value => ({ value: value.id, label: value.name }))} /></Form.Item>
      <Form.Item label="资产" field="asset_id" rules={[{ required: true, message: '请选择资产' }]}><Select showSearch placeholder="选择资产" disabled={!state.region} loading={!!state.region && state.assets.isPending} onChange={state.changeAsset} options={(state.assets.data ?? []).filter(value => value.status === 'enabled').map(value => ({ value: value.id, label: value.name }))} /></Form.Item>
      <Form.Item label={<>目标端口<HelpPopover title="目标端口">使用资产已配置的服务端口。只有一个端口时自动选中；配置多个端口时，选择本次访问的端口。</HelpPopover></>} field="target_port" rules={[{ required: true, message: '请选择端口' }]}><Select aria-label="目标端口" placeholder="选择端口" disabled={state.create.isPending || !state.asset || state.ports.data?.length === 1} loading={!!state.asset && state.ports.isPending} options={(state.ports.data ?? []).map(value => ({ value: value.port, label: `${value.port} / ${value.protocol.toUpperCase()}` }))} /></Form.Item>
      <Form.Item label={<>目标账号<HelpPopover title="目标账号"><p>填写登录资产时使用的用户名，例如 SSH 命令 ssh root@主机 中的 root，或数据库账号 admin。密码或私钥在连接时提供。</p><p>启用 SSH 或数据库操作审计时，申请需明确登录账号，连接时会校验实际账号与申请一致。HTTP 和未启用操作审计的原生隧道可留空。</p></HelpPopover></>} field="target_account" rules={state.targetAccountRequired ? [{ required: true, match: /\S/, message: '请填写目标账号（登录资产的用户名）' }] : []}><Input aria-label="目标账号" aria-required={state.targetAccountRequired} placeholder={state.targetAccountRequired ? '必填，登录用户名，如 root / admin / test' : '选填，登录用户名'} maxLength={128} autoComplete="off" onChange={state.markTargetAccountEdited} /></Form.Item>
      {state.clientAccess && state.accessOptions.data?.client_access_enabled && <Form.Item label={<>来源 IP<HelpPopover title="来源 IP">填写网关看到的客户端 IP。同机直连可填 127.0.0.1；公网网关填写本机出口 IP，不填 localhost 或目标资产 IP。</HelpPopover></>} field="source_ip" rules={[{ required: true, match: /\S/, message: '请输入来源 IP' }]}><Input aria-label="来源 IP" placeholder="例如 127.0.0.1 或 203.0.113.10" autoComplete="off" /></Form.Item>}
      <Form.Item label={<>会话有效期<HelpPopover title="会话有效期">{state.demoMode ? '演示会话固定为 5 分钟，从自动审批通过开始计时，等待启动和未连接的时间也包含在内，到期自动断开并回收。' : <>{state.testAccess ? '从创建测试会话开始计时，最长 10 分钟。' : '从最终审批通过开始计时，等待启动和未连接的时间也包含在内，最长 5 小时。'}当前资产最多可用 {formatDuration(state.maxTTL)}，到期自动断开并回收会话。</>}</HelpPopover></>} field="ttl_seconds" validateStatus={state.demoDurationError ? 'error' : undefined} help={state.demoDurationError} rules={[{ required: true, type: 'number', min: 1, max: state.maxTTL, message: state.demoDurationError }]}><Select aria-label="会话有效期" disabled={state.demoMode} options={(state.demoMode ? [DEMO_SESSION_TTL_SECONDS] : requestDurationOptions(state.maxTTL)).map(value => ({ value, label: formatDuration(value) }))} /></Form.Item>
    </div>
    {!state.demoMode && !state.testAccess && state.asset && <WorkflowProgress assetID={state.asset.id} />}
    <SectionTitle>申请信息</SectionTitle>
    {!state.demoMode && !state.testAccess && <Form.Item label={<>申请优先级<HelpPopover title="紧急访问">用于故障处理等需要优先审批的访问，请在申请原因中说明故障情况和影响范围。紧急申请会在审批待办中优先展示，启用飞书通知时也会突出紧急状态。仍须完成审批与审计。</HelpPopover></>} field="emergency" triggerPropName="checked"><Checkbox>紧急访问（优先审批）</Checkbox></Form.Item>}
    <Form.Item label="申请原因" field="reason" rules={[{ required: true, match: /\S/, message: '请输入申请原因' }]}><Input.TextArea autoSize={{ minRows: 3, maxRows: 6 }} maxLength={2000} showWordLimit /></Form.Item>
  </ResourceForm>
}
