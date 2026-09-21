import { Button, Form, Input, InputNumber, Radio, Select, Tag, Tooltip } from '@arco-design/web-react'
import type { DataColumn } from '@/shared/ui/data-table'
import { IconCloud, IconRefresh } from '@arco-design/web-react/icon'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { useIdentity } from '@/features/auth'
import { catalogKeys } from '@/features/catalog'
import { useTableView } from '@/shared/hooks/use-table-view'
import { DataTable, TableText } from '@/shared/ui/data-table'
import { TabToolbar } from '@/shared/ui/route-tabs'
import { EmptyResult, QueryState, SectionTitle } from '@/shared/ui/page'
import { ResourceForm } from '@/shared/ui/resource-form'
import { queryPath } from '@/shared/lib/navigation'
import { formatTime } from '@/shared/lib/format'
import { cloudAccountQuery, cloudJobQuery, cloudJobsKey, queueCloudSync } from './cloud-api'
import type { CloudSyncInput, CloudSyncJob } from './cloud-api'
import { requiredRules, uuidRules } from './fields'

interface SyncForm extends Omit<CloudSyncInput, 'instance_ids' | 'ports'> { account_id: string; mode: 'region' | 'instances'; instance_ids_text: string; ports_text: string }
const tokens = (value: string) => value.trim().split(/[\s,，]+/).filter(Boolean)
const regionOptions: Record<string, string[]> = {
  aliyun: ['cn-hangzhou', 'cn-shanghai', 'cn-beijing', 'cn-shenzhen', 'cn-chengdu', 'cn-hongkong', 'ap-southeast-1'],
  aws: ['us-east-1', 'us-west-2', 'ap-east-1', 'ap-southeast-1', 'ap-northeast-1', 'eu-west-1', 'cn-north-1', 'cn-northwest-1'],
  huaweicloud: ['cn-north-4', 'cn-north-1', 'cn-east-3', 'cn-south-1', 'cn-southwest-2', 'ap-southeast-1', 'ap-southeast-3'],
}

function CloudSyncEditor({ accountID, previous, backTo }: { accountID?: string; previous?: CloudSyncJob; backTo: string }) {
  const [form] = Form.useForm<SyncForm>()
  const [mode, setMode] = useState<'region' | 'instances'>(previous && !previous.input.instance_ids.length ? 'region' : 'instances')
  const [selectedAccount, setSelectedAccount] = useState(accountID ?? previous?.account_id ?? '')
  const [dirty, setDirty] = useState(false)
  const identity = useIdentity()
  const accounts = useQuery(cloudAccountQuery)
  const provider = accounts.data?.find(value => value.id === selectedAccount)?.provider ?? ''
  const client = useQueryClient()
  const mutation = useMutation({ mutationFn: (value: SyncForm) => queueCloudSync(value.account_id, {
    cloud_region: value.cloud_region.trim(),
    instance_ids: mode === 'instances' ? tokens(value.instance_ids_text) : [], ports: tokens(value.ports_text).map(Number),
    approver_id: value.approver_id.trim(), risk_level: value.risk_level, max_ttl_seconds: value.max_ttl_seconds,
  }), onSuccess: async () => { setDirty(false); await client.invalidateQueries({ queryKey: cloudJobsKey }) } })
  return <ResourceForm form={form} dirty={dirty} onChange={() => { setDirty(true); mutation.reset() }} submitting={mutation.isPending} saved={mutation.isSuccess}
    error={accounts.error || mutation.error} backTo={backTo} submitText="开始同步" onSubmit={value => mutation.mutate(value)} initialValues={{
      ...previous?.input, account_id: selectedAccount || undefined, mode, cloud_region: previous?.input.cloud_region ?? '',
      instance_ids_text: previous?.input.instance_ids.join('\n') ?? '', ports_text: previous?.input.ports.join(', ') ?? '22',
      approver_id: previous?.input.approver_id ?? identity.data?.user_id, risk_level: previous?.input.risk_level ?? 'normal', max_ttl_seconds: previous?.input.max_ttl_seconds ?? 3600,
    }}>
      <div className="form-grid">
        <Form.Item label="云账号" field="account_id" rules={requiredRules} extra={!accounts.isPending && !accounts.data?.length && <Link to="/admin/assets?tab=cloud">添加云账号</Link>}><Select loading={accounts.isPending} showSearch options={(accounts.data ?? []).map(value => ({ value: value.id, label: value.name, disabled: !value.enabled }))} onChange={value => { setSelectedAccount(value); form.setFieldsValue({ cloud_region: '', instance_ids_text: '' }) }} /></Form.Item>
        <Form.Item label="云 Region" field="cloud_region" rules={[...requiredRules, { match: /^[a-z][a-z0-9-]{1,62}[a-z0-9]$/, message: '请输入 Region 编码' }]}><Select showSearch allowCreate allowClear options={regionOptions[provider] ?? []} placeholder="cn-hangzhou" /></Form.Item>
      </div>
      <Form.Item label="同步范围" field="mode"><Radio.Group type="button" onChange={setMode} options={[{ value: 'instances', label: '指定 ECS 实例' }, { value: 'region', label: '整个云 Region' }]} /></Form.Item>
      {mode === 'instances' && <Form.Item label="实例 ID" field="instance_ids_text" rules={[...requiredRules, { validator: (value: string | undefined, callback) => {
        const ids = tokens(value ?? '')
        if (!ids.length || ids.length > 100 || ids.some(id => !/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$/.test(id))) return callback('请填写 1 到 100 个有效实例 ID')
        callback()
      } }]}><Input.TextArea autoSize={{ minRows: 3, maxRows: 8 }} placeholder="i-xxxxxxxx" /></Form.Item>}
      <SectionTitle>新资产配置</SectionTitle>
      <Form.Item label="TCP 端口" field="ports_text" rules={[...requiredRules, { validator: (value: string | undefined, callback) => {
        const ports = tokens(value ?? '')
        if (!ports.length || ports.length > 100 || ports.some(port => !/^\d+$/.test(port) || Number(port) < 1 || Number(port) > 65535)) return callback('请填写有效的 TCP 端口')
        callback()
      } }]}><Input placeholder="22, 3306" /></Form.Item>
      <Form.Item label="审批人 ID" field="approver_id" rules={uuidRules}><Input /></Form.Item>
      <div className="form-grid"><Form.Item label="风险等级" field="risk_level" rules={requiredRules}><Select options={[{ value: 'normal', label: '普通' }, { value: 'sensitive', label: '敏感' }, { value: 'critical', label: '关键' }]} /></Form.Item><Form.Item label="最长访问时限（秒）" field="max_ttl_seconds" rules={[{ required: true, type: 'number', min: 1, max: 18000 }]}><InputNumber min={1} max={18000} precision={0} /></Form.Item></div>
  </ResourceForm>
}

export function CloudSyncForm() {
  const [params] = useSearchParams()
  const jobID = params.get('job') ?? ''
  const jobs = useQuery({ ...cloudJobQuery(), enabled: !!jobID })
  const previous = jobs.data?.find(value => value.id === jobID)
  const backTo = queryPath('/admin/assets', params, { tab: 'sync', region: null, account: null, job: null })
  return <QueryState loading={!!jobID && jobs.isPending} error={jobs.error} retry={() => void jobs.refetch()}>
    {jobID && !previous ? <EmptyResult title="同步记录不存在" /> : <CloudSyncEditor accountID={params.get('account') ?? undefined} previous={previous} backTo={backTo} />}
  </QueryState>
}

export function CloudSyncAction({ accountID, previous, compact = false }: { accountID?: string; previous?: CloudSyncJob; compact?: boolean }) {
  const [params] = useSearchParams()
  const label = compact && previous ? '再次同步' : '同步云资产'
  const disabled = previous?.status === 'queued' || previous?.status === 'running'
  const button = <Button type={compact ? 'text' : 'primary'} icon={compact ? <IconRefresh /> : <IconCloud />} aria-label={label} disabled={disabled}>{!compact && label}</Button>
  return <Tooltip content={label}>{disabled ? button : <Link to={queryPath('/admin/cloud-sync/create', params, { tab: null, account: accountID ?? null, job: previous?.id ?? null })}>{button}</Link>}</Tooltip>
}


const statusLabels = { queued: '等待中', running: '同步中', success: '已完成', failed: '失败' }

export function CloudSyncWorkspace() {
  const accounts = useQuery(cloudAccountQuery)
  const jobs = useQuery(cloudJobQuery())
  const client = useQueryClient()
  const view = useTableView('sync', jobs.data, value => `${value.id} ${accounts.data?.find(account => account.id === value.account_id)?.name ?? value.account_id} ${value.input.cloud_region} ${value.input.instance_ids.join(' ')} ${statusLabels[value.status]}`)
  const completed = jobs.data?.filter(value => value.status === 'success').map(value => value.id).join(',') ?? ''
  useEffect(() => { if (completed) void client.invalidateQueries({ queryKey: catalogKeys.all }) }, [client, completed])
  const columns: DataColumn<CloudSyncJob>[] = [
    { title: '云账号', width: 180, render: (_, value) => <TableText>{accounts.data?.find(account => account.id === value.account_id)?.name ?? value.account_id}</TableText> },
    { title: '云 Region', width: 140, render: (_, value) => <TableText>{value.input.cloud_region}</TableText> },
    { title: '实例范围', width: 210, render: (_, value) => <TableText>{value.input.instance_ids.length ? value.input.instance_ids.join(', ') : '整个云 Region'}</TableText> },
    { title: '状态', width: 110, render: (_, value) => <Tag color={value.status === 'success' ? 'green' : value.status === 'failed' ? 'red' : 'blue'}>{statusLabels[value.status]}</Tag> },
    { title: '结果', width: 290, render: (_, value) => <TableText>{value.error || (value.status === 'success' ? `新增 ${value.result.created}，更新 ${value.result.updated}，无内网地址 ${value.result.skipped}${value.result.missing_ids?.length ? `；未找到：${value.result.missing_ids.join(', ')}` : ''}` : '')}</TableText> },
    { title: '时间', width: 180, render: (_, value) => formatTime(value.created_at) },
    { title: '操作', width: 96, fixed: 'right', render: (_, value) => <CloudSyncAction previous={value} compact /> },
  ]
  return <div className="cloud-sync-workspace">
    <TabToolbar title="同步记录"><Input.Search className="filter-search" aria-label="搜索同步记录" placeholder="搜索云账号、Region 或实例" allowClear value={view.search} onChange={view.setSearch} /><div className="table-actions">
      <Tooltip content="刷新同步记录"><Button icon={<IconRefresh />} aria-label="刷新同步记录" loading={jobs.isFetching} onClick={() => void jobs.refetch()} /></Tooltip>
      <CloudSyncAction />
    </div></TabToolbar>
    <DataTable columns={columns} data={view.data} pagination={view.pagination} loading={jobs.isPending} error={jobs.error || accounts.error} onRetry={() => { void jobs.refetch(); void accounts.refetch() }} />
  </div>
}
