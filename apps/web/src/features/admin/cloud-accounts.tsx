import { Button, Checkbox, Form, Input, Select, Space, Switch, Tag, Tooltip } from '@arco-design/web-react'
import type { DataColumn } from '@/shared/ui/data-table'
import { IconEdit, IconPlus, IconRefresh } from '@arco-design/web-react/icon'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { queryPath } from '@/shared/lib/navigation'
import { ResourceForm } from '@/shared/ui/resource-form'
import { PermissionGate } from '@/features/auth'
import { useTableView } from '@/shared/hooks/use-table-view'
import { DataTable, TableText } from '@/shared/ui/data-table'
import { TabToolbar } from '@/shared/ui/route-tabs'
import { EmptyResult, QueryState } from '@/shared/ui/page'
import { cloudAccountQuery, cloudJobQuery, cloudProviders, saveCloudAccount } from './cloud-api'
import { CloudSyncAction } from './cloud-sync'
import type { CloudAccount, CloudAccountInput } from './cloud-api'
import { requiredRules } from './fields'

function CloudAccountEditor({ account, backTo }: { account?: CloudAccount; backTo: string }) {
  const [form] = Form.useForm<CloudAccountInput>()
  const [provider, setProvider] = useState(account?.provider ?? 'aliyun')
  const [clearToken, setClearToken] = useState(false)
  const [dirty, setDirty] = useState(false)
  const client = useQueryClient()
  const mutation = useMutation({ mutationFn: (value: CloudAccountInput) => saveCloudAccount(account?.id, {
    ...value, revision: account?.revision, session_token: clearToken ? '' : value.session_token?.trim() || undefined,
  }), onSuccess: async () => { setDirty(false); await client.invalidateQueries({ queryKey: cloudAccountQuery.queryKey }) } })
  return <ResourceForm form={form} initialValues={{ name: account?.name, provider, enabled: account?.enabled ?? true }} onSubmit={value => mutation.mutate(value)}
    dirty={dirty} onChange={() => { setDirty(true); mutation.reset() }} submitting={mutation.isPending} saved={mutation.isSuccess} error={mutation.error} backTo={backTo}>
      <Form.Item label="账号名称" field="name" rules={requiredRules}><Input maxLength={128} /></Form.Item>
      <Form.Item label="云厂商" field="provider" rules={requiredRules}><Select options={cloudProviders} disabled={!!account} onChange={setProvider} /></Form.Item>
      <Form.Item label={account ? 'Access Key（已配置）' : 'Access Key'} field="access_key" rules={account ? [] : requiredRules}><Input.Password autoComplete="new-password" maxLength={256} /></Form.Item>
      <Form.Item label={account ? 'Secret Key（已配置）' : 'Secret Key'} field="secret_key" rules={account ? [] : requiredRules}><Input.Password autoComplete="new-password" maxLength={256} /></Form.Item>
      {provider !== 'huaweicloud' && <><Form.Item label="Session Token" field="session_token"><Input.Password autoComplete="new-password" maxLength={8192} disabled={clearToken} /></Form.Item>{account && <Form.Item><Checkbox checked={clearToken} onChange={value => { setClearToken(value); setDirty(true); mutation.reset() }}>清除 Session Token</Checkbox></Form.Item>}</>}
      <Form.Item label="启用" field="enabled" triggerPropName="checked"><Switch /></Form.Item>
  </ResourceForm>
}

export function CloudAccountForm({ id }: { id?: string }) {
  const [params] = useSearchParams()
  const accounts = useQuery({ ...cloudAccountQuery, enabled: !!id })
  const backTo = queryPath('/admin/assets', params, { tab: 'cloud', region: null })
  const account = accounts.data?.find(value => value.id === id)
  return <QueryState loading={!!id && accounts.isPending} error={accounts.error} retry={() => void accounts.refetch()}>
    {id && !account ? <EmptyResult title="云账号不存在" /> : <CloudAccountEditor key={id ?? 'create'} account={account} backTo={backTo} />}
  </QueryState>
}

export function CloudAccounts() {
  const query = useQuery(cloudAccountQuery)
  const jobs = useQuery(cloudJobQuery())
  const view = useTableView('accounts', query.data, value => `${value.name} ${value.provider}`)
  const [params] = useSearchParams()
  const columns: DataColumn<CloudAccount>[] = [
    { title: '账号名称', width: 200, render: (_, value) => <TableText>{value.name}</TableText> },
    { title: '云厂商', width: 160, render: (_, value) => cloudProviders.find(option => option.value === value.provider)?.label },
    { title: '状态', width: 120, render: (_, value) => <Tag color={value.enabled ? 'green' : undefined}>{value.enabled ? '启用' : '停用'}</Tag> },
    { title: '最近云 Region', width: 160, render: (_, value) => <TableText>{jobs.data?.find(job => job.account_id === value.id)?.input.cloud_region}</TableText> },
    { title: '最近实例范围', width: 240, render: (_, value) => {
      const job = jobs.data?.find(item => item.account_id === value.id)
      return <TableText>{job ? job.input.instance_ids.length ? job.input.instance_ids.join(', ') : '整个云 Region' : ''}</TableText>
    } },
    { title: '操作', width: 88, fixed: 'right', render: (_, value) => <Space>
      <PermissionGate permission="role:manage"><Tooltip content="编辑云账号"><Link to={queryPath(`/admin/cloud-accounts/${value.id}/edit`, params, { tab: null })}><Button icon={<IconEdit />} aria-label={`编辑 ${value.name}`} /></Link></Tooltip></PermissionGate>
      {value.enabled && <CloudSyncAction accountID={value.id} previous={jobs.data?.find(job => job.account_id === value.id)} compact />}
    </Space> },
  ]
  return <>
    <TabToolbar title="云账号"><div className="table-filters"><Input.Search className="filter-search" aria-label="搜索云账号" placeholder="搜索云账号" allowClear value={view.search} onChange={view.setSearch} /></div><div className="table-actions">
      <Tooltip content="刷新云账号"><Button icon={<IconRefresh />} aria-label="刷新云账号" loading={query.isFetching || jobs.isFetching} onClick={() => { void query.refetch(); void jobs.refetch() }} /></Tooltip>
      <PermissionGate permission="role:manage"><Link to={queryPath('/admin/cloud-accounts/create', params, { tab: null })}><Button type="primary" icon={<IconPlus />}>添加云账号</Button></Link></PermissionGate>
    </div></TabToolbar>
    <DataTable columns={columns} data={view.data} pagination={view.pagination} loading={query.isPending} error={query.error || jobs.error} onRetry={() => { void query.refetch(); void jobs.refetch() }} />
  </>
}
