import { Button, Form, InputNumber, Message, Popconfirm, Select, Space, Tooltip } from '@arco-design/web-react'
import { IconDelete, IconEdit, IconPlus, IconRefresh } from '@arco-design/web-react/icon'
import type { DataColumn } from '@/shared/ui/data-table'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { catalogKeys, portQuery } from '@/features/catalog'
import { PermissionGate } from '@/features/auth'
import type { AssetPort } from '@/features/catalog'
import { request, resourcePath } from '@/shared/api/client'
import { useTableView } from '@/shared/hooks/use-table-view'
import { queryPath } from '@/shared/lib/navigation'
import { DataTable } from '@/shared/ui/data-table'
import { CopyableText } from '@/shared/ui/copyable-text'
import { ResourceForm } from '@/shared/ui/resource-form'
import { HelpPopover } from '@/shared/ui/help-popover'
import { EmptyResult, ErrorNotice, QueryState, SectionTitle } from '@/shared/ui/page'
import { useAdminForm } from './hooks'
import { assetAuditQuery, managedAssetsQuery } from './api'
import { AssetGovernance } from '@/features/governance'
import { AssetConfiguration } from './asset-configuration'
import { AssetDeleteAction } from './asset-delete-action'
import './asset-settings.css'

function PortSettings({ id }: { id: string }) {
  const [params] = useSearchParams()
  const client = useQueryClient()
  const query = useQuery(portQuery(id))
  const remove = useMutation({
    mutationFn: (port: AssetPort) => request<void>(resourcePath('admin/assets', id, `/ports/${encodeURIComponent(port.id)}`), { method: 'DELETE' }),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: catalogKeys.ports(id) })
      await client.invalidateQueries({ queryKey: assetAuditQuery(id).queryKey })
      Message.success('端口已删除')
    },
  })
  const view = useTableView('ports', query.data, value => `${value.port} ${value.protocol}`)
  const columns: DataColumn<AssetPort>[] = [
    { title: '端口', dataIndex: 'port', width: 120 }, { title: '协议', dataIndex: 'protocol', width: 120 },
    { title: '操作', width: 72, fixed: 'right', render: (_, port) => <Popconfirm title={`删除端口 ${port.port} / ${port.protocol.toUpperCase()}？`} content="删除后不能再申请访问此端口。" okText="删除" cancelText="取消" onOk={() => remove.mutateAsync(port)}><Tooltip content="删除端口"><Button type="text" size="small" status="danger" icon={<IconDelete />} aria-label={`删除端口 ${port.port}`} loading={remove.isPending && remove.variables?.id === port.id} disabled={remove.isPending} /></Tooltip></Popconfirm> },
  ]
  return <section aria-label="端口">
    <SectionTitle extra={<div className="table-actions">
      <Tooltip content="刷新端口"><Button icon={<IconRefresh />} aria-label="刷新端口" loading={query.isFetching} onClick={() => void query.refetch()} /></Tooltip>
      <Link to={queryPath(`/admin/assets/${id}/ports/create`, params, { tab: null })}><Button type="primary" icon={<IconPlus />}>添加端口</Button></Link>
    </div>}>端口</SectionTitle>
    <ErrorNotice error={remove.error} />
    <DataTable columns={columns} data={view.data} pagination={view.pagination} loading={query.isPending} error={query.error} onRetry={() => void query.refetch()} />
  </section>
}

export function PortCreateForm({ id }: { id: string }) {
  const [params] = useSearchParams()
  const state = useAdminForm((body: { port: number; protocol: string }) => request(resourcePath('admin/assets', id, '/ports'), { method: 'POST', body }))
  return <ResourceForm form={state.form} initialValues={{ protocol: 'tcp' }} onSubmit={value => state.mutation.mutate(value)} onChange={state.change} dirty={state.dirty} submitting={state.mutation.isPending} saved={state.mutation.isSuccess} backTo={queryPath(`/admin/assets/${id}`, params, { tab: null })} error={state.mutation.error} submitText="添加端口">
    <div className="form-grid"><Form.Item label="端口" field="port" rules={[{ required: true, type: 'number', min: 1, max: 65535 }]}><InputNumber min={1} max={65535} precision={0} /></Form.Item><Form.Item label="协议" field="protocol"><Select options={['tcp']} /></Form.Item></div>
  </ResourceForm>
}

export function AssetSettings({ id }: { id: string }) {
  const [params] = useSearchParams()
  const navigate = useNavigate()
  const assets = useQuery(managedAssetsQuery)
  const asset = assets.data?.find(value => value.id === id)
  const region = asset?.region_id ?? ''
  return <QueryState loading={assets.isPending} error={assets.error} retry={() => void assets.refetch()}>{asset ? <div className="asset-settings">
    <div className="detail-actions">
      <Space>资产 ID <CopyableText value={id} /></Space>
      <Space wrap>
        <PermissionGate permission="role:manage"><Link to={`/requests/create?asset=${id}&region=${region}&mode=test`}><Button disabled={!region}>测试连接</Button></Link><HelpPopover title="测试连接">管理员可创建最长 10 分钟的免审批测试会话。网关会随会话自动启动，连接要求来源 IP 校验和加密。</HelpPopover></PermissionGate>
        <Link to={queryPath(`/admin/assets/${id}/status/edit`, params, { tab: null })}><Button icon={<IconEdit />}>修改状态</Button></Link>
        <AssetDeleteAction asset={asset} onDeleted={() => void navigate(queryPath('/admin/assets', params, { tab: 'assets' }), { replace: true })} />
      </Space>
    </div>
    <AssetConfiguration asset={asset} />
    <PortSettings id={id} />
    <AssetGovernance id={id} />
  </div> : <EmptyResult title="资产不存在" />}</QueryState>
}
