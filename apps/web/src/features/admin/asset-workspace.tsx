import { Button, Input, Select, Tooltip } from '@arco-design/web-react'
import { IconEdit, IconPlus, IconRefresh, IconSearch } from '@arco-design/web-react/icon'
import type { DataColumn } from '@/shared/ui/data-table'
import { useQuery } from '@tanstack/react-query'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { ResourceStatusTag, RiskTag } from '@/features/catalog'
import type { Asset } from '@/features/catalog'
import { useTableView } from '@/shared/hooks/use-table-view'
import { queryPath } from '@/shared/lib/navigation'
import { DataTable, TableText } from '@/shared/ui/data-table'
import { RouteTabs, TabToolbar } from '@/shared/ui/route-tabs'
import { managedAssetsQuery } from './api'
import { cloudAccountQuery, cloudProviders } from './cloud-api'
import { CloudAccounts } from './cloud-accounts'
import { CloudSyncAction, CloudSyncWorkspace } from './cloud-sync'
import { ResourceLookupAction } from './resource-actions'
import { assetProtocolLabel, statusOptions } from './fields'
import { AssetDeleteAction } from './asset-delete-action'

function ManagedAssetsTable() {
  const [params, setParams] = useSearchParams()
  const navigate = useNavigate()
  const assets = useQuery(managedAssetsQuery)
  const accounts = useQuery(cloudAccountQuery)
  const source = params.get('source') ?? ''
  const status = params.get('status') ?? ''
  const rows = assets.data?.map(value => {
    const accountID = value.external_source?.startsWith('cloud.') ? value.external_source.slice(6) : ''
    const account = accounts.data?.find(item => item.id === accountID)
    // Cloud identities are stored as <region>.<instance ID> by the sync service.
    const [cloudRegion = '', instanceID = ''] = accountID ? (value.external_id ?? '').split('.', 2) : []
    return { ...value, accountName: account?.name ?? accountID, source: accountID ? account?.provider ?? 'cloud' : value.external_source ? 'external' : 'manual', cloudRegion, instanceID }
  })
  const filtered = rows?.filter(value => (!source || value.source === source) && (!status || value.status === status))
  const view = useTableView('assets', filtered, value => `${value.name} ${value.id} ${value.asset_type} ${value.accountName} ${value.cloudRegion} ${value.external_id ?? ''}`)
  const filter = (key: string, value: string) => setParams(previous => {
    const next = new URLSearchParams(previous)
    if (value) next.set(key, value)
    else next.delete(key)
    next.set('assets_page', '1')
    return next
  }, { replace: true })
  const settingsPath = (value: Asset) => queryPath(`/admin/assets/${value.id}/edit`, params, { tab: null, region: null })
  const columns: DataColumn<NonNullable<typeof rows>[number]>[] = [
    { title: '资产名称', width: 220, render: (_, value) => <Link className="table-link" to={queryPath(`/admin/assets/${value.id}`, params, { tab: null, region: null })}><TableText>{value.name}</TableText></Link> },
    { title: '类型', width: 120, render: (_, value) => <TableText>{assetProtocolLabel(value.asset_type)}</TableText> },
    { title: '来源 / 云账号', width: 180, render: (_, value) => <TableText>{value.accountName || value.external_source || '手动添加'}</TableText> },
    { title: '云 Region', width: 150, render: (_, value) => <TableText>{value.cloudRegion}</TableText> },
    { title: '实例 ID', width: 240, render: (_, value) => <TableText>{value.instanceID || value.external_id}</TableText> },
    { title: '风险', width: 90, render: (_, value) => <RiskTag risk={value.risk_level} /> },
    { title: '状态', width: 90, render: (_, value) => <ResourceStatusTag status={value.status} /> },
    { title: '操作', width: 100, fixed: 'right', render: (_, value) => <div className="table-actions"><Tooltip content="配置资产"><Link to={settingsPath(value)}><Button type="text" size="small" icon={<IconEdit />} aria-label={`配置 ${value.name}`} /></Link></Tooltip><AssetDeleteAction asset={value} compact /></div> },
  ]
  return <>
    <TabToolbar title="资产">
      <div className="table-filters">
        <Input className="filter-search" aria-label="搜索资产" placeholder="搜索资产、云 Region 或实例 ID" prefix={<IconSearch />} allowClear value={view.search} onChange={view.setSearch} />
        <Select className="filter-select" aria-label="资产来源" value={source} onChange={value => filter('source', value)} options={[{ value: '', label: '全部来源' }, { value: 'manual', label: '手动添加' }, ...cloudProviders, { value: 'external', label: '外部导入' }]} />
        <Select className="filter-select" aria-label="资产状态" value={status} onChange={value => filter('status', value)} options={[{ value: '', label: '全部状态' }, ...statusOptions]} />
      </div>
      <div className="table-actions">
        <ResourceLookupAction label="资产 ID" onLookup={id => void navigate(queryPath(`/admin/assets/${id}`, params, { tab: null }))} actionLabel="管理资产" />
        <Tooltip content="刷新资产"><Button aria-label="刷新资产" icon={<IconRefresh />} loading={assets.isFetching} onClick={() => void assets.refetch()} /></Tooltip>
        <Link to={queryPath('/admin/assets/create', params, { tab: 'assets', region: null })}><Button icon={<IconPlus />}>新建资产</Button></Link>
        <CloudSyncAction />
      </div>
    </TabToolbar>
    <DataTable columns={columns} data={view.data} loading={assets.isPending} error={assets.error || accounts.error} onRetry={() => { void assets.refetch(); void accounts.refetch() }} pagination={view.pagination} empty="暂无资产" />
  </>
}

export function AssetWorkspace() {
  return <RouteTabs items={[
    { key: 'assets', title: '资产', content: <ManagedAssetsTable /> },
    { key: 'cloud', title: '云账号', content: <CloudAccounts /> },
    { key: 'sync', title: '同步记录', content: <CloudSyncWorkspace /> },
  ]} />
}
