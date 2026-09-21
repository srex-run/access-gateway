import { Button, Input, Select } from '@arco-design/web-react'
import type { DataColumn } from '@/shared/ui/data-table'
import { IconPlus, IconRefresh, IconSearch } from '@arco-design/web-react/icon'
import { Link } from 'react-router-dom'
import { formatDuration } from '@/shared/lib/format'
import { CopyableText } from '@/shared/ui/copyable-text'
import { DataTable } from '@/shared/ui/data-table'
import { TabToolbar } from '@/shared/ui/route-tabs'
import { IconButton } from '@/shared/ui/icon-button'
import { StatusTag } from '@/shared/ui/status-tag'
import { useCatalog } from './hooks'
import type { Asset, ResourceStatus, RiskLevel } from './types'

const resourceLabels: Record<ResourceStatus, string> = { enabled: '已启用', disabled: '已停用', maintenance: '维护中' }
const riskLabels: Record<RiskLevel, string> = { normal: '普通', sensitive: '敏感', critical: '关键' }
export function ResourceStatusTag({ status }: { status: ResourceStatus }) {
  return <StatusTag label={resourceLabels[status] ?? status} tone={status === 'enabled' ? 'success' : status === 'maintenance' ? 'warning' : 'neutral'} />
}
export function RiskTag({ risk }: { risk: RiskLevel }) {
  return <StatusTag label={riskLabels[risk] ?? risk} tone={risk === 'critical' ? 'danger' : risk === 'sensitive' ? 'warning' : 'info'} />
}

export function CatalogWorkspace() {
  const catalog = useCatalog()
  const columns: DataColumn<Asset>[] = [
    { title: '资产名称', dataIndex: 'name', width: 220 },
    { title: '资产 ID', width: 180, render: (_, asset) => <CopyableText value={asset.id} abbreviated /> },
    { title: '类型', dataIndex: 'asset_type', width: 140 },
    { title: '风险级别', width: 100, render: (_, asset) => <RiskTag risk={asset.risk_level} /> },
    { title: '状态', width: 100, render: (_, asset) => <ResourceStatusTag status={asset.status} /> },
    { title: '最长访问时限', width: 160, render: (_, asset) => formatDuration(asset.max_ttl_seconds) },
    { title: '操作', width: 120, fixed: 'right', render: (_, asset) => asset.status === 'enabled' ? <Link to={`/requests/create?region=${encodeURIComponent(asset.region_id)}&asset=${encodeURIComponent(asset.id)}`}><Button type="text" size="small" icon={<IconPlus />}>申请访问</Button></Link> : <span className="muted">不可申请</span> },
  ]
  return <>
    <TabToolbar title="资产目录"><div className="table-filters">
      <Select className="filter-select" aria-label="区域" placeholder="选择区域" value={catalog.region || undefined} loading={catalog.regions.isPending} onChange={(value: string) => catalog.setFilter('region', value)} options={(catalog.regions.data ?? []).map(region => ({ value: region.id, label: region.name }))} />
      <Input className="filter-search" aria-label="搜索资产" placeholder="搜索资产名称、类型或 ID" prefix={<IconSearch />} allowClear value={catalog.search} onChange={value => catalog.setFilter('q', value)} />
    </div><IconButton label="刷新资产目录" icon={<IconRefresh />} loading={catalog.assets.isFetching} onClick={() => { void catalog.regions.refetch(); if (catalog.region) void catalog.assets.refetch() }} /></TabToolbar>
    <DataTable columns={columns} data={catalog.data} loading={catalog.regions.isPending || (!!catalog.region && catalog.assets.isPending)} error={catalog.regions.error ?? catalog.assets.error} onRetry={() => { void catalog.regions.refetch(); if (catalog.region) void catalog.assets.refetch() }} empty={catalog.search ? '没有匹配的资产' : '该区域暂无可用资产'} />
  </>
}
