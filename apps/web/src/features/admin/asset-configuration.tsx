import { Button } from '@arco-design/web-react'
import { IconEdit } from '@arco-design/web-react/icon'
import { Link, useSearchParams } from 'react-router-dom'
import { PermissionGate } from '@/features/auth'
import { ResourceStatusTag, RiskTag } from '@/features/catalog'
import type { Asset } from '@/features/catalog'
import { AssetWorkflowSelect } from '@/features/governance'
import { queryPath } from '@/shared/lib/navigation'
import { TableText } from '@/shared/ui/data-table'
import { DetailList, SectionTitle } from '@/shared/ui/page'
import { assetProtocolLabel } from './fields'

export function AssetConfiguration({ asset }: { asset: Asset }) {
  const [params] = useSearchParams()
  return <section className="asset-configuration" aria-label="基本配置">
    <SectionTitle extra={<div className="table-actions"><PermissionGate permission="workflow:manage"><Link to="/admin/workflows">管理审批流程</Link></PermissionGate><Link to={queryPath(`/admin/assets/${asset.id}/edit`, params, { tab: null })}><Button type="primary" size="small" icon={<IconEdit />}>编辑资产</Button></Link></div>}>基本配置</SectionTitle>
    <DetailList items={[
      { label: '资产名称', value: <TableText>{asset.name}</TableText> },
      { label: '类型', value: <TableText>{assetProtocolLabel(asset.asset_type)}</TableText> },
      { label: '状态', value: <ResourceStatusTag status={asset.status} /> },
      { label: '风险等级', value: <RiskTag risk={asset.risk_level} /> },
      { label: '最长访问时限', value: <TableText>{`${asset.max_ttl_seconds} 秒`}</TableText> },
      { label: '审批流程', value: <AssetWorkflowSelect value={asset.approval_workflow_id} assetID={asset.id} readOnly /> },
    ]} />
  </section>
}
