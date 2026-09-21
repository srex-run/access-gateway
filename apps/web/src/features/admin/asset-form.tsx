import { Button, Form, Input, InputNumber, Select } from '@arco-design/web-react'
import { IconPlus } from '@arco-design/web-react/icon'
import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import type { Asset } from '@/features/catalog'
import { AssetWorkflowSelect } from '@/features/governance'
import { queryPath } from '@/shared/lib/navigation'
import { EmptyResult, QueryState, SectionTitle } from '@/shared/ui/page'
import { ResourceForm } from '@/shared/ui/resource-form'
import { assetAuditQuery, createAsset, managedAssetsQuery, updateAsset } from './api'
import { AssetAuditFields } from './asset-audit-fields'
import { assetAuditInput, auditRule, isAuditProtocol, normalizeAssetProtocol } from './asset-form-model'
import type { AssetAuditRule, AssetAuditView, AssetFormValues } from './asset-form-model'
import { assetProtocolOptions, assetProtocolLabel, requiredRules, StatusField } from './fields'
import { useAdminForm } from './hooks'

function AssetForm({ asset, audit }: { asset?: Asset; audit?: AssetAuditView }) {
  const [params] = useSearchParams()
  const [protocol, setProtocol] = useState(normalizeAssetProtocol(asset?.asset_type ?? 'mysql'))
  const [generating, setGenerating] = useState(false)
  const state = useAdminForm((values: AssetFormValues) => {
    const body = { name: values.name.trim(), asset_type: values.asset_type, risk_level: values.risk_level, max_ttl_seconds: values.max_ttl_seconds,
      ...((values.approval_workflow_id ?? '') !== (asset?.approval_workflow_id ?? '') ? { approval_workflow_id: values.approval_workflow_id ?? '' } : {}),
      audit: assetAuditInput(values.rules, audit?.revision ?? 0) }
    return asset ? updateAsset(asset.id, { ...body, ...(values.target?.trim() ? { target: values.target.trim() } : {}) })
      : createAsset({ ...body, target: values.target.trim(), status: values.status })
  })
  const defaultProtocol = isAuditProtocol(protocol) ? protocol : 'mysql'
  const [initial] = useState<Partial<AssetFormValues>>(() => ({ name: asset?.name, asset_type: protocol, risk_level: asset?.risk_level ?? 'normal', max_ttl_seconds: asset?.max_ttl_seconds ?? 3600,
    status: asset?.status ?? 'enabled', target: '', approval_workflow_id: asset?.approval_workflow_id ?? '',
    rules: asset ? (audit?.profiles ?? []).map(p => auditRule(p.protocol, p, audit?.has_secrets[p.name])) : [auditRule(defaultProtocol)] }))
  const backTo = queryPath('/admin/assets', params, { tab: 'assets', region: null })
  const busy = state.mutation.isPending || generating
  return <ResourceForm form={state.form} initialValues={initial} onSubmit={value => { if (!busy) state.mutation.mutate({ ...value, rules: state.form.getFieldValue('rules') as AssetAuditRule[] }) }} onChange={state.change} dirty={state.dirty}
    submitting={busy} saved={state.mutation.isSuccess} error={state.mutation.error} backTo={backTo}>
    <SectionTitle>基本信息</SectionTitle>
    <div className="form-grid">
      <Form.Item label="资产名称" field="name" rules={requiredRules}><Input maxLength={128} /></Form.Item>
      <Form.Item label="资产类型" field="asset_type" rules={requiredRules}><Select options={isAuditProtocol(protocol) ? assetProtocolOptions : [...assetProtocolOptions, { value: protocol, label: `现有类型：${assetProtocolLabel(protocol)}` }]} onChange={value => {
        setProtocol(value)
        if (isAuditProtocol(value)) state.form.setFieldValue('rules', [auditRule(value)])
      }} /></Form.Item>
    </div>
    <Form.Item label="目标地址" field="target" rules={asset ? [] : requiredRules}><Input autoComplete="off" maxLength={4096} disabled={busy || !!asset?.external_source} placeholder={asset?.external_source ? '由外部来源维护' : asset ? '留空保留当前地址' : '资产域名或 IP'} /></Form.Item>
    <div className={`form-grid${asset ? '' : ' asset-policy-grid'}`}>
      <Form.Item label="风险级别" field="risk_level" rules={requiredRules}><Select options={[{ value: 'normal', label: '普通' }, { value: 'sensitive', label: '敏感' }, { value: 'critical', label: '关键' }]} /></Form.Item>
      <Form.Item label="最长访问时限（秒）" field="max_ttl_seconds" rules={[{ required: true, type: 'number', min: 1, max: 18000 }]}><InputNumber min={1} max={18000} precision={0} /></Form.Item>
      {!asset && <StatusField />}
    </div>
    <SectionTitle>访问审批</SectionTitle>
    <Form.Item label="审批流程" field="approval_workflow_id"><AssetWorkflowSelect assetID={asset?.id} disabled={busy} /></Form.Item>
    <SectionTitle>连接与审计</SectionTitle>
    <Form.List field="rules" rules={[{ validator: (rules, callback) => {
      if (!rules?.length) return asset ? callback() : callback('请至少配置一个隧道端口')
      const ports = rules.map(rule => (rule as { profile: { port: number } }).profile.port)
      if (new Set(ports).size !== ports.length) return callback('隧道端口不能重复')
      callback()
    } }]}>{(fields, { add, remove }) => <>
      {fields.map((item, index) => <AssetAuditFields key={`${protocol}-${item.key}`} form={state.form} field={item.field} index={index} assetID={asset?.id} fixedProtocol={isAuditProtocol(protocol)} busy={busy} onChange={state.change} onBusy={setGenerating}
        onRemove={fields.length > 1 ? () => { remove(index); state.change() } : undefined} />)}
      <Button type="text" disabled={busy || fields.length >= 100} icon={<IconPlus />} onClick={() => { add(auditRule(defaultProtocol)); state.change() }}>添加端口</Button>
    </>}</Form.List>
  </ResourceForm>
}

export function AssetCreateForm() {
  return <AssetForm />
}

export function AssetEditForm({ id }: { id: string }) {
  const assets = useQuery(managedAssetsQuery)
  const audit = useQuery(assetAuditQuery(id))
  const asset = assets.data?.find(value => value.id === id)
  return <QueryState loading={assets.isPending || audit.isPending} error={assets.error || audit.error} retry={() => { void assets.refetch(); void audit.refetch() }}>
    {asset && audit.data ? <AssetForm key={id} asset={asset} audit={audit.data} /> : <EmptyResult title="资产不存在" />}
  </QueryState>
}
