import { Button, Form, Tag } from '@arco-design/web-react'
import type { FormInstance } from '@arco-design/web-react'
import { IconSearch } from '@arco-design/web-react/icon'
import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { request } from '@/shared/api/client'
import { DataTable } from '@/shared/ui/data-table'
import { LabelTags } from '@/shared/ui/labels'
import { ErrorNotice } from '@/shared/ui/page'
import type { LabelBindingDraft, LabelMatchPage, LabelPreview } from './types'

interface PreviewInput { user_selector: string; role_selector: string; asset_selector: string; user_offset: number; role_offset: number; asset_offset: number; limit: number }

function Matches({ title, value, loading, onPage }: { title: string; value: LabelMatchPage; loading: boolean; onPage: (offset: number, limit: number) => void }) {
  return <section className="label-match-results"><div className="table-toolbar"><strong>{title}</strong><Tag color={value.total ? 'green' : 'orange'}>{value.total} 个匹配对象</Tag></div>
    <DataTable data={value.items} loading={loading} columns={[
      { title: '名称', dataIndex: 'name', width: 160 },
      { title: '标签', width: 300, render: (_, value) => <LabelTags value={value.labels} /> },
    ]} empty="没有匹配对象" pagination={{ page: Math.floor(value.offset / value.limit) + 1, pageSize: value.limit, count: value.items.length, total: value.total, hasNext: value.offset + value.items.length < value.total, onChange: (page, size) => onPage((page - 1) * size, size) }} />
  </section>
}

export function LabelBindingPreview({ form, ownership }: { form: FormInstance<LabelBindingDraft>; ownership: boolean }) {
  const userSelector = String(Form.useWatch('user_selector', form) ?? '')
  const roleSelector = String(Form.useWatch('role_selector', form) ?? '')
  const assetSelector = String(Form.useWatch('asset_selector', form) ?? '')
  const [input, setInput] = useState<PreviewInput | null>(null)
  const current = input && input.user_selector === userSelector && (ownership ? input.asset_selector === assetSelector : input.role_selector === roleSelector)
  const query = useQuery({ queryKey: ['label-preview', ownership, input], enabled: !!current, retry: false, refetchOnWindowFocus: false, queryFn: ({ signal }) => request<LabelPreview>(ownership ? '/admin/ownerships/preview' : '/admin/role-bindings/preview', { method: 'POST', body: input, signal, validationMessages: true }) })
  const preview = () => {
    if (current) { void query.refetch(); return }
    setInput({ user_selector: userSelector, role_selector: roleSelector, asset_selector: assetSelector, user_offset: 0, role_offset: 0, asset_offset: 0, limit: 20 })
  }
  const paginate = (field: 'user_offset' | 'role_offset' | 'asset_offset', offset: number, limit: number) => setInput(previous => previous && ({ ...previous, ...(limit !== previous.limit ? { user_offset: 0, role_offset: 0, asset_offset: 0 } : {}), [field]: offset, limit }))
  return <section className="label-match-preview"><div className="table-toolbar"><strong>标签匹配预览</strong><Button icon={<IconSearch />} loading={!!current && query.isFetching} disabled={!userSelector.trim() || !(ownership ? assetSelector : roleSelector).trim()} onClick={preview}>预览匹配</Button></div>
    {current && <><ErrorNotice error={query.error} retry={preview} />{query.data && <>
      <Matches title={ownership ? '负责人候选用户' : '授权用户'} value={query.data.users} loading={query.isFetching} onPage={(offset, limit) => paginate('user_offset', offset, limit)} />
      <Matches title={ownership ? '负责资产' : '授予角色'} value={ownership ? query.data.assets : query.data.roles} loading={query.isFetching} onPage={(offset, limit) => paginate(ownership ? 'asset_offset' : 'role_offset', offset, limit)} />
    </>}</>}
  </section>
}
