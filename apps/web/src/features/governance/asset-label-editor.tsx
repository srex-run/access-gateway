import { Input, Select } from '@arco-design/web-react'
import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { PermissionGate, useIdentity } from '@/features/auth'
import { request, resourcePath } from '@/shared/api/client'
import { ErrorNotice } from '@/shared/ui/page'
import { LabelEditor, type Labels } from '@/shared/ui/labels'

// Display short keys while retaining existing audit and approval selectors.
export const assetLabelKeyAliases = { 'security.access-gateway.io/audit-profile': 'audit' }
const isUserID = (value: string) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)
interface Owner { id: string; nickname: string; username: string }

function OwnerSelect({ value, onChange }: { value: string; onChange: (value: string) => void }) {
  const [search, setSearch] = useState('')
  const query = useQuery({ queryKey: ['users', search, true, 50, 0], queryFn: ({ signal }) => request<Owner[]>('/admin/users', { signal, query: { search, active: true, limit: 50, offset: 0 } }) })
  return <div className="label-value-editor">
    <Select aria-label="标签值" placeholder="选择负责人" value={isUserID(value) ? value : undefined} onChange={onChange} showSearch filterOption={false} onSearch={setSearch} loading={query.isFetching} disabled={!!query.error} options={(query.data ?? []).map(owner => ({ value: owner.id, label: `${owner.nickname}${owner.username ? ` (${owner.username})` : ''}` }))} />
    <ErrorNotice error={query.error} retry={() => void query.refetch()} />
  </div>
}

export function AssetLabelEditor({ value = {}, onChange, disabled }: { value?: Labels; onChange?: (value: Labels) => void; disabled?: boolean }) {
  const identity = useIdentity()
  const ownerID = value.owner ?? ''
  const owner = useQuery({ queryKey: ['managed-user', ownerID], enabled: isUserID(ownerID) && !!identity.data?.permissions.includes('user:read'), queryFn: ({ signal }) => request<Owner>(resourcePath('admin/users', ownerID), { signal }) })
  return <LabelEditor compact value={value} onChange={onChange} disabled={disabled} keyAliases={assetLabelKeyAliases}
    validateEntry={(key, entry) => key !== 'owner' || isUserID(entry)}
    formatValue={(key, entry) => key === 'owner' && owner.data ? owner.data.username || owner.data.nickname : entry}
    renderValueInput={(key, entry, change) => key === 'owner' ? <PermissionGate permission="user:read" fallback={<Input aria-label="标签值" placeholder="负责人用户 ID" value={entry} onChange={change} maxLength={36} />}><OwnerSelect value={entry} onChange={change} /></PermissionGate> : null} />
}
