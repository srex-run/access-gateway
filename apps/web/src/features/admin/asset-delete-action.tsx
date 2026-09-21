import { Button, Message, Popconfirm, Tooltip } from '@arco-design/web-react'
import { IconDelete } from '@arco-design/web-react/icon'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { PermissionGate } from '@/features/auth'
import type { Asset } from '@/features/catalog'
import { describeError, request, resourcePath } from '@/shared/api/client'

export function AssetDeleteAction({ asset, compact = false, onDeleted }: { asset: Asset; compact?: boolean; onDeleted?: () => void }) {
  const client = useQueryClient()
  const remove = useMutation({
    mutationFn: () => request<void>(resourcePath('admin/assets', asset.id), { method: 'DELETE' }),
    onSuccess: async () => {
      onDeleted?.()
      await client.invalidateQueries({ queryKey: ['catalog'] })
      Message.success('资产已删除')
    },
    onError: error => Message.error(describeError(error)),
  })
  return <PermissionGate permission="catalog:manage"><Popconfirm title={`删除资产「${asset.name}」？`} content="删除后将回收未结束的会话，保留历史申请和审计记录。" okText="删除" cancelText="取消" onOk={() => remove.mutateAsync()}><Tooltip content="删除资产"><Button type={compact ? 'text' : 'outline'} size={compact ? 'small' : 'default'} status="danger" icon={<IconDelete />} aria-label={`删除资产 ${asset.name}`} loading={remove.isPending} disabled={remove.isPending}>{compact ? null : '删除资产'}</Button></Tooltip></Popconfirm></PermissionGate>
}
