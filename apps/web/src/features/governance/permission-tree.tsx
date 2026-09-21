import { Button, Tree } from '@arco-design/web-react'
import type { TreeProps } from '@arco-design/web-react'
import { useMemo, useState } from 'react'
import { HelpPopover } from '@/shared/ui/help-popover'
import { buildPermissionTree, changePermissionSelection, expandedPermissionKeys, permissionSelectionState } from './permission-tree-model'
import type { PermissionItem, PermissionNode, PermissionTreeOptions } from './permission-tree-model'
import './permission-tree.css'

interface PermissionTreeProps extends PermissionTreeOptions {
  items: readonly PermissionItem[]
  value?: string[]
  onChange?: (value: string[]) => void
  disabled?: boolean
}

function renderNodes(nodes: PermissionNode[], disabled?: boolean): NonNullable<TreeProps['treeData']> {
  return nodes.map(node => ({
    ...node,
    disableCheckbox: disabled || node.disableCheckbox,
    title: <span className="permission-tree-title"><span className="permission-tree-name">{node.title}</span>{!node.children && <HelpPopover title={`${node.title}权限`} onClick={event => event.stopPropagation()}>
      {node.permissions.map(permission => <div key={permission.key}>
        <p>{permission.name}：{permission.description}</p>
        {permission.menus.length > 1 && <p>此权限同时用于{permission.menus.join('、')}，勾选或取消时同步生效。</p>}
        {permission.locked && <p>内置平台管理员必须保留此权限，以便继续管理角色与授权。</p>}
      </div>)}
    </HelpPopover>}</span>,
    children: node.children && renderNodes(node.children, disabled),
  }))
}

export function PermissionTree({ items, value = [], onChange, disabled, lockedPermissions }: PermissionTreeProps) {
  const nodes = useMemo(() => buildPermissionTree(items, { lockedPermissions }), [items, lockedPermissions])
  const treeData = useMemo(() => renderNodes(nodes, disabled), [nodes, disabled])
  const [expandedKeys, setExpandedKeys] = useState(() => expandedPermissionKeys(nodes))
  const { checkedKeys, halfCheckedKeys } = permissionSelectionState(nodes, value)

  return <div className="permission-tree">
    <div className="permission-tree-toolbar"><span>已选 {new Set(value).size} 项权限</span><div>
      <Button type="text" size="mini" disabled={disabled} onClick={() => setExpandedKeys(expandedPermissionKeys(nodes))}>展开全部</Button>
      <Button type="text" size="mini" disabled={disabled} onClick={() => setExpandedKeys([])}>收起全部</Button>
    </div></div>
    <Tree checkable checkStrictly actionOnClick="check" selectedKeys={[]} blockNode treeData={treeData} checkedKeys={checkedKeys} halfCheckedKeys={halfCheckedKeys} expandedKeys={expandedKeys} autoExpandParent={false} onExpand={setExpandedKeys}
      onCheck={(_, { node, checked }) => { if (!disabled) onChange?.(changePermissionSelection(nodes, value, node.props._key ?? '', checked)) }} />
  </div>
}
