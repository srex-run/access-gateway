import { navigationItems } from '../../shared/config/navigation'

export interface PermissionItem { key: string; name: string; description: string }
interface MenuPermission extends PermissionItem { menus: string[]; locked: boolean }
export interface PermissionNode {
  key: string
  title: string
  permissions: MenuPermission[]
  disableCheckbox?: boolean
  children?: PermissionNode[]
}

export interface PermissionTreeOptions { lockedPermissions?: readonly string[] }

export function buildPermissionTree(items: readonly PermissionItem[], options: PermissionTreeOptions = {}): PermissionNode[] {
  const byKey = new Map(items.map(item => [item.key, {
    ...item,
    menus: navigationItems.filter(menu => menu.permissions.some(key => key === item.key)).map(menu => menu.label),
    locked: options.lockedPermissions?.includes(item.key) ?? false,
  }]))
  const placed = new Set<string>()
  const groups = new Map<string, PermissionNode>()
  const leaf = (key: string, title: string, permissions: MenuPermission[]): PermissionNode => ({
    key, title, permissions, disableCheckbox: permissions.every(permission => permission.locked),
  })

  for (const menu of navigationItems) {
    const permissions = menu.permissions.flatMap(key => {
      const item = byKey.get(key)
      if (!item) return []
      placed.add(key)
      return [item]
    })
    if (!permissions.length) continue
    let group = groups.get(menu.group)
    if (!group) {
      group = { key: `group:${menu.group}`, title: menu.group, permissions: [], children: [] }
      groups.set(menu.group, group)
    }
    group.children!.push(leaf(`menu:${menu.path}`, menu.label, permissions))
  }

  const remaining = [...byKey.values()].filter(item => !placed.has(item.key))
  if (remaining.length) groups.set('other', {
    key: 'group:other', title: '其他权限', permissions: [],
    children: remaining.map(item => leaf(`menu:other:${item.key}`, item.name, [item])),
  })
  return [...groups.values()].map(group => {
    const permissions = [...new Map(group.children!.flatMap(node => node.permissions).map(item => [item.key, item])).values()]
    return { ...group, permissions, disableCheckbox: permissions.every(permission => permission.locked) }
  })
}

export function permissionNodes(nodes: readonly PermissionNode[]): PermissionNode[] {
  return nodes.flatMap(node => [node, ...permissionNodes(node.children ?? [])])
}

export function expandedPermissionKeys(nodes: readonly PermissionNode[]): string[] {
  return nodes.filter(node => node.children?.length).map(node => node.key)
}

export function permissionSelectionState(nodes: readonly PermissionNode[], value: readonly string[]): { checkedKeys: string[]; halfCheckedKeys: string[] } {
  const selected = new Set(value)
  const checkedKeys: string[] = [], halfCheckedKeys: string[] = []
  for (const node of permissionNodes(nodes)) {
    const count = node.permissions.filter(permission => selected.has(permission.key)).length
    if (count && count === node.permissions.length) checkedKeys.push(node.key)
    else if (count) halfCheckedKeys.push(node.key)
  }
  return { checkedKeys, halfCheckedKeys }
}

export function changePermissionSelection(nodes: readonly PermissionNode[], value: readonly string[], key: string, checked: boolean): string[] {
  const target = permissionNodes(nodes).find(node => node.key === key)
  if (!target || target.disableCheckbox) return [...value]
  const next = new Set(value)
  // Apply only this menu/group's keys; preserve partial grants in other menus.
  for (const permission of target.permissions) {
    if (permission.locked) continue
    if (checked) next.add(permission.key)
    else next.delete(permission.key)
  }
  return [...next]
}
