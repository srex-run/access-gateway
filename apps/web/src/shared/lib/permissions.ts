export type Permission = 'directory:read' | 'request:manage' | 'approval:manage' | 'session:manage' | 'catalog:manage' | 'audit:read' | 'session:override' | 'role:manage' | 'user:read' | 'user:manage' | 'workflow:manage'

export function hasPermission(granted: readonly Permission[], required: Permission | Permission[]) {
  return (Array.isArray(required) ? required : [required]).some(permission => granted.includes(permission))
}
