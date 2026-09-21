import { Form, Select } from '@arco-design/web-react'

export const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
export const uuidRules = [{ required: true, match: uuidPattern, message: '请输入有效的 UUID' }]
export const requiredRules = [{ required: true, whitespace: true, message: '此项不能为空' }]
export const statusOptions = [{ value: 'enabled', label: '启用' }, { value: 'disabled', label: '停用' }, { value: 'maintenance', label: '维护' }]
export const assetProtocolOptions = [
  { value: 'mysql', label: 'MySQL' },
  { value: 'postgresql', label: 'PostgreSQL' },
  { value: 'redis', label: 'Redis' },
  { value: 'mongodb', label: 'MongoDB' },
  { value: 'http', label: 'HTTP / HTTPS' },
  { value: 'ssh', label: 'SSH / SSHD' },
]

export function assetProtocolLabel(value: string) {
  return assetProtocolOptions.find(option => option.value === value)?.label ?? value
}

export function StatusField() {
  return <Form.Item label="状态" field="status" rules={requiredRules}><Select options={statusOptions} /></Form.Item>
}
