import type { OperationEvent } from './types'

export function operationLabel(value: OperationEvent): string {
  return ({ terminal_output: '终端输出', shell: '交互终端', client: '客户端终端', exec: '命令请求', client_version_probe: 'MySQL 客户端初始化（版本检查）', client_syntax_probe: 'MySQL 客户端初始化（语法探测）' } as Record<string, string>)[value.operation_type] ?? value.operation_type
}

export function operationSummary(value: OperationEvent): string {
  if (['client_version_probe', 'client_syntax_probe'].includes(value.operation_type)) return operationLabel(value)
  return value.normalized_operation || value.object_name || operationLabel(value)
}

export function operationVisible(value: Pick<OperationEvent, 'operation_type'>): boolean {
  return !['client_version_probe', 'client_syntax_probe'].includes(value.operation_type)
}

export function operationText(value: OperationEvent): string {
  if (value.operation_type === 'terminal_output' && value.metadata?.encoding === 'base64' && value.metadata.data) {
    try {
      const bytes = Uint8Array.from(atob(value.metadata.data), char => char.charCodeAt(0))
      // Display terminal bytes as text, never execute terminal escape sequences.
      return new TextDecoder().decode(bytes).replaceAll('\x1b', '␛')
    } catch { /* Retain the safe preview if a legacy event has invalid data. */ }
  }
  return value.normalized_operation || value.object_name || operationLabel(value)
}
