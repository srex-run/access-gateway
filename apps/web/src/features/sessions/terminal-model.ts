export const terminalClients = {
  ssh: { name: 'SSH', client: 'SSH shell', database: undefined },
  mysql: { name: 'MySQL', client: 'mariadb / mysql', database: '' },
  postgresql: { name: 'PostgreSQL', client: 'psql', database: 'postgres' },
  redis: { name: 'Redis', client: 'redis-cli', database: '0' },
  mongodb: { name: 'MongoDB', client: 'mongosh', database: 'test' },
  http: { name: 'HTTP', client: 'HTTP 请求终端', database: undefined },
} as const

export type TerminalProtocol = keyof typeof terminalClients

export function terminalProtocol(protocol?: string): TerminalProtocol | undefined {
  return protocol && Object.hasOwn(terminalClients, protocol) ? protocol as TerminalProtocol : undefined
}

export function validTerminalDatabase(protocol: TerminalProtocol, database: string, authSource: string) {
  if (database.length > 128 || !/^[a-zA-Z0-9_.-]*$/.test(database)) return false
  if (protocol === 'redis' && database && (!/^\d+$/.test(database) || Number(database) > 2147483647)) return false
  return protocol !== 'mongodb' || (authSource.length <= 128 && /^[a-zA-Z0-9_.-]*$/.test(authSource))
}
