import type { Session, SessionRecordDetail } from './types'

export function connectionAddress(session: Session) {
  const endpoint = session.gateway_endpoint?.match(/^(?:\[([^\]]+)\]|([^:]+)):(\d+)$/)
  const host = session.gateway_host || endpoint?.[1] || endpoint?.[2]
  const port = session.gateway_port || (endpoint ? Number(endpoint[3]) : 0)
  if (!host || !Number.isInteger(port) || port < 1 || port > 65535) return null
  return { host, port, endpoint: `${host.includes(':') ? `[${host}]` : host}:${port}` }
}

function shellArgument(value: string) {
  return /^[a-zA-Z0-9_./:@+-]+$/.test(value) ? value : `'${value.replaceAll("'", "'\\''")}'`
}

export function connectionCommand(value: SessionRecordDetail): string | null {
  const { session } = value
  const address = connectionAddress(session)
  if (!address || !session.can_connect || session.status !== 'running' || !['native', 'audit'].includes(session.connection_mode)) return null
  const protocol = (session.audit_policy?.protocol || value.asset_type || value.evidence.context?.protocols[0] || '').toLowerCase()
  const host = shellArgument(address.host)
  const user = shellArgument(session.target_account || value.target_account || 'YOUR_USERNAME')
  const port = address.port
  const audit = session.connection_mode === 'audit'
  const ca = shellArgument(`./agent-${session.id}-ca.pem`)
  const knownHosts = shellArgument(`./agent-${session.id}.known_hosts`)
  if (audit && !session.audit_trust) return null
  switch (protocol) {
    case 'mysql': return `mysql --protocol=TCP -h ${host} -P ${port} --user=${user} -p ${audit ? `--ssl-mode=VERIFY_IDENTITY --ssl-ca=${ca}` : '--ssl-mode=REQUIRED'}`
    case 'postgres':
    case 'postgresql': return `PGSSLMODE=${audit ? `verify-full PGSSLROOTCERT=${ca}` : 'require'} psql --host=${host} --port=${port} --username=${user} --dbname=YOUR_DATABASE`
    case 'redis': return `redis-cli --tls -h ${host} -p ${port}${audit ? ` --cacert ${ca} --user ${user} --askpass` : ''}`
    case 'mongo':
    case 'mongodb': return `mongosh --host=${host} --port=${port} --tls${audit ? ` --tlsCAFile=${ca} --username=${user}` : ''}`
    case 'ssh':
    case 'sshd': return `ssh${audit ? ` -o UserKnownHostsFile=${knownHosts} -o StrictHostKeyChecking=yes` : ''} -p ${port} -l ${user} -- ${host}`
    case 'http':
    case 'https': return `curl${audit ? ` --cacert ${ca}` : ''} ${shellArgument(`https://${address.endpoint}/`)}`
    default: return null
  }
}
