export function developmentWebConfig(env) {
  const configured = env.PUBLIC_URL?.trim().replace(/\/+$/, '')
  let origin
  if (configured) {
    try { origin = new URL(configured) } catch { throw new Error('PUBLIC_URL must be an HTTP or HTTPS origin.') }
    if (!/^https?:$/.test(origin.protocol) || origin.username || origin.password || origin.pathname !== '/' || origin.search || origin.hash || /[?#\\\s]/.test(configured) || ['0.0.0.0', '[::]'].includes(origin.hostname)) {
      throw new Error('PUBLIC_URL must be an HTTP or HTTPS origin without credentials, path, query or fragment.')
    }
  }
  const loopback = origin && ['localhost', '127.0.0.1', '[::1]'].includes(origin.hostname)
  const direct = loopback && origin.protocol === 'http:'
  const rawPort = env.DEV_WEB_PORT || (direct ? origin.port || '80' : '9527')
  const port = Number(rawPort)
  if (!/^\d+$/.test(String(rawPort)) || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error('DEV_WEB_PORT must be between 1 and 65535.')
  if (direct && port !== Number(origin.port || '80')) throw new Error('DEV_WEB_PORT must match the local HTTP port in PUBLIC_URL.')
  return {
    port,
    host: loopback && origin.hostname === '[::1]' ? '::1' : '127.0.0.1',
    publicURL: origin ? configured : `http://127.0.0.1:${port}`,
    allowedHosts: origin && !loopback ? [origin.hostname] : [],
  }
}
