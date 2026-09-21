import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { parseEnv } from 'node:util'
import { developmentWebConfig } from '../apps/web/dev-server.mjs'

export function loadDevelopmentEnvironment(root, inherited = process.env) {
  let contents
  try {
    contents = readFileSync(resolve(root, '.env'), 'utf8')
  } catch (error) {
    if (error.code === 'ENOENT') throw new Error('Missing .env. Create it from .env.example and configure DATABASE_URL.')
    throw error
  }
  return { ...parseEnv(contents), ...inherited }
}

function port(value, name) {
  if (!/^\d+$/.test(String(value))) throw new Error(`${name} must be a port number.`)
  const result = Number(value)
  if (!Number.isInteger(result) || result < 1 || result > 65535) throw new Error(`${name} must be between 1 and 65535.`)
  return result
}

export function developmentConfig(env) {
  if (!env.DATABASE_URL && !env.DATABASE_URL_FILE) throw new Error('Configure DATABASE_URL or DATABASE_URL_FILE in .env.')
  if (env.DATABASE_URL && env.DATABASE_URL_FILE) throw new Error('Configure only one of DATABASE_URL and DATABASE_URL_FILE.')
  const address = env.HTTP_ADDR || '127.0.0.1:8080'
  const match = /^(?:(?:127\.0\.0\.1|localhost|\[::1\])?):(\d+)$/.exec(address)
  if (!match) throw new Error('make dev requires a loopback HTTP_ADDR, such as 127.0.0.1:8080.')
  const apiPort = port(match[1], 'HTTP_ADDR')
  const web = developmentWebConfig(env)
  const webPort = web.port
  if (apiPort === webPort) throw new Error('HTTP_ADDR and DEV_WEB_PORT must use different ports.')
  return {
    apiPort, webPort,
    apiURL: `http://127.0.0.1:${apiPort}`,
    webURL: web.publicURL, webHost: web.host,
    env: { ...env, PUBLIC_URL: web.publicURL, DEV_WEB_PORT: String(webPort), GATEWAY_RUNTIME: env.GATEWAY_RUNTIME || 'local', HTTP_ADDR: `127.0.0.1:${apiPort}`, ACCESS_GATEWAY_UPSTREAM: `http://127.0.0.1:${apiPort}` },
  }
}
