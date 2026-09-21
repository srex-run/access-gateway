import { spawn } from 'node:child_process'
import { mkdirSync } from 'node:fs'
import { createServer } from 'node:net'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { setTimeout as delay } from 'node:timers/promises'
import { developmentConfig, loadDevelopmentEnvironment } from './dev-config.mjs'
import { frontendDependencyIssue } from './dev-dependencies.mjs'

const root = fileURLToPath(new URL('..', import.meta.url))
const children = new Map()
let stopping = false
let killTimer

function signalChild(child, signal) {
  if (!child.pid) return
  try {
    if (children.get(child)) process.kill(-child.pid, signal)
    else child.kill(signal)
  } catch (error) {
    if (error.code !== 'ESRCH') console.error(`Could not stop child process: ${error.code}`)
  }
}

function stop(code = 0) {
  if (stopping) return
  stopping = true
  process.exitCode = code
  for (const child of children.keys()) signalChild(child, 'SIGTERM')
  killTimer = setTimeout(() => {
    for (const child of children.keys()) signalChild(child, 'SIGKILL')
  }, 12_000)
  killTimer.unref()
}

function launch(command, args, env, cwd = root, detached = process.platform !== 'win32') {
  if (stopping) throw new Error('Development startup was cancelled.')
  const child = spawn(command, args, { cwd, env, stdio: 'inherit', detached })
  children.set(child, detached)
  return new Promise((resolveDone, reject) => {
    child.once('error', error => {
      children.delete(child)
      reject(new Error(`Could not start ${command}: ${error.code}`))
    })
    child.once('close', (code, signal) => {
      children.delete(child)
      if (children.size === 0) clearTimeout(killTimer)
      if (code === 0 || stopping) resolveDone()
      else reject(new Error(`${command} exited with ${signal || `status ${code}`}.`))
    })
  })
}

async function assertPortAvailable(port, host = '127.0.0.1') {
  await new Promise((resolveCheck, reject) => {
    const server = createServer()
    server.once('error', error => reject(new Error(`Port ${port} is unavailable (${error.code}). Check HTTP_ADDR, PUBLIC_URL and DEV_WEB_PORT in .env.`)))
    server.listen(port, host, () => server.close(resolveCheck))
  })
}

async function waitForAPI(url) {
  for (let attempt = 0; attempt < 40 && !stopping; attempt++) {
    try {
      const response = await fetch(`${url}/readyz`, { signal: AbortSignal.timeout(1000) })
      if (response.ok) return
    } catch { /* The API may still be connecting to PostgreSQL. */ }
    await delay(500)
  }
  throw new Error('API did not become ready. Check the backend output and DATABASE_URL.')
}

async function initializeInstallation(env) {
  const directory = resolve(root, 'var/dev-secrets')
  const bootstrapEnv = {
    ...env,
    BOOTSTRAP_ADMIN_USERNAME: env.BOOTSTRAP_ADMIN_USERNAME || 'admin',
    BOOTSTRAP_ADMIN_NICKNAME: env.BOOTSTRAP_ADMIN_NICKNAME || 'Administrator',
    BOOTSTRAP_ADMIN_PASSWORD_FILE: env.BOOTSTRAP_ADMIN_PASSWORD_FILE || resolve(directory, 'initial-admin-password'),
  }
  if (!env.BOOTSTRAP_ADMIN_PASSWORD_FILE) mkdirSync(directory, { recursive: true, mode: 0o700 })
  console.log('Checking first-time administrator initialization...')
  await launch('go', ['run', './cmd/account', 'bootstrap'], bootstrapEnv)
}

async function main() {
  const env = loadDevelopmentEnvironment(root)
  const mode = process.argv[2]
  if (mode === '--migrate' || mode === '--migrate-status') {
    await launch('go', ['run', './cmd/migrate', mode === '--migrate' ? 'up' : 'status'], env)
    return
  }
  if (mode === '--initialize') {
    await initializeInstallation(env)
    return
  }
  if (mode === '--account') {
    // Password entry needs the invoking terminal's foreground process group.
    await launch('go', ['run', './cmd/account', ...process.argv.slice(3)], env, root, false)
    return
  }
  if (mode && mode !== '--check') throw new Error(`Unknown option: ${mode}`)
  const config = developmentConfig(env)
  const webDirectory = resolve(root, 'apps/web')
  const vite = resolve(webDirectory, 'node_modules/vite/bin/vite.js')
  const dependencyIssue = frontendDependencyIssue(webDirectory)
  if (mode === '--check') {
    console.log(`.env parsed. API: ${config.apiURL}; Web: ${config.webURL}`)
    console.log(`Frontend dependencies: ${dependencyIssue ? `${dependencyIssue}; make dev will install them` : 'up to date'}`)
    return
  }
  await assertPortAvailable(config.apiPort)
  await assertPortAvailable(config.webPort, config.webHost)
  if (dependencyIssue) {
    console.log(`Installing frontend dependencies: ${dependencyIssue}...`)
    await launch('npm', ['ci', '--ignore-scripts', '--no-audit', '--no-fund'], env, webDirectory)
    const remainingIssue = frontendDependencyIssue(webDirectory)
    if (remainingIssue) throw new Error(`Frontend dependency installation is incomplete: ${remainingIssue}`)
  }
  mkdirSync(resolve(root, 'bin/dev'), { recursive: true })
  const binary = resolve(root, `bin/dev/access-gateway${process.platform === 'win32' ? '.exe' : ''}`)
  if (config.env.GATEWAY_RUNTIME === 'local' && !config.env.SESSION_AGENT_BINARY) {
    const agentBinary = resolve(root, 'bin/dev/gateway-agent')
    console.log('Building the session agent...')
    await launch('go', ['build', '-o', agentBinary, './cmd/gateway-agent'], config.env)
    config.env.SESSION_AGENT_BINARY = agentBinary
  }
  console.log('Building the API...')
  await launch('go', ['build', '-o', binary, './cmd/access-gateway'], config.env)
  console.log('Applying pending database migrations...')
  await launch('go', ['run', './cmd/migrate', 'up'], config.env)
  await initializeInstallation(config.env)
  if (stopping) return
  // Run the compiled binary directly so Ctrl+C terminates the actual server.
  const apiDone = launch(binary, [], config.env).then(() => {
    if (!stopping) { console.error('API exited unexpectedly.'); stop(1) }
  }, error => { console.error(error.message); stop(1) })
  await waitForAPI(config.apiURL)
  if (stopping) return
  const webDone = launch(process.execPath, [vite, '--host', config.webHost, '--port', String(config.webPort), '--strictPort'], config.env, resolve(root, 'apps/web'))
    .then(() => {
      if (!stopping) { console.error('Vite exited unexpectedly.'); stop(1) }
    }, error => { console.error(error.message); stop(1) })
  console.log(`API ready: ${config.apiURL}\nFrontend starting: ${config.webURL}\nCtrl+C stops both processes.`)
  console.log('Go backend changes require restarting make dev; Vite only reloads frontend changes.')
  await Promise.all([apiDone, webDone])
}

process.once('SIGINT', () => stop())
process.once('SIGTERM', () => stop())
main().catch(error => {
  if (!stopping) { console.error(error.message); stop(1) }
})
