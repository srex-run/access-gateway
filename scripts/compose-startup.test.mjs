import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { after, test } from 'node:test'
import { fileURLToPath } from 'node:url'

const repository = fileURLToPath(new URL('..', import.meta.url))
const workspace = realpathSync(mkdtempSync(join(tmpdir(), 'access-gateway-compose-')))
after(() => rmSync(workspace, { recursive: true, force: true }))
copyFileSync(join(repository, 'docker-compose.yml'), join(workspace, 'docker-compose.yml'))
const environment = Object.fromEntries(['PATH', 'HOME', 'TMPDIR'].filter(key => process.env[key]).map(key => [key, process.env[key]]))
writeFileSync(join(workspace, '.env'), [
  readFileSync(join(repository, '.env.example'), 'utf8'),
  'ACCESS_GATEWAY_IMAGE=example/access-gateway:startup-test',
  'PUBLIC_URL=https://gateway.example.test',
  `ACCESS_GATEWAY_SECRETS_HOST_PATH=${workspace}/secrets`,
  `SESSION_AGENT_STATE_HOST_PATH=${workspace}/sessions`,
  'DOCKER_SOCKET_GID=999',
].join('\n'))

function render(overrides = {}) {
  const args = ['compose', '--env-file', join(workspace, '.env')]
  const result = spawnSync('docker', [...args, 'config', '--format', 'json'], { cwd: workspace, env: { ...environment, ...overrides }, encoding: 'utf8' })
  assert.equal(result.status, 0, result.stderr || result.error?.message)
  return JSON.parse(result.stdout)
}

const production = render()
// Compose config escapes literal dollars so its output can be parsed again.
const preparationScript = production.services.prepare.command[0].replaceAll('$$', '$')
const encryptionKey = 'initial-test-encryption-key-with-at-least-32-bytes'
const databasePassword = 'test p@ss:/#%?\\ with quote\' and literal $() `text`'

function fixture(t) {
  const directory = mkdtempSync(join(workspace, 'prepare-'))
  const secrets = join(directory, 'secrets')
  const sessions = join(directory, 'sessions')
  const helpers = join(directory, 'helpers')
  mkdirSync(helpers)
  // Verify the privileged commands' arguments without changing the test user's
  // file ownership or flushing unrelated host filesystems. No Docker daemon runs.
  writeFileSync(join(helpers, 'chown'), '#!/bin/sh\n[ "$1" = "65532:65532" ]\n', { mode: 0o700 })
  writeFileSync(join(helpers, 'sync'), '#!/bin/sh\n[ "$#" -eq 0 ]\n', { mode: 0o700 })
  const script = preparationScript.replaceAll('/run/secrets/access-gateway', secrets).replaceAll('/var/lib/access-gateway/sessions', sessions)
  t.after(() => rmSync(directory, { recursive: true, force: true }))
  return {
    secrets, sessions, helpers,
    read: name => readFileSync(join(secrets, name), 'utf8').trimEnd(),
    run: (overrides = {}) => spawnSync('/bin/sh', ['-ec', script], {
      env: {
        ...environment, PATH: `${helpers}:${environment.PATH}`,
        ...production.services.prepare.environment,
        ENCRYPTION_KEY: encryptionKey, POSTGRES_PASSWORD: databasePassword,
        ...overrides,
      },
      encoding: 'utf8', timeout: 10_000,
    }),
  }
}

test('production waits for prepared files, healthy PostgreSQL and completed migrations and initialization', () => {
  const { prepare, postgres, migrate, initialize, 'access-gateway': app } = production.services
  assert.equal(prepare.network_mode, 'none')
  assert.equal(prepare.environment.DATABASE_URL, undefined)
  assert.equal(app.environment.GATEWAY_RUNTIME, 'docker')
  assert.equal(app.environment.SESSION_AGENT_IMAGE, app.image)
  assert.equal(postgres.depends_on.prepare.condition, 'service_completed_successfully')
  assert.equal(migrate.depends_on.postgres.condition, 'service_healthy')
  assert.equal(initialize.depends_on.migrate.condition, 'service_completed_successfully')
  assert.equal(app.depends_on.initialize.condition, 'service_completed_successfully')
  assert.equal(postgres.ports, undefined)
  assert.equal(production.networks.database.internal, true)
  assert.equal(production.networks.database.driver, 'bridge')
  assert.equal(production.networks.database.ipam.config[0].subnet, '172.29.0.0/24')
  assert.equal(postgres.networks.database.ipv4_address, '172.29.0.10')
  assert.equal(app.network_mode, 'host')
  assert.deepEqual(app.extra_hosts, ['postgres=172.29.0.10'])
  for (const service of [migrate, initialize]) {
    assert.equal(service.network_mode, undefined)
    assert.deepEqual(Object.keys(service.networks), ['database'])
  }
  const databaseMount = postgres.volumes.find(volume => volume.target === '/var/lib/postgresql/data')
  assert.equal(databaseMount.type, 'bind')
  assert.equal(databaseMount.source, join(workspace, 'data', 'postgres'))
  assert.equal(databaseMount.bind.create_host_path, true)
  for (const service of [migrate, initialize, app]) {
    assert.equal(service.image, 'example/access-gateway:startup-test')
    assert.equal(service.environment.DATABASE_URL, '')
    assert.equal(service.environment.ENCRYPTION_KEY, '')
    assert.equal(service.environment.DATABASE_URL_FILE, '/run/secrets/access-gateway/database-url')
  }
  assert.equal(spawnSync('/bin/sh', ['-n'], { input: preparationScript }).status, 0)
})

test('custom database storage and subnet settings reach the PostgreSQL container and host controller', () => {
  const dataDirectory = join(workspace, 'custom-postgres-data')
  const config = render({ POSTGRES_NETWORK_PREFIX: '192.168.240', POSTGRES_DATA_HOST_PATH: dataDirectory })
  assert.equal(config.networks.database.ipam.config[0].subnet, '192.168.240.0/24')
  assert.equal(config.services.postgres.networks.database.ipv4_address, '192.168.240.10')
  assert.deepEqual(config.services['access-gateway'].extra_hosts, ['postgres=192.168.240.10'])
  const databaseMount = config.services.postgres.volumes.find(volume => volume.target === '/var/lib/postgresql/data')
  assert.equal(databaseMount.type, 'bind')
  assert.equal(databaseMount.source, dataDirectory)
})

test('database readiness rejects wrong passwords and missing secrets even when PostgreSQL accepts connections', t => {
  const setup = fixture(t)
  assert.equal(setup.run().status, 0)
  // Model a running PostgreSQL server whose loopback rule trusts callers but
  // whose bridge connections require the stored database role's password.
  writeFileSync(join(setup.helpers, 'pg_isready'), '#!/bin/sh\nexit 0\n', { mode: 0o700 })
  writeFileSync(join(setup.helpers, 'psql'), `#!${process.execPath}
const args = process.argv.slice(2)
const option = name => args[args.indexOf(name) + 1]
if (option('-h') === '127.0.0.1') process.exit(0)
if (option('-h') !== 'postgres' || option('-U') !== 'access_gateway' || option('-d') !== 'access_gateway' || option('-c') !== 'SELECT 1') process.exit(3)
process.exit(process.env.PGPASSWORD === process.env.TEST_DATABASE_PASSWORD ? 0 : 2)
`, { mode: 0o700 })
  const [kind, command] = production.services.postgres.healthcheck.test
  assert.equal(kind, 'CMD-SHELL')
  const check = expectedPassword => spawnSync('/bin/sh', ['-c', command.replaceAll('$$', '$')], {
    env: {
      ...environment, ...production.services.postgres.environment,
      PATH: `${setup.helpers}:${environment.PATH}`,
      POSTGRES_PASSWORD_FILE: join(setup.secrets, 'postgres-password'),
      TEST_DATABASE_PASSWORD: expectedPassword,
    },
    encoding: 'utf8', timeout: 5000,
  })
  assert.equal(check(databasePassword).status, 0)
  const wrongPassword = check('old-database-role-password')
  assert.equal(wrongPassword.status, 2)
  assert.ok(!wrongPassword.stdout.includes(databasePassword) && !wrongPassword.stderr.includes(databasePassword))
  rmSync(join(setup.secrets, 'postgres-password'))
  assert.notEqual(check(databasePassword).status, 0)
  writeFileSync(join(setup.secrets, 'postgres-password'), '', { mode: 0o400 })
  assert.notEqual(check('').status, 0)
})

test('first startup creates private files and safely encodes database credentials', t => {
  const setup = fixture(t)
  const result = setup.run()
  assert.equal(result.status, 0, result.stderr)
  assert.equal(setup.read('encryption-key'), encryptionKey)
  assert.equal(setup.read('postgres-password'), databasePassword)
  assert.match(setup.read('metrics-bearer-token'), /^[0-9a-f]{64}$/)
  const connection = new URL(setup.read('database-url'))
  assert.equal(decodeURIComponent(connection.password), databasePassword)
  assert.equal(decodeURIComponent(connection.username), 'access_gateway')
  assert.equal(decodeURIComponent(connection.pathname), '/access_gateway')
  assert.equal(connection.host, 'postgres:5432')
  for (const name of readdirSync(setup.secrets)) assert.equal(statSync(join(setup.secrets, name)).mode & 0o777, 0o400)
  for (const directory of [setup.secrets, setup.sessions]) assert.equal(statSync(directory).mode & 0o777, 0o700)
  assert.ok(!result.stdout.includes(encryptionKey) && !result.stdout.includes(databasePassword))
})

test('restarts preserve secrets and replace stale database URLs with the bundled database connection', t => {
  const setup = fixture(t)
  assert.equal(setup.run().status, 0)
  const originalToken = setup.read('metrics-bearer-token')
  const staleConnection = 'postgres://old-user:old-password@127.0.0.1:15432/old-database?sslmode=disable'
  rmSync(join(setup.secrets, 'database-url'))
  writeFileSync(join(setup.secrets, 'database-url'), staleConnection, { mode: 0o400 })
  const result = setup.run({ ENCRYPTION_KEY: '', POSTGRES_PASSWORD: '', DATABASE_URL: staleConnection })
  assert.equal(result.status, 0, result.stderr)
  assert.equal(setup.read('encryption-key'), encryptionKey)
  assert.equal(setup.read('postgres-password'), databasePassword)
  assert.equal(setup.read('metrics-bearer-token'), originalToken)
  const connection = new URL(setup.read('database-url'))
  assert.equal(connection.host, 'postgres:5432')
  assert.equal(decodeURIComponent(connection.username), 'access_gateway')
  assert.equal(decodeURIComponent(connection.password), databasePassword)
  assert.equal(decodeURIComponent(connection.pathname), '/access_gateway')
  assert.equal(readdirSync(setup.secrets).length, 4)
})

test('changed encryption keys and database passwords fail without overwriting existing secrets', t => {
  const setup = fixture(t)
  assert.equal(setup.run().status, 0)
  const originals = Object.fromEntries(readdirSync(setup.secrets).map(name => [name, setup.read(name)]))
  for (const [name, value] of [['ENCRYPTION_KEY', 'changed-test-encryption-key-with-at-least-32-bytes'], ['POSTGRES_PASSWORD', 'changed-password']]) {
    const result = setup.run({ [name]: value })
    assert.notEqual(result.status, 0)
    assert.match(result.stderr, new RegExp(`${name} differs`))
    assert.ok(!result.stderr.includes(value))
    for (const [filename, contents] of Object.entries(originals)) assert.equal(setup.read(filename), contents)
  }
})

test('missing or short initial encryption keys can be corrected and retried', t => {
  const setup = fixture(t)
  for (const value of ['', 'short']) {
    const result = setup.run({ ENCRYPTION_KEY: value })
    assert.notEqual(result.status, 0)
    assert.match(result.stderr, /ENCRYPTION_KEY/)
    assert.ok(!existsSync(join(setup.secrets, 'encryption-key')))
  }
  const result = setup.run()
  assert.equal(result.status, 0, result.stderr)
})

test('secret symlinks are rejected without changing their targets', t => {
  const setup = fixture(t)
  mkdirSync(setup.secrets, { mode: 0o700 })
  const target = join(setup.secrets, 'original-key')
  writeFileSync(target, encryptionKey, { mode: 0o400 })
  symlinkSync(target, join(setup.secrets, 'encryption-key'))
  assert.notEqual(setup.run().status, 0)
  assert.equal(readFileSync(target, 'utf8'), encryptionKey)
})
