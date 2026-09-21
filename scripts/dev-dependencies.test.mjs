import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { test } from 'node:test'
import { frontendDependencyIssue } from './dev-dependencies.mjs'

function fixture(t) {
  const directory = mkdtempSync(join(tmpdir(), 'access-gateway-dev-dependencies-'))
  t.after(() => rmSync(directory, { recursive: true, force: true }))
  const write = (path, value) => {
    const destination = join(directory, path)
    mkdirSync(dirname(destination), { recursive: true })
    writeFileSync(destination, JSON.stringify(value))
  }
  const manifest = { dependencies: { vite: '^8.2.0' } }
  const vite = { version: '8.2.0', resolved: 'https://registry.example/vite.tgz', integrity: 'sha512-example' }
  const lock = { lockfileVersion: 3, packages: { '': structuredClone(manifest), 'node_modules/vite': vite } }
  const installed = { lockfileVersion: 3, packages: { 'node_modules/vite': structuredClone(vite) } }
  const save = () => {
    write('package.json', manifest)
    write('package-lock.json', lock)
    write('node_modules/.package-lock.json', installed)
  }
  save()
  write('node_modules/vite/package.json', { name: 'vite', version: '8.2.0' })
  write('node_modules/vite/bin/vite.js', '')
  return { directory, write, manifest, lock, installed, save }
}

test('current installs are reused, including absent optional platform packages', t => {
  const f = fixture(t)
  f.lock.packages['node_modules/platform-binding'] = { version: '1.0.0', optional: true, os: ['other-os'] }
  f.save()
  assert.equal(frontendDependencyIssue(f.directory), null)
})

test('new terminal dependencies require installation even when Vite is present', t => {
  const f = fixture(t)
  f.manifest.dependencies['@xterm/xterm'] = '^6.0.0'
  f.lock.packages[''].dependencies['@xterm/xterm'] = '^6.0.0'
  f.lock.packages['node_modules/@xterm/xterm'] = { version: '6.0.0', integrity: 'sha512-terminal' }
  f.save()
  assert.match(frontendDependencyIssue(f.directory), /missing node_modules\/@xterm\/xterm/)
  f.installed.packages['node_modules/@xterm/xterm'] = structuredClone(f.lock.packages['node_modules/@xterm/xterm'])
  f.write('node_modules/@xterm/xterm/package.json', { name: '@xterm/xterm', version: '6.0.0' })
  f.save()
  assert.equal(frontendDependencyIssue(f.directory), null)
})

test('transitive lockfile changes and leftover packages require installation', t => {
  const f = fixture(t)
  f.lock.packages['node_modules/transitive'] = { version: '1.0.1', integrity: 'sha512-new' }
  f.installed.packages['node_modules/transitive'] = { version: '1.0.0', integrity: 'sha512-old' }
  f.write('node_modules/transitive/package.json', { version: '1.0.0' })
  f.save()
  assert.match(frontendDependencyIssue(f.directory), /outdated node_modules\/transitive/)
  delete f.lock.packages['node_modules/transitive']
  f.save()
  assert.match(frontendDependencyIssue(f.directory), /installed packages differ/)
})

test('partial installs and removed node_modules are detected from actual files', t => {
  const f = fixture(t)
  rmSync(join(f.directory, 'node_modules/vite/bin/vite.js'))
  assert.match(frontendDependencyIssue(f.directory), /missing Vite executable/)
  rmSync(join(f.directory, 'node_modules/vite/package.json'))
  assert.match(frontendDependencyIssue(f.directory), /missing or outdated node_modules\/vite/)
  rmSync(join(f.directory, 'node_modules'), { recursive: true })
  assert.match(frontendDependencyIssue(f.directory), /missing installation metadata/)
})

test('a manifest change without a matching lockfile is reported before startup', t => {
  const f = fixture(t)
  f.manifest.dependencies.vite = '^8.3.0'
  f.save()
  assert.match(frontendDependencyIssue(f.directory), /package.json differs from package-lock.json/)
})

test('corrupt installation metadata requires reinstalling', t => {
  const f = fixture(t)
  writeFileSync(join(f.directory, 'node_modules/.package-lock.json'), '{')
  assert.match(frontendDependencyIssue(f.directory), /missing installation metadata/)
})
