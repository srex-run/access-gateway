import { existsSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { isDeepStrictEqual } from 'node:util'

function installedJSON(path) {
  try { return JSON.parse(readFileSync(path, 'utf8')) }
  catch (error) {
    if (error.code === 'ENOENT' || error instanceof SyntaxError) return null
    throw error
  }
}

// npm writes this lockfile after installing. Compare its package records with
// the committed lockfile, then check the actual files to catch partial installs.
// Optional packages for other operating systems need not be installed.
export function frontendDependencyIssue(directory) {
  const manifest = JSON.parse(readFileSync(resolve(directory, 'package.json'), 'utf8'))
  const lock = JSON.parse(readFileSync(resolve(directory, 'package-lock.json'), 'utf8'))
  const specifications = value => ({ ...value?.dependencies, ...value?.devDependencies })
  const direct = specifications(manifest)
  if (!isDeepStrictEqual(direct, specifications(lock.packages?.['']))) {
    return 'package.json differs from package-lock.json'
  }
  const installed = installedJSON(resolve(directory, 'node_modules/.package-lock.json'))
  if (!installed?.packages) return 'missing installation metadata'
  const required = new Set(Object.keys(direct).map(name => `node_modules/${name}`))
  for (const [path, expected] of Object.entries(lock.packages)) {
    if (!path) continue
    const actual = installed.packages[path]
    if (!actual && expected.optional && !required.has(path)) continue
    if (!actual) return `missing ${path}`
    if (['version', 'resolved', 'integrity'].some(key => actual[key] !== expected[key])) {
      return `outdated ${path}`
    }
    const packageJSON = installedJSON(resolve(directory, path, 'package.json'))
    if (!packageJSON || packageJSON.version !== expected.version) return `missing or outdated ${path}`
  }
  if (Object.keys(installed.packages).some(path => !lock.packages[path])) {
    return 'installed packages differ from package-lock.json'
  }
  if (!existsSync(resolve(directory, 'node_modules/vite/bin/vite.js'))) return 'missing Vite executable'
  return null
}
