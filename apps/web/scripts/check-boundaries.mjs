import { readdir, readFile } from 'node:fs/promises'
import path from 'node:path'
import ts from 'typescript'

const root = path.resolve('src')
const violations = []
const forbidden = { shared: ['app', 'pages', 'features'], features: ['app', 'pages'], pages: ['app'] }

async function inspect(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const file = path.join(directory, entry.name)
    if (entry.isDirectory()) {
      await inspect(file)
      continue
    }
    if (!/\.tsx?$/.test(file)) continue
    const layer = path.relative(root, file).split(path.sep)[0]
    const source = ts.createSourceFile(file, await readFile(file, 'utf8'), ts.ScriptTarget.Latest, true)
    function visit(node) {
      const specifier = (ts.isImportDeclaration(node) || ts.isExportDeclaration(node))
        ? node.moduleSpecifier
        : ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword
          ? node.arguments[0]
          : undefined
      if (specifier && ts.isStringLiteral(specifier)) {
        const name = specifier.text
        const target = name.startsWith('@/') ? path.join(root, name.slice(2))
          : name.startsWith('.') ? path.resolve(path.dirname(file), name) : undefined
        const targetLayer = target && path.relative(root, target).split(path.sep)[0]
        if (forbidden[layer]?.includes(targetLayer)) {
          violations.push(`${path.relative(root, file)} -> ${name}`)
        }
      }
      ts.forEachChild(node, visit)
    }
    visit(source)
  }
}

await inspect(root)
if (violations.length) {
  console.error(`Invalid layer dependencies:\n${violations.join('\n')}`)
  process.exitCode = 1
} else {
  console.log('Frontend layer boundaries passed.')
}
