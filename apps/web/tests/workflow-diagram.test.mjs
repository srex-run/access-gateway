import assert from 'node:assert/strict'
import { after, before, test } from 'node:test'
import { mkdtemp, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { pathToFileURL } from 'node:url'
import { build } from 'vite'

let directory, render
before(async () => {
  directory = await mkdtemp(path.join(tmpdir(), 'workflow-diagram-'))
  const entry = path.join(directory, 'fixture.tsx')
  await writeFile(entry, `
    import { renderToStaticMarkup } from 'react-dom/server'
    import { WorkflowDiagram } from '@/features/governance/workflow-diagram'
    export function render(steps) { return renderToStaticMarkup(<WorkflowDiagram steps={steps} onStepSelect={() => {}} />) }
  `)
  await symlink(path.resolve('node_modules'), path.join(directory, 'node_modules'))
  await build({ configFile: false, logLevel: 'silent', resolve: { alias: { '@': path.resolve('src') } }, build: { ssr: entry, outDir: path.join(directory, 'dist'), emptyOutDir: true } })
  ;({ render } = await import(pathToFileURL(path.join(directory, 'dist/fixture.js')).href))
})
after(async () => { if (directory) await rm(directory, { recursive: true, force: true }) })

test('preview shows submission, configured approvals and the end node in order', () => {
  const markup = render([{ name: '数据负责人', kind: 'owners', mode: 'all', selector: '' }, { name: '平台审批', kind: 'role_selector', mode: 'any', selector: 'duty=ops' }])
  const nodes = ['提交申请', '数据负责人', '平台审批', '审批结束']
  for (const name of nodes) assert.ok(markup.includes(name), name)
  for (let index = 1; index < nodes.length; index++) assert.ok(markup.indexOf(nodes[index - 1]) < markup.indexOf(nodes[index]))
  assert.doesNotMatch(markup, /提交访问申请|开通资产访问|申请被拒绝|申请过期|申请取消|全员通过|任一人通过|duty=ops/)
  assert.equal([...markup.matchAll(/class="workflow-diagram-step-link"/g)].length, 2)
})

test('node names and order follow the draft and unnamed nodes remain visible', () => {
  const markup = render([{ name: '安全审核', kind: 'user_selector', mode: 'all', selector: 'team=security' }, { name: '', kind: 'owners', mode: 'any', selector: '' }])
  assert.match(markup, /安全审核/)
  assert.match(markup, /未命名审批节点/)
  assert.ok(markup.indexOf('安全审核') < markup.indexOf('未命名审批节点'))
  assert.doesNotMatch(markup, /平台审批|匹配用户标签|team=security/)
})
