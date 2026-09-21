import type { Step } from './types'
import './workflow-diagram.css'

interface WorkflowDiagramProps {
  steps: readonly Step[]
  title?: string
  onStepSelect?: (index: number) => void
}

export function WorkflowDiagram({ steps, title = '审批流程预览', onStepSelect }: WorkflowDiagramProps) {
  return <section className="workflow-diagram" aria-label={title}>
    <strong>{title}</strong>
    <ol className="workflow-diagram-steps">
      <li><div className="workflow-diagram-node"><strong>提交申请</strong></div></li>
      {steps.map((step, index) => <li key={index}>
        <span className="workflow-diagram-arrow" aria-hidden="true">→</span>
        <div className="workflow-diagram-node">
          {onStepSelect ? <button type="button" className="workflow-diagram-step-link" onClick={() => onStepSelect(index)}>{step.name.trim() || '未命名审批节点'}</button> : <strong>{step.name.trim() || '未命名审批节点'}</strong>}
        </div>
      </li>)}
      {!steps.length && <li><span className="workflow-diagram-arrow" aria-hidden="true">→</span><div className="workflow-diagram-node">请添加审批节点</div></li>}
      <li><span className="workflow-diagram-arrow" aria-hidden="true">→</span><div className="workflow-diagram-node"><strong>审批结束</strong></div></li>
    </ol>
  </section>
}
