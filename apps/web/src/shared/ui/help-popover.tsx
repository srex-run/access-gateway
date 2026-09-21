import { Popover } from '@arco-design/web-react'
import type { MouseEventHandler, ReactNode } from 'react'
import './help-popover.css'

export function HelpPopover({ title, children, onClick }: { title: string; children: ReactNode; onClick?: MouseEventHandler<HTMLButtonElement> }) {
  return <Popover title={title} content={<div className="help-popover-content">{children}</div>} trigger="click" position="bottom">
    <button type="button" className="help-popover-trigger" aria-label={`${title}说明`} onClick={onClick}>?</button>
  </Popover>
}
