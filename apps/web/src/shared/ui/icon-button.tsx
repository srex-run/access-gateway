import { Button, Tooltip } from '@arco-design/web-react'
import type { ReactNode } from 'react'

interface IconButtonProps { label: string; icon: ReactNode; onClick?: () => void; loading?: boolean; disabled?: boolean; htmlType?: 'button' | 'submit' | 'reset' }
export function IconButton({ label, icon, onClick, loading, disabled, htmlType = 'button' }: IconButtonProps) {
  return <Tooltip content={label}><Button className="icon-button" aria-label={label} icon={icon} onClick={onClick} loading={loading} disabled={disabled} htmlType={htmlType} /></Tooltip>
}
