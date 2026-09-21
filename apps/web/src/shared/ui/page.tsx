import { Alert, Breadcrumb, Button, Result, Space, Spin, Typography } from '@arco-design/web-react'
import type { ReactNode } from 'react'
import { describeError } from '@/shared/api/client'

export interface PageHeaderProps {
  title: string
  breadcrumb?: ReactNode
  actions?: ReactNode
}

export function PageHeader({ title, breadcrumb, actions }: PageHeaderProps) {
  return <header className="page-header">
    <nav className="page-breadcrumb" aria-label="面包屑">
      <Breadcrumb separator="/">
        {breadcrumb && <Breadcrumb.Item>{breadcrumb}</Breadcrumb.Item>}
        <Breadcrumb.Item><h1 aria-current="page">{title}</h1></Breadcrumb.Item>
      </Breadcrumb>
    </nav>
    {actions && <Space wrap>{actions}</Space>}
  </header>
}

interface PageBodyProps { children: ReactNode; narrow?: boolean }
export function PageBody({ children, narrow = false }: PageBodyProps) {
  return <section className={`page-body${narrow ? ' page-body--narrow' : ''}`}>{children}</section>
}

interface ErrorNoticeProps { error: unknown; retry?: () => void }
export function ErrorNotice({ error, retry }: ErrorNoticeProps) {
  if (!error) return null
  return <Alert type="error" content={describeError(error)} action={retry && <Button size="small" onClick={retry}>重试</Button>} />
}

interface QueryStateProps extends ErrorNoticeProps { loading: boolean; children: ReactNode }
export function QueryState({ loading, error, retry, children }: QueryStateProps) {
  if (loading) return <output className="loading-state" aria-label="正在加载"><Spin /></output>
  if (error) return <ErrorNotice error={error} retry={retry} />
  return <>{children}</>
}

interface EmptyResultProps { title: string; children?: ReactNode; status?: '403' | '404' | 'error' }
export function EmptyResult({ title, children, status = '404' }: EmptyResultProps) {
  return <Result status={status} title={title} extra={children} />
}

interface DetailListProps { items: { label: string; value: ReactNode }[] }
export function DetailList({ items }: DetailListProps) {
  return <dl className="detail-list">{items.map(item => <div key={item.label}><dt>{item.label}</dt><dd>{item.value ?? '-'}</dd></div>)}</dl>
}

interface SectionTitleProps { children: ReactNode; extra?: ReactNode }
export function SectionTitle({ children, extra }: SectionTitleProps) {
  return <div className="section-title"><Typography.Title heading={6}>{children}</Typography.Title>{extra}</div>
}
