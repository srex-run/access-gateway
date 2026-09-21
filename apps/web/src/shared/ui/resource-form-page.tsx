import type { ReactNode } from 'react'
import { PageBody, PageHeader } from './page'

// All resource forms use the same compact page frame; features supply fields,
// data and mutations through ResourceForm, including its navigation guard.
export function ResourceFormPage({ title, breadcrumb, children }: { title: string; breadcrumb: ReactNode; children: ReactNode }) {
  return <><PageHeader title={title} breadcrumb={breadcrumb} /><PageBody><div className="resource-form-page">{children}</div></PageBody></>
}
