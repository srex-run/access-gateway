import { CatalogWorkspace } from '@/features/catalog'
import { PageBody, PageHeader } from '@/shared/ui/page'
export default function CatalogPage() {
  return <><PageHeader title="资产目录" breadcrumb="访问管理" /><PageBody><CatalogWorkspace /></PageBody></>
}
