import { ResourceFormPage } from '@/shared/ui/resource-form-page'
import { Link } from 'react-router-dom'
import { BindingForm, RoleCenter, RoleDefinitionForm, WorkflowCenter, WorkflowForm } from '@/features/governance'
import { PageBody, PageHeader } from '@/shared/ui/page'

export function RolesPage() { return <><PageHeader title="角色与权限" breadcrumb="安全管理" /><PageBody><RoleCenter /></PageBody></> }
export function RoleDefinitionPage() { return <ResourceFormPage title="角色配置" breadcrumb={<Link to="/admin/roles">角色与权限</Link>}><RoleDefinitionForm /></ResourceFormPage> }
export function RoleBindingPage() { return <ResourceFormPage title="标签授权绑定" breadcrumb={<Link to="/admin/roles?tab=bindings">角色与权限</Link>}><BindingForm /></ResourceFormPage> }
export function WorkflowsPage() { return <><PageHeader title="审批流程" breadcrumb="平台管理" /><PageBody><WorkflowCenter /></PageBody></> }
export function WorkflowEditPage() { return <ResourceFormPage title="流程配置" breadcrumb={<Link to="/admin/workflows">审批流程</Link>}><WorkflowForm /></ResourceFormPage> }
export function OwnershipPage() { return <ResourceFormPage title="负责人匹配规则" breadcrumb={<Link to="/admin/workflows?tab=owners">审批流程</Link>}><BindingForm ownership /></ResourceFormPage> }
