import type { Permission } from '@/features/auth'
import type { Labels } from '@/shared/ui/labels'

export interface RoleDefinition { name: string; description: string; permissions: Permission[]; labels: Labels; enabled: boolean; built_in: boolean; revision: number }
export interface RoleGrant { role: RoleDefinition; sources: { kind: 'baseline' | 'direct' | 'binding' | 'bootstrap'; id?: string; name: string; revision?: number; user_selector?: string; role_selector?: string }[] }
export interface RoleBinding { id: string; name: string; user_selector: string; role_selector: string; enabled: boolean; revision: number }
export interface Ownership { id: string; name: string; asset_selector: string; user_selector: string; enabled: boolean; revision: number }
export interface LabelBindingDraft { id: string; name: string; user_selector: string; role_selector?: string; asset_selector?: string; enabled: boolean; revision: number }
export interface Step { name: string; kind: 'owners' | 'user_selector' | 'role_selector'; mode: 'any' | 'all'; selector: string }
export interface Workflow { id: string; name: string; description: string; labels: Labels; asset_selector: string; enabled: boolean; built_in: boolean; revision: number; timeout_seconds: number; steps: Step[] }
export interface AssetLabels { asset_id: string; labels: Labels; revision: number }
export interface WorkflowApproval { id: string; user_id: string; name: string; level: number; required: number; step_name: string; decision: 'approved' | 'rejected' | null; comment: string | null; decided_at: string | null }
export interface WorkflowStage { level: number; name: string; required: number; approved: number; candidates: number; status: 'pending' | 'approved' | 'rejected' | 'waiting' | 'expired' | 'cancelled' | 'skipped' }
export interface WorkflowView { snapshot: { name: string; workflow_id: string; revision: number; steps: { level: number; name: string; kind?: Step['kind']; selector?: string; mode: string; required: number; candidates: { user_id: string; name: string }[] }[] } | null; approvals: WorkflowApproval[]; stages: WorkflowStage[]; current_level: number; expires_at: string | null; status: string; can_decide: boolean; approval_id?: string; decision_reason?: string }
export interface LabelMatch { id: string; name: string; labels: Labels }
export interface LabelMatchPage { items: LabelMatch[]; total: number; limit: number; offset: number }
export interface LabelPreview { users: LabelMatchPage; roles: LabelMatchPage; assets: LabelMatchPage }
