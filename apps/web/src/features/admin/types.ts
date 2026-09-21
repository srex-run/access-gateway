import type { ResourceStatus, RiskLevel } from '@/features/catalog'
import type { AssetAuditInput } from './asset-form-model'
export interface AssetInput { region_id?: string; name: string; asset_type: string; target: string; risk_level: RiskLevel; max_ttl_seconds: number; status: ResourceStatus; audit?: AssetAuditInput; approval_workflow_id?: string }
export type AssetUpdateInput = Partial<Pick<AssetInput, 'name' | 'asset_type' | 'target' | 'risk_level' | 'max_ttl_seconds' | 'audit' | 'approval_workflow_id'>>
export interface RoleAssignment { id: string; user_id: string; role: string; granted_by: string; created_at: string; revoked_at?: string }
export interface CreatedResource { id: string }
