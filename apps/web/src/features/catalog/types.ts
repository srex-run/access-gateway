export type ResourceStatus = 'enabled' | 'disabled' | 'maintenance'
export type RiskLevel = 'normal' | 'sensitive' | 'critical'
export interface Region { id: string; code: string; name: string; status: ResourceStatus }
export interface Asset {
  id: string
  approval_workflow_id?: string
  region_id: string
  name: string
  asset_type: string
  risk_level: RiskLevel
  max_ttl_seconds: number
  status: ResourceStatus
  external_source?: string
  external_id?: string
  last_synced_at?: string
}
export interface AssetPort { id: string; asset_id: string; port: number; protocol: string; target_account_required?: boolean }
