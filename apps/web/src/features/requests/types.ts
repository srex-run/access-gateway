export type RequestStatus = 'pending_approval' | 'approved' | 'rejected' | 'cancelled' | 'approval_expired'
export interface AccessRequest {

  approval_mode?: 'required' | 'admin_test' | 'demo'
  id: string
  applicant_id: string
  asset_id: string
  target_port: number
  source_ip?: string
  target_account?: string
  reason: string
  ticket_no?: string
  emergency: boolean
  ttl_seconds: number
  status: RequestStatus
  idempotency_key: string
  created_at: string
  updated_at: string
}
export interface CreateRequestInput {
  region_id: string
  asset_id: string
  target_port: number
  source_ip?: string
  target_account?: string
  reason: string
  emergency: boolean
  ttl_seconds: number
}
export type RequestFormValues = CreateRequestInput & { client_access?: boolean }
export interface AccessOptions {
  client_access_enabled: boolean
  demo_mode: boolean
  demo_session_ttl_seconds: number
}
