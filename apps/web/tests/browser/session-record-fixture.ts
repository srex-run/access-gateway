export function sessionRecordFixture(session: { id: string; request_id: string; status: string; [key: string]: unknown }) {
  return {
    ...session, applicant_id: 'applicant', applicant_name: '申请人甲', asset_id: 'asset-1', asset_name: 'payments-mysql', asset_type: 'mysql',
    request: { id: session.request_id, applicant_id: 'applicant', asset_id: 'asset-1', status: 'approved', approval_mode: 'workflow', reason: '排查付款失败', target_account: 'root', target_port: 3306, ttl_seconds: 600, created_at: '2026-09-11T14:40:00Z' },
    session,
    workflow: { status: 'approved', snapshot: null, approvals: [{ id: 'approval-1', user_id: 'approver', name: '审批人乙', level: 1, step_name: '资产负责人', decision: 'approved', comment: '同意排查', decided_at: '2026-09-11T14:42:00Z' }], stages: [], current_level: 0, can_decide: false },
    evidence: { verified_accounts: [], operation_count: 0, connection_count: 0, failed_connections: 0 },
    can_close: session.status === 'running',
  }
}
