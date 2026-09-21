package domain

import "sort"

// AuditClassification describes a user-initiated mutation. Authentication,
// reads and runtime evidence belong outside the platform operation log.
type AuditClassification struct {
	Category string `json:"category"`
	Action   string `json:"action"`
	Label    string `json:"label"`
}

var auditClassifications = map[string]AuditClassification{
	"access_request.created":               {"access", "create", "提交访问申请"},
	"access_request.approval_decided":      {"access", "update", "审批访问申请"},
	"access_request.cancelled":             {"access", "update", "取消访问申请"},
	"session.revoke_requested":             {"access", "update", "结束会话"},
	"session.revoke_failed":                {"access", "update", "结束会话"},
	"session.force_close_requested":        {"access", "update", "强制结束会话"},
	"region.created":                       {"resources", "create", "创建区域"},
	"region.status_updated":                {"resources", "update", "修改区域状态"},
	"gateway.created":                      {"resources", "create", "创建网关"},
	"gateway.status_updated":               {"resources", "update", "修改网关状态"},
	"gateway.capacity_updated":             {"resources", "update", "修改网关容量"},
	"gateway.credential_reference_updated": {"resources", "update", "修改网关凭据"},
	"asset.created":                        {"resources", "create", "创建资产"},
	"asset.updated":                        {"resources", "update", "修改资产"},
	"asset.deleted":                        {"resources", "delete", "删除资产"},
	"asset.status_updated":                 {"resources", "update", "修改资产状态"},
	"asset.gateway_bound":                  {"resources", "update", "绑定资产网关"},
	"asset.gateway_binding_updated":        {"resources", "update", "修改资产网关"},
	"asset_port.created":                   {"resources", "create", "添加资产端口"},
	"asset_port.deleted":                   {"resources", "delete", "删除资产端口"},
	"asset_approver.created":               {"access", "create", "添加资产审批人"},
	"workflow.asset_labels_saved":          {"access", "update", "修改审批规则"},
	"cloud_account.saved":                  {"resources", "update", "保存云账号"},
	"cloud_sync.queued":                    {"resources", "update", "发起资产同步"},
	"iam.role_saved":                       {"permissions", "update", "保存角色"},
	"iam.binding_saved":                    {"permissions", "update", "保存权限绑定"},
	"rbac.role_granted":                    {"permissions", "create", "授予角色"},
	"rbac.role_revoked":                    {"permissions", "delete", "撤销角色"},
	"iam.user_updated":                     {"users", "update", "修改用户"},
	"user.local_created":                   {"users", "create", "创建用户"},
	"user.invitation_created":              {"users", "create", "邀请用户"},
	"user.invitation_resent":               {"users", "update", "重发邀请"},
	"user.invitation_revoked":              {"users", "update", "撤销邀请"},
	"user.invitation_accepted":             {"users", "update", "接受邀请"},
	"user.mfa_bound":                       {"users", "update", "绑定 MFA"},
	"user.mfa_unbound":                     {"users", "update", "解绑 MFA"},
	"user.mfa_reset":                       {"users", "update", "重置 MFA"},
	"user.mfa_recovery_regenerated":        {"users", "update", "更新 MFA 恢复码"},
	"user.mfa_recovery_used":               {"users", "update", "使用 MFA 恢复码"},
	"user.external_created":                {"users", "create", "创建外部用户"},
	"user.password_changed":                {"users", "update", "修改密码"},
	"user.feishu_bound":                    {"users", "update", "绑定飞书账号"},
	"user.feishu_unbound":                  {"users", "update", "解绑飞书账号"},
	"system.settings_updated":              {"settings", "update", "修改系统设置"},
}

func ClassifyAuditEvent(eventType string) AuditClassification {
	return auditClassifications[eventType]
}

func UserMutationEventTypes(category, action string) []string {
	types := make([]string, 0, len(auditClassifications))
	for eventType, value := range auditClassifications {
		if (category == "" || value.Category == category) && (action == "" || value.Action == action) {
			types = append(types, eventType)
		}
	}
	sort.Strings(types)
	return types
}

func ValidAuditCategory(value string) bool {
	return value == "" || value == "access" || value == "resources" || value == "permissions" || value == "users" || value == "settings"
}

func ValidAuditAction(value string) bool {
	return value == "" || value == "create" || value == "update" || value == "delete"
}
