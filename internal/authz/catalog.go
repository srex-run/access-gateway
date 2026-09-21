package authz

const (
	RoleSRE                  Role       = "sre"
	PermissionUserRead       Permission = "user:read"
	PermissionUserManage     Permission = "user:manage"
	PermissionWorkflowManage Permission = "workflow:manage"
)

type PermissionInfo struct {
	Key         Permission `json:"key"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
}

// Catalog is the exhaustive permission vocabulary. No wildcard or label is a permission.
func Catalog() []PermissionInfo {
	return []PermissionInfo{
		{PermissionDirectoryRead, "浏览资产", "浏览启用的资产和端口"},
		{PermissionRequestManage, "访问申请", "创建、查看和取消自己的申请"},
		{PermissionApprovalManage, "处理审批", "处理当前流程明确分配给自己的节点，禁止自批"},
		{PermissionSessionManage, "个人会话", "连接、查看和关闭自己的会话"},
		{PermissionCatalogManage, "资产管理", "维护资产、端口和网关目录"},
		{PermissionAuditRead, "查看审计", "查看访问、审批及命令操作审计"},
		{PermissionSessionOverride, "强制回收", "查看未结束的资产访问会话并强制终止，可授予自定义管理员角色"},
		{PermissionRoleManage, "授权管理", "管理角色、权限、授权绑定和用户授权标签"},
		{PermissionUserRead, "用户目录", "查看本站用户及标签"},
		{PermissionUserManage, "用户管理", "创建、修改和停用本站账户"},
		{PermissionWorkflowManage, "审批流程管理", "维护流程、资源标签和负责人匹配规则"},
	}
}

func Known(value Permission) bool {
	for _, entry := range Catalog() {
		if entry.Key == value {
			return true
		}
	}
	return false
}
