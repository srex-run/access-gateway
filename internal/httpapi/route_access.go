package httpapi

// These exceptions are explicit: absence from routePermission never makes a
// route public. Conditional routes validate their own login state or service
// credentials before accessing data.
func routeAccessException(method, path string) string {
	switch method + " " + path {
	case "GET /healthz", "GET /readyz",
		"GET /api/v1/auth/providers",
		"POST /api/v1/auth/local/login", "POST /api/v1/auth/ldap/login",
		"GET /api/v1/auth/{provider}/login", "GET /api/v1/auth/{provider}/callback",
		"POST /api/v1/auth/invitation/preview", "POST /api/v1/auth/invitation/accept":
		return "public"
	case "GET /api/v1/auth/me", "GET /api/v1/auth/account", "POST /api/v1/auth/password",
		"POST /api/v1/auth/logout", "POST /api/v1/auth/feishu/bind", "DELETE /api/v1/auth/feishu/bind",
		"GET /api/v1/auth/account/mfa", "POST /api/v1/auth/account/mfa/enroll",
		"POST /api/v1/auth/account/mfa/recovery-codes", "POST /api/v1/auth/account/mfa/unbind",
		"GET /api/v1/events", "GET /api/v1/notifications", "POST /api/v1/notifications/read", "POST /api/v1/notifications/{notification_id}/read":
		return "authenticated"
	case "GET /api/v1/auth/mfa", "POST /api/v1/auth/mfa/enroll",
		"POST /api/v1/auth/mfa/confirm", "POST /api/v1/auth/mfa/verify":
		return "pending_mfa"
	case "POST /api/v1/auth/transport/challenges":
		return "transport_target"
	case "POST /callbacks/feishu", "POST /internal/gateway/events", "POST /internal/gateway/events/batch",
		"POST /internal/gateway/operations/batch", "POST /internal/audit/operations/batch":
		return "service_credentials"
	default:
		return ""
	}
}

func isOperationAuditRoute(method, path string) bool {
	return method == "GET" && (path == "/api/v1/operation-audit-events" || path == "/api/v1/operation-audit-sessions")
}
