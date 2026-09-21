package operationaudit

import "strings"

const (
	ProtocolSSH        = "ssh"
	ProtocolMySQL      = "mysql"
	ProtocolRedis      = "redis"
	ProtocolMongoDB    = "mongodb"
	ProtocolPostgreSQL = "postgresql"
	ProtocolHTTP       = "http"
)

// ValidProtocol describes the operation event contract, not the protocols an
// agent can decode. HTTPS uses http here; transport encryption is independent.
func ValidProtocol(value string) bool {
	switch value {
	case ProtocolSSH, ProtocolMySQL, ProtocolRedis, ProtocolMongoDB, ProtocolPostgreSQL, ProtocolHTTP:
		return true
	default:
		return false
	}
}

// NormalizeProtocol maps the labels accepted by asset inventory to the
// canonical protocol used by audit profiles and operation events.
func NormalizeProtocol(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "postgres", ProtocolPostgreSQL:
		return ProtocolPostgreSQL
	case "mongo", ProtocolMongoDB:
		return ProtocolMongoDB
	case "https", ProtocolHTTP:
		return ProtocolHTTP
	case "sshd", ProtocolSSH:
		return ProtocolSSH
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func ValidAssetProtocol(value string) bool {
	return ValidProtocol(NormalizeProtocol(value))
}
