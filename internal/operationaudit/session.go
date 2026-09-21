package operationaudit

// Policy is the public, immutable selection attached to an approved session.
// Private credentials are only included in the protected session-agent grant.
type Policy struct {
	Profile  string `json:"profile,omitempty"`
	Revision string `json:"revision,omitempty"`
	Protocol string `json:"protocol,omitempty"`
}

type SessionEvent struct {
	Event
	ConnectionID string `json:"connection_id"`
	OperationID  string `json:"operation_id"`
	Phase        string `json:"phase"`
}

type SessionBatch struct {
	Events []SessionEvent `json:"events"`
}
