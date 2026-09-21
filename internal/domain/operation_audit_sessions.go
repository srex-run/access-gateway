package domain

import "time"

type OperationAuditSession struct {
	SessionRecord
	CommandCount        int64     `json:"command_count"`
	SuccessCommandCount int64     `json:"success_command_count"`
	FailedCommandCount  int64     `json:"failed_command_count"`
	ActualAccounts      []string  `json:"actual_accounts"`
	Protocols           []string  `json:"protocols"`
	LastOccurredAt      time.Time `json:"last_occurred_at"`
}
