package service

import (
	"github.com/srex-run/access-gateway/internal/domain"
	"testing"
)

func TestWorkflowThresholdsDoNotSkipAllApprovalNodes(t *testing.T) {
	approved := domain.ApprovalApproved
	v := []domain.Approval{{ApprovalLevel: 1, RequiredApprovals: 2, Decision: &approved}, {ApprovalLevel: 1, RequiredApprovals: 2}, {ApprovalLevel: 2, RequiredApprovals: 1}}
	if level, done := nextApprovalLevel(v); level != 1 || done {
		t.Fatal("all-node advanced after one vote")
	}
	v[1].Decision = &approved
	if level, done := nextApprovalLevel(v); level != 2 || done {
		t.Fatal("all-node did not advance after all votes")
	}
	v[2].Decision = &approved
	if level, done := nextApprovalLevel(v); level != 0 || !done {
		t.Fatal("completed workflow remained pending")
	}
	// Inconsistent thresholds fail conservatively by taking the highest value.
	v[0].RequiredApprovals = 3
	if level, done := nextApprovalLevel(v); level != 1 || done {
		t.Fatal("inconsistent threshold bypassed")
	}
}
