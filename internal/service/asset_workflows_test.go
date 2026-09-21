package service

import (
	"context"
	"errors"
	"testing"

	"github.com/srex-run/access-gateway/internal/approvalflow"
)

func TestAssetWorkflowSelectionRequiresExplicitAssignment(t *testing.T) {
	flows := []approvalflow.Definition{
		{ID: "direct", Enabled: true},
		{ID: "by-label", Enabled: true, AssetSelector: "team=db"},
		{ID: "duplicate", Enabled: true, AssetSelector: "team=db"},
		{ID: "disabled", Enabled: false, AssetSelector: "team=db"},
	}
	for _, id := range []string{"direct", "by-label"} {
		selected, err := selectApprovalWorkflow(flows, &id)
		if err != nil || selected == nil || selected.ID != id {
			t.Fatalf("explicit assignment did not override ambiguous labels: %+v %v", selected, err)
		}
	}
	for _, id := range []string{"disabled", "missing"} {
		if selected, err := selectApprovalWorkflow(flows, &id); !errors.Is(err, ErrValidation) || selected != nil {
			t.Fatalf("invalid assignment silently fell back to labels: %+v %v", selected, err)
		}
	}
	empty := "  "
	for _, available := range [][]approvalflow.Definition{nil, flows[:1], flows[:2], flows} {
		for _, assigned := range []*string{nil, &empty} {
			if selected, err := selectApprovalWorkflow(available, assigned); !errors.Is(err, ErrValidation) || selected != nil {
				t.Fatalf("unassigned asset fell back to labels or legacy approval: %+v %v", selected, err)
			}
		}
	}
}

func TestAssetWorkflowCanRemainUnconfiguredUntilAccessIsRequested(t *testing.T) {
	if id, err := validateAssetWorkflow(context.Background(), nil, "  "); err != nil || id != nil {
		t.Fatalf("clearing explicit assignment failed: %v %v", id, err)
	}
	if _, err := validateAssetWorkflow(context.Background(), nil, "invalid"); !errors.Is(err, ErrValidation) {
		t.Fatalf("invalid workflow ID accepted: %v", err)
	}
}
