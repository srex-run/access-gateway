package approvalflow

import "testing"

func TestWorkflowRequiresExplicitSelectorsAndOrderedNodes(t *testing.T) {
	v := Definition{Name: "owners then platform", AssetSelector: "team in (db,storage),env=production", TimeoutSeconds: 3600, Steps: []Step{{Name: "owners", Kind: "owners", Mode: "all"}, {Name: "platform", Kind: "role_selector", Mode: "any", Selector: "access-gateway.io/approval=platform"}}}
	if err := v.Validate(); err != nil {
		t.Fatal(err)
	}
	direct := v
	direct.AssetSelector = ""
	if err := direct.Validate(); err != nil {
		t.Fatalf("directly assigned workflow must not require resource labels: %v", err)
	}
	for _, change := range []func(*Definition){func(v *Definition) { v.AssetSelector = "team in (" }, func(v *Definition) { v.TimeoutSeconds = 0 }, func(v *Definition) { v.Steps = nil }, func(v *Definition) { v.Steps = []Step{{Name: "any", Kind: "user_selector", Mode: "any", Selector: ""}} }, func(v *Definition) { v.Steps = []Step{{Name: "auto", Kind: "auto", Mode: "any"}} }} {
		copy := v
		change(&copy)
		if copy.Validate() == nil {
			t.Fatalf("invalid definition accepted: %+v", copy)
		}
	}
}
