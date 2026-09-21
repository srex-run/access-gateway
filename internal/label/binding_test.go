package label

import "testing"

func TestBindingSelectorsRejectImplicitEveryone(t *testing.T) {
	for _, value := range []string{"", "   "} {
		if _, err := BindingSelector(value); err == nil {
			t.Fatal("empty selector accepted")
		}
		if MatchesBinding(value, Labels{}) {
			t.Fatal("empty binding matched")
		}
	}
	if !MatchesBinding("team in (db,ops),env!=dev,!suspended", Labels{"team": "db", "env": "prod"}) {
		t.Fatal("selector semantics not retained")
	}
	if MatchesBinding("team=db", Labels{"team": "web"}) {
		t.Fatal("unrelated resource matched")
	}
	if err := ValidateEditable(Labels{PrefixSystem + "role": "admin"}); err == nil {
		t.Fatal("system label editable")
	}
}
