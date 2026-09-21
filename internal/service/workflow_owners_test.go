package service

import (
	"testing"

	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/label"
)

func TestAssetOwnerLabelTakesPrecedenceOverRules(t *testing.T) {
	const ownerID = "11111111-1111-4111-8111-111111111111"
	rule, err := label.BindingSelector("team=database")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		labels label.Labels
		user   domain.User
		want   bool
	}{
		{name: "explicit owner needs no matching user labels", labels: label.Labels{"owner": ownerID, "env": "prod"}, user: domain.User{ID: ownerID}, want: true},
		{name: "rule cannot add another owner", labels: label.Labels{"owner": ownerID}, user: domain.User{ID: "other", Labels: label.Labels{"team": "database"}}},
		{name: "display name cannot impersonate owner", labels: label.Labels{"owner": ownerID}, user: domain.User{ID: "other", Nickname: ownerID}},
		{name: "unknown owner does not fall back", labels: label.Labels{"owner": "missing"}, user: domain.User{ID: ownerID, Labels: label.Labels{"team": "database"}}},
		{name: "ordinary labels retain ownership rules", labels: label.Labels{"env": "prod"}, user: domain.User{ID: ownerID, Labels: label.Labels{"team": "database"}}, want: true},
		{name: "no matching rule", labels: label.Labels{"env": "prod"}, user: domain.User{ID: ownerID, Labels: label.Labels{"team": "web"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := matchesAssetOwner(test.labels, test.user, []label.Selector{rule}); got != test.want {
				t.Fatalf("owner match = %v, want %v", got, test.want)
			}
		})
	}
}
