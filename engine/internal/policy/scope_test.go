package policy

import (
	"net/netip"
	"testing"

	"github.com/Roger08G/netra/engine/internal/model"
)

func TestValidatePlanRejectsPublicAndLargeActiveScopes(t *testing.T) {
	public := model.Plan{SchemaVersion: model.SchemaVersion, Scope: []string{"8.8.8.0/24"}}
	if _, err := ValidatePlan(public); err == nil {
		t.Fatal("expected public scope to be rejected")
	}
	large := model.Plan{SchemaVersion: model.SchemaVersion, Scope: []string{"10.0.0.0/19"}}
	if _, err := ValidatePlan(large); err == nil {
		t.Fatal("expected large active scope to be rejected")
	}
}

func TestTargetsRespectsExclusionsAndNetworkAddresses(t *testing.T) {
	plan := model.Plan{
		SchemaVersion: model.SchemaVersion,
		Scope:         []string{"192.168.10.0/29"},
		Exclude:       []string{"192.168.10.2"},
	}
	targets, err := Targets(plan)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 5 {
		t.Fatalf("got %d targets, want 5", len(targets))
	}
	if Contains(plan, netip.MustParseAddr("192.168.10.2")) {
		t.Fatal("excluded target was accepted")
	}
}
