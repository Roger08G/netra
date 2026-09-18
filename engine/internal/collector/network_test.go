package collector

import (
	"testing"

	"github.com/Roger08G/netra/engine/internal/model"
)

func TestParseNeighborsSupportsWindowsARPAndIPNeigh(t *testing.T) {
	plan := model.Plan{SchemaVersion: model.SchemaVersion, Scope: []string{"192.168.1.0/24"}}
	input := `
  192.168.1.10         aa-bb-cc-dd-ee-01     dynamic
192.168.1.11 dev eth0 lladdr aa:bb:cc:dd:ee:02 REACHABLE
10.0.0.1 dev eth0 lladdr aa:bb:cc:dd:ee:03 REACHABLE
`
	neighbors := parseNeighbors(input, plan)
	if len(neighbors) != 2 {
		t.Fatalf("got %d neighbors, want 2: %#v", len(neighbors), neighbors)
	}
	if neighbors[0].MAC != "aa:bb:cc:dd:ee:01" || neighbors[1].MAC != "aa:bb:cc:dd:ee:02" {
		t.Fatalf("unexpected normalized MACs: %#v", neighbors)
	}
}
