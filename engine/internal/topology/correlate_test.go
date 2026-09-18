package topology

import (
	"testing"
	"time"

	"github.com/Roger08G/netra/engine/internal/model"
)

func TestFDBBehindLLDPBridgeIsNotDirectAttachment(t *testing.T) {
	managed := &model.ManagedEvidence{
		SchemaVersion: model.SchemaVersion,
		ObservedAt:    time.Date(2026, 9, 18, 8, 0, 0, 0, time.UTC),
		Switches: []model.ManagedSwitch{
			{
				ID: "sw-core", Name: "SW-CORE",
				LLDP: []model.LLDPNeighbor{{LocalPort: "Gi1/0/17", RemoteDeviceID: "sw-desk", RemoteName: "SW-DESK", RemoteCapabilities: []string{"bridge"}}},
				FDB: []model.FDBEntry{
					{MAC: "aa:bb:cc:dd:ee:01", Port: "Gi1/0/17", VLAN: 20},
					{MAC: "aa:bb:cc:dd:ee:02", Port: "Gi1/0/17", VLAN: 20},
				},
			},
		},
	}
	_, relationships, err := Correlate(nil, managed)
	if err != nil {
		t.Fatal(err)
	}
	learned := 0
	for _, relationship := range relationships {
		if relationship.Type == "physical_attachment" && relationship.From == "sw-core" {
			t.Fatalf("unexpected direct attachment: %#v", relationship)
		}
		if relationship.Type == "mac_learned_on_port" {
			learned++
			if relationship.State != "observed" {
				t.Fatalf("FDB relation state = %q", relationship.State)
			}
		}
	}
	if learned != 2 {
		t.Fatalf("got %d learned relationships, want 2", learned)
	}
}

func TestSingleMACAccessPortIsOnlyInferred(t *testing.T) {
	managed := &model.ManagedEvidence{
		SchemaVersion: model.SchemaVersion,
		Switches: []model.ManagedSwitch{{
			ID: "sw-desk", Name: "SW-DESK",
			FDB: []model.FDBEntry{{MAC: "aa:bb:cc:dd:ee:01", Port: "Port 1", VLAN: 20}},
		}},
	}
	_, relationships, err := Correlate(nil, managed)
	if err != nil {
		t.Fatal(err)
	}
	for _, relationship := range relationships {
		if relationship.Type == "physical_attachment" {
			if relationship.State != "inferred" {
				t.Fatalf("physical attachment state = %q", relationship.State)
			}
			return
		}
	}
	t.Fatal("missing inferred physical attachment")
}
