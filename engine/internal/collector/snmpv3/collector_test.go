package snmpv3

import (
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/Roger08G/netra/engine/internal/model"
)

func TestValidateRequiresActiveInScopeAuthPrivConfiguration(t *testing.T) {
	plan := model.Plan{SchemaVersion: model.SchemaVersion, Scope: []string{"192.168.1.0/24"}}
	valid := Config{SchemaVersion: model.SchemaVersion, Targets: []Target{{
		Address: "192.168.1.2", Port: 161, TimeoutMS: 1000, Retries: 1,
		Username: "netra-ro", AuthProtocol: "SHA256", AuthPassphrase: "auth-passphrase",
		PrivacyProtocol: "AES", PrivacyPassphrase: "privacy-passphrase",
	}}}
	if err := Validate(valid, plan); err != nil {
		t.Fatalf("valid configuration rejected: %v", err)
	}
	outside := valid
	outside.Targets = append([]Target{}, valid.Targets...)
	outside.Targets[0].Address = "192.168.2.2"
	if err := Validate(outside, plan); err == nil {
		t.Fatal("expected out-of-scope target to be rejected")
	}
	passive := plan
	passive.Passive = true
	if err := Validate(valid, passive); err == nil {
		t.Fatal("expected SNMP on a passive plan to be rejected")
	}
}

func TestParseSwitchNormalizesFDBVLANAndLLDP(t *testing.T) {
	scalars := []gosnmp.SnmpPDU{
		{Name: oidSysName, Type: gosnmp.OctetString, Value: []byte("SW-CORE")},
		{Name: oidSysDescr, Type: gosnmp.OctetString, Value: []byte("Fixture switch")},
		{Name: oidLLDPLocalChassisType, Type: gosnmp.Integer, Value: 4},
		{Name: oidLLDPLocalChassis, Type: gosnmp.OctetString, Value: []byte{0x02, 0, 0, 0, 0, 1}},
	}
	raw := tables{
		ifName: []gosnmp.SnmpPDU{
			{Name: oidIfName + ".5", Type: gosnmp.OctetString, Value: []byte("Gi1/0/17")},
			{Name: oidIfName + ".8", Type: gosnmp.OctetString, Value: []byte("Gi1/0/8")},
		},
		basePortIfIndex: []gosnmp.SnmpPDU{
			{Name: oidBasePortIfIndex + ".17", Type: gosnmp.Integer, Value: 5},
			{Name: oidBasePortIfIndex + ".8", Type: gosnmp.Integer, Value: 8},
		},
		bridgeFDB:       []gosnmp.SnmpPDU{{Name: oidBridgeFDBPort + ".170.187.204.221.238.1", Type: gosnmp.Integer, Value: 17}},
		qBridgeFDB:      []gosnmp.SnmpPDU{{Name: oidQBridgeFDBPort + ".20.170.187.204.221.238.2", Type: gosnmp.Integer, Value: 8}},
		vlanFDBID:       []gosnmp.SnmpPDU{{Name: oidQVlanFDBID + ".0.20", Type: gosnmp.Integer, Value: 20}},
		lldpLocalPort:   []gosnmp.SnmpPDU{{Name: oidLLDPLocalPortID + ".5", Type: gosnmp.OctetString, Value: []byte("Gi1/0/17")}},
		lldpChassisType: []gosnmp.SnmpPDU{{Name: oidLLDPRemoteChassisType + ".0.5.1", Type: gosnmp.Integer, Value: 4}},
		lldpChassis:     []gosnmp.SnmpPDU{{Name: oidLLDPRemoteChassisID + ".0.5.1", Type: gosnmp.OctetString, Value: []byte{0x02, 0, 0, 0, 0, 2}}},
		lldpPort:        []gosnmp.SnmpPDU{{Name: oidLLDPRemotePortID + ".0.5.1", Type: gosnmp.OctetString, Value: []byte("Uplink 1")}},
		lldpName:        []gosnmp.SnmpPDU{{Name: oidLLDPRemoteSysName + ".0.5.1", Type: gosnmp.OctetString, Value: []byte("SW-DESK")}},
		lldpCaps:        []gosnmp.SnmpPDU{{Name: oidLLDPRemoteCaps + ".0.5.1", Type: gosnmp.OctetString, Value: []byte{0x28}}},
	}
	sw := parseSwitch("192.168.1.2", scalars, raw, time.Date(2026, 9, 18, 10, 0, 0, 0, time.UTC))
	if sw.Name != "SW-CORE" || sw.Source != "snmpv3" || len(sw.MACs) != 1 {
		t.Fatalf("unexpected identity: %#v", sw)
	}
	if len(sw.FDB) != 2 {
		t.Fatalf("got %d FDB entries, want 2: %#v", len(sw.FDB), sw.FDB)
	}
	var vlanEntry *model.FDBEntry
	for index := range sw.FDB {
		if sw.FDB[index].VLAN == 20 {
			vlanEntry = &sw.FDB[index]
		}
	}
	if vlanEntry == nil || vlanEntry.Port != "Gi1/0/8" || vlanEntry.MAC != "aa:bb:cc:dd:ee:02" {
		t.Fatalf("unexpected VLAN-aware FDB entry: %#v", vlanEntry)
	}
	if len(sw.LLDP) != 1 {
		t.Fatalf("got %d LLDP neighbors, want 1", len(sw.LLDP))
	}
	neighbor := sw.LLDP[0]
	if neighbor.LocalPort != "Gi1/0/17" || neighbor.RemotePort != "Uplink 1" || neighbor.RemoteName != "SW-DESK" {
		t.Fatalf("unexpected LLDP neighbor: %#v", neighbor)
	}
	if len(neighbor.RemoteCapabilities) != 2 || neighbor.RemoteCapabilities[0] != "bridge" || neighbor.RemoteCapabilities[1] != "router" {
		t.Fatalf("unexpected capabilities: %#v", neighbor.RemoteCapabilities)
	}
}

func TestResolveLLDPIdentityUsesCollectedChassisMAC(t *testing.T) {
	switches := []model.ManagedSwitch{
		{ID: "snmp:192.168.1.2", Name: "SW-CORE", LLDP: []model.LLDPNeighbor{{RemoteDeviceID: "lldp:temporary", RemoteName: "SW-DESK", RemoteMACs: []string{"02:00:00:00:00:02"}}}},
		{ID: "snmp:192.168.1.3", Name: "SW-DESK", MACs: []string{"02:00:00:00:00:02"}},
	}
	resolveLLDPIdentities(switches)
	if got := switches[0].LLDP[0].RemoteDeviceID; got != "snmp:192.168.1.3" {
		t.Fatalf("resolved id = %q", got)
	}
}

func TestSixByteNonMACChassisIsNotMergedAsMAC(t *testing.T) {
	if mac := typedChassisMAC(7, []byte{0x02, 0, 0, 0, 0, 2}); mac != "" {
		t.Fatalf("local chassis subtype was misclassified as MAC: %s", mac)
	}
}
